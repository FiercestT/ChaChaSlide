/**
 * @file ccs_poly1305.c
 * @brief Poly1305 one-time authenticator implementation.
 * @copyright Copyright (c) 2026 FiercestT
 */

#include "ccs_poly1305.h"
#include "ccs_internal.h"

#if CCS_NEED_POLY

#include "ccs_util.h"

#if CCS_POLY == 2

/*
 * MUL15 is adapted from BearSSL src/inner.h.
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
static inline uint32_t ccs_poly1305_mul15(uint32_t x, uint32_t y) {
    return ((x | UINT32_C(0x80000000)) * (y | UINT32_C(0x80000000))) & UINT32_C(0x7fffffff);
}

static inline uint64_t ccs_poly1305_mul32(uint32_t x, uint32_t y) {
    const uint32_t a = x & UINT32_C(65535), b = x >> 16;
    const uint32_t c = y & UINT32_C(32767), d = y >> 15;
    const uint32_t p = ccs_poly1305_mul15(a, c), q = ccs_poly1305_mul15(a, d);
    const uint32_t u = ccs_poly1305_mul15(b, c), v = ccs_poly1305_mul15(b, d);
    return (uint64_t)p + ((uint64_t)q << 15) + ((uint64_t)u << 16) + ((uint64_t)v << 31);
}

static void ccs_poly1305_blocks(ccs_poly1305_ctx_t* ctx, const uint8_t* block, size_t block_count, uint8_t high_bit) {
    const uint32_t rlow = ctx->r[0] & 3;
    uint32_t k[8], low[4];
    for(uint8_t i = 0; i < 4; i++) {
        k[i] = (ctx->r[i] >> 2) * 5;
        k[4 + i] = ctx->r[i];
    }

    uint32_t h0 = ctx->h[0];
    uint32_t h1 = ctx->h[1];
    uint32_t h2 = ctx->h[2];
    uint32_t h3 = ctx->h[3];
    uint32_t h4 = ctx->h[4];

    for(size_t block_index = 0; block_index < block_count; block_index++) {
        const uint64_t a0 = (uint64_t)h0 + ccs_util_load32le(block);
        const uint64_t a1 = (uint64_t)h1 + ccs_util_load32le(&block[4]) + (a0 >> 32);
        const uint64_t a2 = (uint64_t)h2 + ccs_util_load32le(&block[8]) + (a1 >> 32);
        const uint64_t a3 = (uint64_t)h3 + ccs_util_load32le(&block[12]) + (a2 >> 32);
        const uint32_t s4 = h4 + high_bit + (uint32_t)(a3 >> 32);

        uint32_t carry = 0;
        for(uint8_t i = 0; i < 4; i++) {
            const uint64_t row = ccs_poly1305_mul32((uint32_t)a0, k[4 + i])
                               + ccs_poly1305_mul32((uint32_t)a1, k[3 + i])
                               + ccs_poly1305_mul32((uint32_t)a2, k[2 + i])
                               + ccs_poly1305_mul32((uint32_t)a3, k[1 + i])
                               + ccs_poly1305_mul15(s4, k[i]) + carry;
            low[i] = (uint32_t)row;
            carry = (uint32_t)(row >> 32);
        }

        const uint32_t top = carry + ccs_poly1305_mul15(s4, rlow);
        uint64_t c = (uint64_t)low[0] + (top >> 2) * 5;
        h0 = (uint32_t)c;
        c = (uint64_t)low[1] + (c >> 32);
        h1 = (uint32_t)c;
        c = (uint64_t)low[2] + (c >> 32);
        h2 = (uint32_t)c;
        c = (uint64_t)low[3] + (c >> 32);
        h3 = (uint32_t)c;
        h4 = (top & 3) + (uint32_t)(c >> 32);
        block += CCS_POLY1305_BLOCKLEN;
    }

    ctx->h[0] = h0;
    ctx->h[1] = h1;
    ctx->h[2] = h2;
    ctx->h[3] = h3;
    ctx->h[4] = h4;
    ccs_util_memzero(sizeof(k), k);
    ccs_util_memzero(sizeof(low), low);
}

#elif CCS_POLY == 3

static void ccs_poly1305_blocks(ccs_poly1305_ctx_t* ctx, const uint8_t* block, size_t block_count, uint8_t high_bit) {
    uint8_t r[16], h[17], x[33];
    for(uint8_t i = 0; i < 16; i++) {
        r[i] = (uint8_t)(ctx->r[i >> 2] >> ((i & 3) * 8));
        h[i] = (uint8_t)(ctx->h[i >> 2] >> ((i & 3) * 8));
    }
    h[16] = (uint8_t)ctx->h[4];

    for(size_t block_index = 0; block_index < block_count; block_index++) {
        uint16_t carry = 0;
        for(uint8_t i = 0; i < 16; i++) {
            carry += (uint16_t)h[i] + block[i];
            h[i] = (uint8_t)carry;
            carry >>= 8;
        }
        h[16] += (uint8_t)(carry + high_bit);

        for(uint8_t i = 0; i < sizeof(x); i++)
            x[i] = 0;
        for(uint8_t i = 0; i < 16; i++) {
            carry = 0;
            for(uint8_t j = 0; j < 17; j++) {
                carry = (uint16_t)x[i + j] + (uint16_t)h[j] * r[i] + carry;
                x[i + j] = (uint8_t)carry;
                carry >>= 8;
            }
            x[i + 17] = (uint8_t)carry;
        }

        carry = 0;
        for(uint8_t i = 0; i < 16; i++) {
            const uint16_t high = (x[i + 16] >> 2) | ((uint16_t)(x[i + 17] & 3) << 6);
            carry += x[i] + high * 5;
            h[i] = (uint8_t)carry;
            carry >>= 8;
        }
        h[16] = (uint8_t)((x[16] & 3) + carry);
        block += CCS_POLY1305_BLOCKLEN;
    }

    for(uint8_t i = 0; i < 4; i++)
        ctx->h[i] = ccs_util_load32le(&h[4 * i]);
    ctx->h[4] = h[16];
    ccs_util_memzero(sizeof(r), r);
    ccs_util_memzero(sizeof(h), h);
    ccs_util_memzero(sizeof(x), x);
}

#else

static void ccs_poly1305_blocks(ccs_poly1305_ctx_t* ctx, const uint8_t* block, size_t block_count, uint8_t high_bit) {
    const uint32_t rlow = ctx->r[0] & 3;
    uint32_t k[8];
    uint64_t x[4];
    for(uint8_t i = 0; i < 4; i++) {
        k[i] = (ctx->r[i] >> 2) * 5;
        k[4 + i] = ctx->r[i];
    }

    uint32_t h0 = ctx->h[0];
    uint32_t h1 = ctx->h[1];
    uint32_t h2 = ctx->h[2];
    uint32_t h3 = ctx->h[3];
    uint32_t h4 = ctx->h[4];

    for(size_t block_index = 0; block_index < block_count; block_index++) {
        const uint64_t s0 = (uint64_t)h0 + ccs_util_load32le(&block[0]);
        const uint64_t s1 = (uint64_t)h1 + ccs_util_load32le(&block[4]);
        const uint64_t s2 = (uint64_t)h2 + ccs_util_load32le(&block[8]);
        const uint64_t s3 = (uint64_t)h3 + ccs_util_load32le(&block[12]);
        const uint32_t s4 = h4 + high_bit;

        for(uint8_t i = 0; i < 4; i++)
            x[i] = s0 * k[4 + i] + s1 * k[3 + i] + s2 * k[2 + i] + s3 * k[1 + i] + (uint64_t)s4 * k[i];

        const uint64_t top = (x[3] >> 32) + s4 * rlow;
        const uint64_t u0 = (uint32_t)x[0] + (top >> 2) * 5;
        const uint64_t u1 = (uint32_t)x[1] + (x[0] >> 32) + (u0 >> 32);
        const uint64_t u2 = (uint32_t)x[2] + (x[1] >> 32) + (u1 >> 32);
        const uint64_t u3 = (uint32_t)x[3] + (x[2] >> 32) + (u2 >> 32);

        h0 = (uint32_t)u0;
        h1 = (uint32_t)u1;
        h2 = (uint32_t)u2;
        h3 = (uint32_t)u3;
        h4 = (uint32_t)(top & 3) + (uint32_t)(u3 >> 32);

        block += CCS_POLY1305_BLOCKLEN;
    }

    ctx->h[0] = h0;
    ctx->h[1] = h1;
    ctx->h[2] = h2;
    ctx->h[3] = h3;
    ctx->h[4] = h4;
    ccs_util_memzero(sizeof(k), k);
    ccs_util_memzero(sizeof(x), x);
}

#endif // CCS_POLY

ccs_res_t ccs_poly1305_init(
    ccs_poly1305_ctx_t* ctx,
    const ccs_poly1305_key_t key
) {
    for(uint8_t i = 0; i < 4; i++) {
        ctx->r[i] = ccs_util_load32le(&key[4 * i]);
        ctx->s[i] = ccs_util_load32le(&key[16 + 4 * i]);
        ctx->h[i] = 0;
    }

    ctx->r[0] &= 0x0fffffff;
    for(uint8_t i = 1; i < 4; i++)
        ctx->r[i] &= 0x0ffffffc;

    ctx->h[4] = 0;
    ctx->block_idx = 0;

    return CCS_OK;
}

ccs_res_t ccs_poly1305_update(
    ccs_poly1305_ctx_t* ctx,
    size_t in_len,
    const uint8_t* in
) {
    // Remnant Block
    if(ctx->block_idx != 0) {
        uint8_t take = CCS_POLY1305_BLOCKLEN - ctx->block_idx;
        if(take > in_len)
            take = (uint8_t)in_len;

        for(uint8_t i = 0; i < take; i++)
            ctx->block[ctx->block_idx++] = *in++;

        if(ctx->block_idx != CCS_POLY1305_BLOCKLEN)
            return CCS_OK;

        in_len -= take;
        ctx->block_idx = 0;
        ccs_poly1305_blocks(ctx, ctx->block, 1, 1);
    }

    // Bulk Blocks
    const size_t blocks = in_len / CCS_POLY1305_BLOCKLEN;
    if(blocks != 0) {
        ccs_poly1305_blocks(ctx, in, blocks, 1);
        const size_t consumed = blocks * CCS_POLY1305_BLOCKLEN;
        in += consumed;
        in_len -= consumed;
    }

    // Leftover In
    for(uint8_t i = 0; i < in_len; i++)
        ctx->block[i] = in[i];
    ctx->block_idx = (uint8_t)in_len;

    return CCS_OK;
}

ccs_res_t ccs_poly1305_final(
    ccs_poly1305_ctx_t* ctx,
    ccs_poly1305_digest_t digest
) {
    // Final Block
    if(ctx->block_idx != 0) {
        for(uint8_t i = 0; i < (CCS_POLY1305_BLOCKLEN - ctx->block_idx); i++)
            ctx->block[ctx->block_idx + i] = 0;

        ctx->block[ctx->block_idx] = 1;
        ccs_poly1305_blocks(ctx, ctx->block, 1, 0);
    }

    uint32_t carry = 5;
    for(size_t i = 0; i < 4; i++)
        carry = (uint32_t)(((uint64_t)ctx->h[i] + carry) >> 32);

    const uint32_t q = (carry + ctx->h[4]) >> 2;
    carry = 5 * q;

    for(size_t i = 0; i < 4; i++) {
        const uint64_t sum = (uint64_t)ctx->h[i] + ctx->s[i] + carry;
        ccs_util_store32le((uint32_t)sum, &digest[4 * i]);
        carry = (uint32_t)(sum >> 32);
    }

    ccs_util_memzero(sizeof(*ctx), ctx);

    return CCS_OK;
}

ccs_res_t ccs_poly1305_verify(
    const ccs_poly1305_digest_t expected,
    const ccs_poly1305_digest_t actual
) {
    uint8_t difference = 0;

    for(size_t i = 0; i < CCS_POLY1305_LEN; i++)
        difference |= expected[i] ^ actual[i];

    return difference == 0 ? CCS_OK : CCS_VERIFICATION_FAILED;
}
#endif // CCS_NEED_POLY
