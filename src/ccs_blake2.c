/**
 * @file ccs_blake2.c
 * @brief BLAKE2s and BLAKE2b implementation.
 * @copyright Copyright (c) 2026 FiercestT
 */

#include "ccs_blake2.h"

#if CCS_NEED_B2

#include "ccs_util.h"

static const uint8_t CCS_BLAKE2_SIGMA[10][8] = {
    { 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe },
    { 0xae, 0x84, 0xf9, 0x6d, 0xc1, 0x20, 0x7b, 0x35 },
    { 0x8b, 0x0c, 0x25, 0xdf, 0xea, 0x63, 0x17, 0x49 },
    { 0x97, 0x13, 0xcd, 0xeb, 0x62, 0xa5, 0x04, 0x8f },
    { 0x09, 0x75, 0x42, 0xfa, 0x1e, 0xcb, 0x86, 0xd3 },
    { 0xc2, 0xa6, 0xb0, 0x38, 0xd4, 0x57, 0xef, 0x91 },
    { 0x5c, 0xf1, 0xde, 0xa4, 0x70, 0x36, 0x29, 0xb8 },
    { 0xbd, 0xe7, 0x1c, 0x93, 0x05, 0x4f, 0x68, 0xa2 },
    { 0xf6, 0x9e, 0x3b, 0x80, 0x2c, 0x7d, 0x41, 0x5a },
    { 0x2a, 0x48, 0x67, 0x51, 0xbf, 0xe9, 0xc3, 0x0d }
};

#if CCS_B2S
static const uint32_t CCS_BLAKE2S_IV[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
};

static inline void ccs_blake2s_increment_ctr(ccs_blake2s_ctx_t* ctx, size_t amount) {
    ctx->t[0] += amount;
    ctx->t[1] += (ctx->t[0] < amount);
}

static inline void ccs_blake2s_copy_iv(uint32_t* h) {
    for(uint8_t i = 0; i < 8; i++)
        h[i] = CCS_BLAKE2S_IV[i];
}

#define CCS_BLAKE2S_G(x, y, a, b, c, d)   \
do {                                      \
    (a) += (b) + (x);                     \
    (d) = ccs_util_rotr32(16, (d) ^ (a)); \
    (c) += (d);                           \
    (b) = ccs_util_rotr32(12, (b) ^ (c)); \
    (a) += (b) + (y);                     \
    (d) = ccs_util_rotr32(8,  (d) ^ (a)); \
    (c) += (d);                           \
    (b) = ccs_util_rotr32(7,  (b) ^ (c)); \
} while(0)

static inline void ccs_blake2s_half(
    const uint8_t* sigma,
    const uint8_t* m,
    uint32_t* v,
    uint8_t diagonal
) {
    for(uint8_t i = 0; i < 4; i++) {
        const uint8_t b = 4 + ((i + diagonal) & 3);
        const uint8_t c = 8 + ((i + 2 * diagonal) & 3);
        const uint8_t d = 12 + ((i - diagonal) & 3);
        uint32_t av = v[i], bv = v[b], cv = v[c], dv = v[d];

        CCS_BLAKE2S_G(
            ccs_util_load32le(&m[(size_t)(sigma[i] & 15) * 4]),
            ccs_util_load32le(&m[(size_t)(sigma[i] >> 4) * 4]),
            av, bv, cv, dv);

        v[i] = av;
        v[b] = bv;
        v[c] = cv;
        v[d] = dv;
    }
}

static inline void ccs_blake2s_round(uint8_t r, const uint8_t* m, uint32_t* v) {
    ccs_blake2s_half(CCS_BLAKE2_SIGMA[r], m, v, 0);
    ccs_blake2s_half(&CCS_BLAKE2_SIGMA[r][4], m, v, 1);
}

static void ccs_blake2s_compress(ccs_blake2s_ctx_t* ctx, const uint8_t* block) {
    uint32_t v[16];

    for(uint8_t i = 0; i < 8; i++)
        v[i] = ctx->h[i];
    ccs_blake2s_copy_iv(&v[8]);
    v[12] ^= ctx->t[0];
    v[13] ^= ctx->t[1];
    v[14] ^= UINT32_C(0) - (uint32_t)ctx->f;

    ccs_blake2s_round(0, block, v);
    ccs_blake2s_round(1, block, v);
    ccs_blake2s_round(2, block, v);
    ccs_blake2s_round(3, block, v);
    ccs_blake2s_round(4, block, v);
    ccs_blake2s_round(5, block, v);
    ccs_blake2s_round(6, block, v);
    ccs_blake2s_round(7, block, v);
    ccs_blake2s_round(8, block, v);
    ccs_blake2s_round(9, block, v);

    for(uint8_t i = 0; i < 8; i++)
        ctx->h[i] = ctx->h[i] ^ v[i] ^ v[i + 8];
    ccs_util_memzero(sizeof(v), v);
}

ccs_res_t ccs_blake2s_init(
    ccs_blake2s_ctx_t* ctx,
    uint8_t digest_len
) {
    if(digest_len == 0 || digest_len > CCS_BLAKE2S_LEN)
        return CCS_ERROR;

    ccs_util_memzero(sizeof(*ctx), ctx);
    ccs_blake2s_copy_iv(ctx->h);

    // Other h[n] params are 0 or configured in config functions.
    ctx->h[0] ^= UINT32_C(0x01010000) | (uint32_t)digest_len;

    ctx->digest_len = digest_len;
    ctx->block_idx = 0;

    return CCS_OK;
}

ccs_res_t ccs_blake2s_config_key(
    ccs_blake2s_ctx_t* ctx,
    const ccs_blake2s_key_t key
) {
    // Replace the key-length byte in the IV-XORed parameter word.
    ctx->h[0] = (ctx->h[0] & ~UINT32_C(0x0000ff00))
                | ((CCS_BLAKE2S_IV[0] ^ ((uint32_t)CCS_BLAKE2S_KEYLEN << 8))
                & UINT32_C(0x0000ff00));

    for(uint8_t i = 0; i < CCS_BLAKE2S_KEYLEN; i++)
        ctx->block[i] = key[i];
    ctx->block_idx = CCS_BLAKE2S_BLOCKLEN;

    return CCS_OK;
}

ccs_res_t ccs_blake2s_config_salt(
    ccs_blake2s_ctx_t* ctx,
    const ccs_blake2s_salt_t salt
) {
    ctx->h[4] = CCS_BLAKE2S_IV[4] ^ ccs_util_load32le(&salt[0]); // salt[0]
    ctx->h[5] = CCS_BLAKE2S_IV[5] ^ ccs_util_load32le(&salt[4]); // salt[1]

    return CCS_OK;
}

ccs_res_t ccs_blake2s_config_personal(
    ccs_blake2s_ctx_t* ctx,
    const ccs_blake2s_personal_t personal
) {
    ctx->h[6] = CCS_BLAKE2S_IV[6] ^ ccs_util_load32le(&personal[0]); // personal[0]
    ctx->h[7] = CCS_BLAKE2S_IV[7] ^ ccs_util_load32le(&personal[4]); // personal[1]

    return CCS_OK;
}

ccs_res_t ccs_blake2s_update(
    ccs_blake2s_ctx_t* ctx,
    size_t in_len,
    const uint8_t* in
) {
    uint8_t index = ctx->block_idx;
    while(in_len > 0) {
        const uint8_t* block = ctx->block;
        if(index == 0 && in_len > CCS_BLAKE2S_BLOCKLEN) {
            block = in;
            in += CCS_BLAKE2S_BLOCKLEN;
            in_len -= CCS_BLAKE2S_BLOCKLEN;
        } else if(index < CCS_BLAKE2S_BLOCKLEN) {
            ctx->block[index++] = *in++;
            in_len--;
            continue;
        }
        ccs_blake2s_increment_ctr(ctx, CCS_BLAKE2S_BLOCKLEN);
        ccs_blake2s_compress(ctx, block);
        index = 0;
    }
    ctx->block_idx = index;

    return CCS_OK;
}

ccs_res_t ccs_blake2s_final(
    ccs_blake2s_ctx_t* ctx,
    ccs_blake2s_digest_t digest
) {
    ctx->f = 1; // Set last block
    ccs_blake2s_increment_ctr(ctx, ctx->block_idx);
    ccs_util_memzero(CCS_BLAKE2S_BLOCKLEN - ctx->block_idx, &ctx->block[ctx->block_idx]);
    ccs_blake2s_compress(ctx, ctx->block);

#if CCS_LITTLE_ENDIAN
    for(uint8_t i = 0; i < ctx->digest_len; i++)
        digest[i] = ((uint8_t*)ctx->h)[i];
#else
    for(uint8_t i = 0; i < ctx->digest_len; i++)
        digest[i] = (uint8_t)(ctx->h[i / 4] >> (8 * (i % 4)));
#endif

    ccs_util_memzero(sizeof(*ctx), ctx);

    return CCS_OK;
}
#endif // CCS_B2S

#if CCS_B2B
static const uint64_t CCS_BLAKE2B_IV[8] = {
    UINT64_C(0x6a09e667f3bcc908), UINT64_C(0xbb67ae8584caa73b),
    UINT64_C(0x3c6ef372fe94f82b), UINT64_C(0xa54ff53a5f1d36f1),
    UINT64_C(0x510e527fade682d1), UINT64_C(0x9b05688c2b3e6c1f),
    UINT64_C(0x1f83d9abfb41bd6b), UINT64_C(0x5be0cd19137e2179)
};

static inline void ccs_blake2b_increment_ctr(ccs_blake2b_ctx_t* ctx, size_t amount) {
    ctx->t[0] += amount;
    ctx->t[1] += (ctx->t[0] < amount);
}

static inline void ccs_blake2b_copy_iv(uint64_t* h) {
    for(uint8_t i = 0; i < 8; i++)
        h[i] = CCS_BLAKE2B_IV[i];
}

#define CCS_BLAKE2B_G(x, y, a, b, c, d)  \
do {                                    \
    (a) += (b) + (x);                    \
    (d) = ccs_util_rotr64(32, (d) ^ (a)); \
    (c) += (d);                          \
    (b) = ccs_util_rotr64(24, (b) ^ (c)); \
    (a) += (b) + (y);                    \
    (d) = ccs_util_rotr64(16, (d) ^ (a)); \
    (c) += (d);                          \
    (b) = ccs_util_rotr64(63, (b) ^ (c)); \
} while(0)

static inline void ccs_blake2b_half(
    const uint8_t* sigma,
    const uint8_t* m,
    uint64_t* v,
    uint8_t diagonal
) {
    for(uint8_t i = 0; i < 4; i++) {
        const uint8_t b = 4 + ((i + diagonal) & 3);
        const uint8_t c = 8 + ((i + 2 * diagonal) & 3);
        const uint8_t d = 12 + ((i - diagonal) & 3);
        uint64_t av = v[i], bv = v[b], cv = v[c], dv = v[d];

        CCS_BLAKE2B_G(
            ccs_util_load64le(&m[(size_t)(sigma[i] & 15) * 8]),
            ccs_util_load64le(&m[(size_t)(sigma[i] >> 4) * 8]),
            av, bv, cv, dv);

        v[i] = av;
        v[b] = bv;
        v[c] = cv;
        v[d] = dv;
    }
}

static inline void ccs_blake2b_round(uint8_t r, const uint8_t* m, uint64_t* v) {
    ccs_blake2b_half(CCS_BLAKE2_SIGMA[r], m, v, 0);
    ccs_blake2b_half(&CCS_BLAKE2_SIGMA[r][4], m, v, 1);
}

static void ccs_blake2b_compress(ccs_blake2b_ctx_t* ctx, const uint8_t* block) {
    uint64_t v[16];

    for(uint8_t i = 0; i < 8; i++)
        v[i] = ctx->h[i];
    ccs_blake2b_copy_iv(&v[8]);
    v[12] ^= ctx->t[0];
    v[13] ^= ctx->t[1];
    v[14] ^= UINT64_C(0) - (uint64_t)ctx->f;

    ccs_blake2b_round(0, block, v);
    ccs_blake2b_round(1, block, v);
    ccs_blake2b_round(2, block, v);
    ccs_blake2b_round(3, block, v);
    ccs_blake2b_round(4, block, v);
    ccs_blake2b_round(5, block, v);
    ccs_blake2b_round(6, block, v);
    ccs_blake2b_round(7, block, v);
    ccs_blake2b_round(8, block, v);
    ccs_blake2b_round(9, block, v);
    ccs_blake2b_round(0, block, v);
    ccs_blake2b_round(1, block, v);

    for(uint8_t i = 0; i < 8; i++)
        ctx->h[i] = ctx->h[i] ^ v[i] ^ v[i + 8];
    ccs_util_memzero(sizeof(v), v);
}

ccs_res_t ccs_blake2b_init(
    ccs_blake2b_ctx_t* ctx,
    uint8_t digest_len
) {
    if(digest_len == 0 || digest_len > CCS_BLAKE2B_LEN)
        return CCS_ERROR;

    ccs_util_memzero(sizeof(*ctx), ctx);
    ccs_blake2b_copy_iv(ctx->h);

    // Other h[n] params are 0 or configured in config functions.
    ctx->h[0] ^= UINT64_C(0x0000000001010000) | (uint64_t)digest_len;

    ctx->digest_len = digest_len;
    ctx->block_idx = 0;

    return CCS_OK;
}

ccs_res_t ccs_blake2b_config_key(
    ccs_blake2b_ctx_t* ctx,
    const ccs_blake2b_key_t key
) {
    // Replace the key-length byte in the IV-XORed parameter word.
    ctx->h[0] = (ctx->h[0] & ~UINT64_C(0x000000000000ff00))
              | ((CCS_BLAKE2B_IV[0] ^ ((uint64_t)CCS_BLAKE2B_KEYLEN << 8))
                 & UINT64_C(0x000000000000ff00));

    for(uint8_t i = 0; i < CCS_BLAKE2B_KEYLEN; i++)
        ctx->block[i] = key[i];
    ctx->block_idx = CCS_BLAKE2B_BLOCKLEN;

    return CCS_OK;
}

ccs_res_t ccs_blake2b_config_salt(
    ccs_blake2b_ctx_t* ctx,
    const ccs_blake2b_salt_t salt
) {
    ctx->h[4] = CCS_BLAKE2B_IV[4] ^ ccs_util_load64le(&salt[0]); // salt[0]
    ctx->h[5] = CCS_BLAKE2B_IV[5] ^ ccs_util_load64le(&salt[8]); // salt[1]

    return CCS_OK;
}

ccs_res_t ccs_blake2b_config_personal(
    ccs_blake2b_ctx_t* ctx,
    const ccs_blake2b_personal_t personal
) {
    ctx->h[6] = CCS_BLAKE2B_IV[6] ^ ccs_util_load64le(&personal[0]); // personal[0]
    ctx->h[7] = CCS_BLAKE2B_IV[7] ^ ccs_util_load64le(&personal[8]); // personal[1]

    return CCS_OK;
}

ccs_res_t ccs_blake2b_update(
    ccs_blake2b_ctx_t* ctx,
    size_t in_len,
    const uint8_t* in
) {
    uint8_t index = ctx->block_idx;
    while(in_len > 0) {
        const uint8_t* block = ctx->block;
        if(index == 0 && in_len > CCS_BLAKE2B_BLOCKLEN) {
            block = in;
            in += CCS_BLAKE2B_BLOCKLEN;
            in_len -= CCS_BLAKE2B_BLOCKLEN;
        } else if(index < CCS_BLAKE2B_BLOCKLEN) {
            ctx->block[index++] = *in++;
            in_len--;
            continue;
        }
        ccs_blake2b_increment_ctr(ctx, CCS_BLAKE2B_BLOCKLEN);
        ccs_blake2b_compress(ctx, block);
        index = 0;
    }
    ctx->block_idx = index;

    return CCS_OK;
}

ccs_res_t ccs_blake2b_final(
    ccs_blake2b_ctx_t* ctx,
    ccs_blake2b_digest_t digest
) {
    ctx->f = 1; // Set last block
    ccs_blake2b_increment_ctr(ctx, ctx->block_idx);
    ccs_util_memzero(CCS_BLAKE2B_BLOCKLEN - ctx->block_idx, &ctx->block[ctx->block_idx]);
    ccs_blake2b_compress(ctx, ctx->block);

#if CCS_LITTLE_ENDIAN
    for(uint8_t i = 0; i < ctx->digest_len; i++)
        digest[i] = ((uint8_t*)ctx->h)[i];
#else
    for(uint8_t i = 0; i < ctx->digest_len; i++)
        digest[i] = (uint8_t)(ctx->h[i / 8] >> (8 * (i % 8)));
#endif

    ccs_util_memzero(sizeof(*ctx), ctx);

    return CCS_OK;
}

#endif // CCS_B2B

#endif // CCS_NEED_B2
