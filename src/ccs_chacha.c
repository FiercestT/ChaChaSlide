/**
 * @file ccs_chacha.c
 * @brief ChaCha stream cipher implementation.
 * @copyright Copyright (c) 2026 FiercestT
 */

#include "ccs_chacha.h"
#include "ccs_internal.h"
#include "ccs_util.h"

#if CCS_NEED_CC
static const uint32_t CCS_CHACHA_CONSTANT[4] = { 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574 }; // "expand 32-byte k"

#define CCS_CHACHA_QR(a, b, c, d) do {                \
    (a) += (b); (d) = ccs_util_rotl32(16, (d) ^ (a)); \
    (c) += (d); (b) = ccs_util_rotl32(12, (b) ^ (c)); \
    (a) += (b); (d) = ccs_util_rotl32(8,  (d) ^ (a)); \
    (c) += (d); (b) = ccs_util_rotl32(7,  (b) ^ (c)); \
} while(0)

static inline void ccs_chacha_block(uint8_t rounds, const uint32_t* state, uint32_t* keystream) {
    for(uint8_t i = 0; i < 16; i++)
        keystream[i] = state[i];

    for(uint8_t i = 0; i < (rounds / 2); i++) {
        for(uint8_t j = 0; j < 4; j++)
            CCS_CHACHA_QR(keystream[j], keystream[4 + j], keystream[8 + j], keystream[12 + j]);

        for(uint8_t j = 0; j < 4; j++)
            CCS_CHACHA_QR(
                keystream[j],
                keystream[4  + ((j + 1) % 4)],
                keystream[8  + ((j + 2) % 4)],
                keystream[12 + ((j + 3) % 4)]
            );
    }
}

#if CCS_NEED_CC_IETF
ccs_res_t ccs_chachaN_ietf(
    uint8_t rounds,
    uint32_t ctr,
    const ccs_chacha_key_t key,
    const ccs_chacha_ietf_nonce_t nonce,
    size_t in_len,
    const uint8_t* in,
    uint8_t* out
) {
    if(rounds < 2)
        return CCS_ERROR;

    if(in_len != 0 && (in_len - 1) / CCS_CHACHA_BLOCKLEN > UINT32_MAX - ctr)
        return CCS_ERROR; // Reject if counter will wrap.

    struct {
        uint32_t state[16];
        uint32_t keystream[16];
    } buf;

    // Init State (Optimal)
    for(uint8_t i = 0; i < 4; i++)
        buf.state[i] = CCS_CHACHA_CONSTANT[i];
    for(uint8_t i = 0; i < 8; i++)
        buf.state[4 + i] = ccs_util_load32le(&key[4 * i]);
    buf.state[12] = ctr;
    for(uint8_t i = 0; i < 3; i++)
        buf.state[13 + i] = ccs_util_load32le(&nonce[4 * i]);

    while(in_len > 0) {
        ccs_chacha_block(rounds, buf.state, buf.keystream);

        // Feedforward + arrange little endian
        for(uint8_t i = 0; i < 16; i++) {
#if CCS_LITTLE_ENDIAN
            buf.keystream[i] = buf.keystream[i] + buf.state[i];
#else
            ccs_util_store32le(buf.keystream[i] + buf.state[i], (uint8_t*)&buf.keystream[i]);
#endif
        }

        const uint8_t remaining = (in_len > CCS_CHACHA_BLOCKLEN) ? CCS_CHACHA_BLOCKLEN : (uint8_t)in_len;
        for(uint8_t i = 0; i < remaining; i++)
            out[i] = in[i] ^ (((uint8_t*)buf.keystream)[i]);

        buf.state[12] = buf.state[12] + 1; // Increment block counter

        in += remaining;
        out += remaining;
        in_len -= remaining;
    }

    ccs_util_memzero(sizeof(buf), &buf);

    return CCS_OK;
}
#endif // CCS_NEED_CC_IETF

#if CCS_NEED_CC_DJB
ccs_res_t ccs_chachaN_djb(
    uint8_t rounds,
    uint64_t ctr,
    const ccs_chacha_key_t key,
    const ccs_chacha_djb_nonce_t nonce,
    size_t in_len,
    const uint8_t* in,
    uint8_t* out
) {
    if(rounds < 2)
        return CCS_ERROR;

    if(in_len != 0 && (in_len - 1) / CCS_CHACHA_BLOCKLEN > UINT64_MAX - ctr)
        return CCS_ERROR; // Reject if counter will wrap.

    struct {
        uint32_t state[16];
        uint32_t keystream[16];
    } buf;

    // Init State (Optimal)
    for(uint8_t i = 0; i < 4; i++)
        buf.state[i] = CCS_CHACHA_CONSTANT[i];
    for(uint8_t i = 0; i < 8; i++)
        buf.state[4 + i] = ccs_util_load32le(&key[4 * i]);
    buf.state[12] = (uint32_t)ctr;
    buf.state[13] = (uint32_t)(ctr >> 32);
    for(uint8_t i = 0; i < 2; i++)
        buf.state[14 + i] = ccs_util_load32le(&nonce[4 * i]);

    while(in_len > 0) {
        ccs_chacha_block(rounds, buf.state, buf.keystream);

        // Feedforward + arrange little endian
        for(uint8_t i = 0; i < 16; i++) {
#if CCS_LITTLE_ENDIAN
            buf.keystream[i] = buf.keystream[i] + buf.state[i];
#else
            ccs_util_store32le(buf.keystream[i] + buf.state[i], (uint8_t*)&buf.keystream[i]);
#endif
        }

        const uint8_t remaining = (in_len > CCS_CHACHA_BLOCKLEN) ? CCS_CHACHA_BLOCKLEN : (uint8_t)in_len;
        for(uint8_t i = 0; i < remaining; i++)
            out[i] = in[i] ^ (((uint8_t*)buf.keystream)[i]);

        // Increment block counter
        uint64_t block_ctr = ((uint64_t)buf.state[12]) | ((uint64_t)buf.state[13] << 32);
        block_ctr += 1;
        buf.state[12] = (uint32_t)block_ctr;
        buf.state[13] = (uint32_t)(block_ctr >> 32);

        in += remaining;
        out += remaining;
        in_len -= remaining;
    }

    ccs_util_memzero(sizeof(buf), &buf);

    return CCS_OK;
}
#endif // CCS_NEED_CC_DJB

#if CCS_NEED_HCC
ccs_res_t ccs_hchachaN(
    uint8_t rounds,
    const ccs_chacha_key_t key,
    const ccs_hchacha_nonce_t nonce,
    uint8_t* out
) {
    if(rounds < 2)
        return CCS_ERROR;

    struct {
        uint32_t state[16];
        uint32_t subkey[16];
    } buf;

    for(uint8_t i = 0; i < 4; i++)
        buf.state[i] = CCS_CHACHA_CONSTANT[i];
    for(uint8_t i = 0; i < 8; i++)
        buf.state[4 + i] = ccs_util_load32le(&key[4 * i]);
    for(uint8_t i = 0; i < 4; i++)
        buf.state[12 + i] = ccs_util_load32le(&nonce[4 * i]);

    ccs_chacha_block(rounds, buf.state, buf.subkey);

    for(uint8_t i = 0; i < 4; i++) {
        ccs_util_store32le(buf.subkey[i], &out[4 * i]);
        ccs_util_store32le(buf.subkey[12 + i], &out[16 + 4 * i]);
    }

    ccs_util_memzero(sizeof(buf), &buf);

    return CCS_OK;
}
#endif // CCS_NEED_HCC

#endif // CCS_NEED_CC
