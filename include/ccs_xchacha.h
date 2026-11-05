/**
 * @file ccs_xchacha.h
 * @brief XChaCha stream cipher interface.
 * @copyright Copyright (c) 2026 FiercestT
 */

#ifndef CCS_XCHACHA_H
#define CCS_XCHACHA_H

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#include "ccs_config.h"
#if CCS_XCC

#include "ccs_types.h"

/**
 * @brief Encrypt/decrypt input with XChaChaN.
 *        Set in = out for in place encrypt/decrypt.
 *
 * @param rounds Number of HChaCha and ChaCha rounds, rounded down to even. Values 0 and 1 return CCS_ERROR.
 * @param ctr Initial 64-bit block counter.
 * @param key [CCS_CHACHA_KEYLEN] The ChaCha key.
 * @param nonce [CCS_XCHACHA_NONCELEN] The XChaCha nonce.
 * @param in_len Byte length of the input.
 * @param in [in_len] The input buffer.
 * @param out [in_len] The output buffer.
 * @return CCS_OK on success or CCS_ERROR if the input will cause a counter overflow or rounds < 2.
 */
ccs_res_t ccs_xchachaN(
    uint8_t rounds,
    uint64_t ctr,
    const ccs_chacha_key_t key,
    const ccs_xchacha_nonce_t nonce,
    size_t in_len,
    const uint8_t* in,
    uint8_t* out
);

/**
 * @brief Encrypt/decrypt input with XChaCha20.
 *        Set in = out for in place encrypt/decrypt.
 *
 * @param key [CCS_CHACHA_KEYLEN] The ChaCha key.
 * @param nonce [CCS_XCHACHA_NONCELEN] The XChaCha nonce.
 * @param in_len Byte length of the input.
 * @param in [in_len] The input buffer.
 * @param out [in_len] The output buffer.
 * @return CCS_OK on success or CCS_ERROR if the input will cause a counter overflow.
 */
static inline ccs_res_t ccs_xchacha20(
    const ccs_chacha_key_t key,
    const ccs_xchacha_nonce_t nonce,
    size_t in_len,
    const uint8_t* in,
    uint8_t* out
) {
    return ccs_xchachaN(20, 0, key, nonce, in_len, in, out);
}

#endif // CCS_XCC

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // CCS_XCHACHA_H
