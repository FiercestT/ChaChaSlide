/**
 * @file ccs_chacha.h
 * @brief ChaCha stream cipher interface.
 * @copyright Copyright (c) 2026 FiercestT
 */

#ifndef CCS_CHACHA_H
#define CCS_CHACHA_H

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#include "ccs_config.h"
#if CCS_NEED_CC

#include "ccs_types.h"

// IETF
#if CCS_CC_IETF
/**
 * @brief Encrypt/decrypt input with IETF ChaChaN.
 *        Set in = out for in place encrypt/decrypt.
 *
 * @param rounds Number of rounds, rounded down to even. Values 0 and 1 return CCS_ERROR.
 * @param ctr Initial 32-bit block counter.
 * @param key [CCS_CHACHA_KEYLEN] The ChaCha key.
 * @param nonce [CCS_CHACHA_IETF_NONCELEN] The IETF ChaCha nonce.
 * @param in_len Byte length of the input.
 * @param in [in_len] The input buffer.
 * @param out [in_len] The output buffer.
 * @return CCS_OK on success or CCS_ERROR if the input will cause a counter overflow or rounds < 2.
 */
ccs_res_t ccs_chachaN_ietf(
    uint8_t rounds,
    uint32_t ctr,
    const ccs_chacha_key_t key,
    const ccs_chacha_ietf_nonce_t nonce,
    size_t in_len,
    const uint8_t* in,
    uint8_t* out
);

/**
 * @brief Encrypt/decrypt input with IETF ChaCha20.
 *        Set in = out for in place encrypt/decrypt.
 *
 * @param key [CCS_CHACHA_KEYLEN] The ChaCha key.
 * @param nonce [CCS_CHACHA_IETF_NONCELEN] The IETF ChaCha nonce.
 * @param in_len Byte length of the input.
 * @param in [in_len] The input buffer.
 * @param out [in_len] The output buffer.
 * @return CCS_OK on success or CCS_ERROR if the input will cause a counter overflow.
 */
static inline ccs_res_t ccs_chacha20_ietf(
    const ccs_chacha_key_t key,
    const ccs_chacha_ietf_nonce_t nonce,
    size_t in_len,
    const uint8_t* in,
    uint8_t* out
) {
    return ccs_chachaN_ietf(20, 0, key, nonce, in_len, in, out);
}

#endif // CCS_CC_IETF

// D.J. Bernstein
#if CCS_CC_DJB
/**
 * @brief Encrypt/decrypt input with D.J. Bernstein ChaChaN.
 *        Set in = out for in place encrypt/decrypt.
 *
 * @param rounds Number of rounds, rounded down to even. Values 0 and 1 return CCS_ERROR.
 * @param ctr Initial 64-bit block counter.
 * @param key [CCS_CHACHA_KEYLEN] The ChaCha key.
 * @param nonce [CCS_CHACHA_DJB_NONCELEN] The D.J. Bernstein ChaCha nonce.
 * @param in_len Byte length of the input.
 * @param in [in_len] The input buffer.
 * @param out [in_len] The output buffer.
 * @return CCS_OK on success or CCS_ERROR if the input will cause a counter overflow or rounds < 2.
 */
ccs_res_t ccs_chachaN_djb(
    uint8_t rounds,
    uint64_t ctr,
    const ccs_chacha_key_t key,
    const ccs_chacha_djb_nonce_t nonce,
    size_t in_len,
    const uint8_t* in,
    uint8_t* out
);

/**
 * @brief Encrypt/decrypt input with D.J. Bernstein ChaCha20.
 *        Set in = out for in place encrypt/decrypt.
 *
 * @param key [CCS_CHACHA_KEYLEN] The ChaCha key.
 * @param nonce [CCS_CHACHA_DJB_NONCELEN] The D.J. Bernstein ChaCha nonce.
 * @param in_len Byte length of the input.
 * @param in [in_len] The input buffer.
 * @param out [in_len] The output buffer.
 * @return CCS_OK on success or CCS_ERROR if the input will cause a counter overflow.
 */
static inline ccs_res_t ccs_chacha20_djb(
    const ccs_chacha_key_t key,
    const ccs_chacha_djb_nonce_t nonce,
    size_t in_len,
    const uint8_t* in,
    uint8_t* out
) {
    return ccs_chachaN_djb(20, 0, key, nonce, in_len, in, out);
}

#endif // CCS_CC_DJB

#if CCS_HCC
/**
 * @brief Derive a subkey with HChaChaN.
 *
 * @param rounds Number of rounds, rounded down to even. Values 0 and 1 return CCS_ERROR.
 * @param key [CCS_CHACHA_KEYLEN] The ChaCha key.
 * @param nonce [CCS_HCHACHA_NONCELEN] The HChaCha nonce.
 * @param out [CCS_CHACHA_KEYLEN] The derived subkey buffer.
 * @return CCS_OK on success or CCS_ERROR if rounds < 2.
 */
ccs_res_t ccs_hchachaN(
    uint8_t rounds,
    const ccs_chacha_key_t key,
    const ccs_hchacha_nonce_t nonce,
    uint8_t* out
);

/**
 * @brief Derive a subkey with HChaCha20.
 *
 * @param key [CCS_CHACHA_KEYLEN] The ChaCha key.
 * @param nonce [CCS_HCHACHA_NONCELEN] The HChaCha nonce.
 * @param out [CCS_CHACHA_KEYLEN] The derived subkey buffer.
 * @return CCS_OK on success.
 */
static inline ccs_res_t ccs_hchacha20(
    const ccs_chacha_key_t key,
    const ccs_hchacha_nonce_t nonce,
    uint8_t* out
) {
    return ccs_hchachaN(20, key, nonce, out);
}

#endif // CCS_HCC
#endif // CCS_NEED_CC

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // CCS_CHACHA_H
