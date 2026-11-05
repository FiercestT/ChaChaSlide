/**
 * @file ccs_xchacha_poly1305.h
 * @brief XChaCha20-Poly1305 authenticated encryption interface.
 * @copyright Copyright (c) 2026 FiercestT
 */

#ifndef CCS_XCHACHA_POLY1305_H
#define CCS_XCHACHA_POLY1305_H

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#include "ccs_config.h"
#if CCS_XCCP

#include "ccs_types.h"

/**
 * @brief Encrypt plaintext and authenticate unencrypted data with XChaChaN-Poly1305.
 *
 * The round count applies to both HChaCha subkey derivation and ChaCha payload processing.
 * @param rounds Number of rounds, rounded down to even. Values 0 and 1 return CCS_ERROR.
 *
 * @param key [CCS_CHACHA_KEYLEN] The ChaCha key.
 * @param nonce [CCS_XCHACHA_NONCELEN] The XChaCha nonce.
 * @param plaintext_len Byte length of the plaintext input.
 * @param plaintext [plaintext_len] The plaintext input buffer.
 * @param ad_len Byte length of the unencrypted, authenticated data.
 * @param ad [ad_len] The unencrypted, authenticated data buffer.
 * @param ciphertext [plaintext_len] The ciphertext output buffer.
 * @param tag [CCS_POLY1305_LEN] The authentication tag output buffer.
 * @return CCS_OK on success or CCS_ERROR if the input will cause a counter overflow or rounds < 2.
 */
ccs_res_t ccs_xchachaN_poly1305_encrypt(
    uint8_t rounds,
    const ccs_chacha_key_t key,
    const ccs_xchacha_nonce_t nonce,
    size_t plaintext_len,
    const uint8_t* plaintext,
    size_t ad_len,
    const uint8_t* ad,
    uint8_t* ciphertext,
    ccs_poly1305_digest_t tag
);

/**
 * @brief Encrypt plaintext and authenticate unencrypted data with XChaCha20-Poly1305.
 *
 * @param key [CCS_CHACHA_KEYLEN] The ChaCha key.
 * @param nonce [CCS_XCHACHA_NONCELEN] The XChaCha nonce.
 * @param plaintext_len Byte length of the plaintext input.
 * @param plaintext [plaintext_len] The plaintext input buffer.
 * @param ad_len Byte length of the unencrypted, authenticated data.
 * @param ad [ad_len] The unencrypted, authenticated data buffer.
 * @param ciphertext [plaintext_len] The ciphertext output buffer.
 * @param tag [CCS_POLY1305_LEN] The authentication tag output buffer.
 * @return CCS_OK on success or CCS_ERROR if the input will cause a counter overflow.
 */
static inline ccs_res_t ccs_xchacha20_poly1305_encrypt(
    const ccs_chacha_key_t key,
    const ccs_xchacha_nonce_t nonce,
    size_t plaintext_len,
    const uint8_t* plaintext,
    size_t ad_len,
    const uint8_t* ad,
    uint8_t* ciphertext,
    ccs_poly1305_digest_t tag
) {
    return ccs_xchachaN_poly1305_encrypt(20, key, nonce, plaintext_len, plaintext, ad_len, ad, ciphertext, tag);
}

/**
 * @brief Verify and decrypt ciphertext with XChaChaN-Poly1305.
 *
 * The round count applies to both HChaCha subkey derivation and ChaCha payload processing.
 * @param rounds Number of rounds, rounded down to even. Values 0 and 1 return CCS_ERROR.
 *
 * @param key [CCS_CHACHA_KEYLEN] The ChaCha key.
 * @param nonce [CCS_XCHACHA_NONCELEN] The XChaCha nonce.
 * @param tag [CCS_POLY1305_LEN] The authentication tag to verify.
 * @param ciphertext_len Byte length of the ciphertext input.
 * @param ciphertext [ciphertext_len] The ciphertext input buffer.
 * @param ad_len Byte length of the unencrypted, authenticated data.
 * @param ad [ad_len] The unencrypted, authenticated data buffer.
 * @param plaintext [ciphertext_len] The plaintext output buffer.
 * @return CCS_OK on success, CCS_VERIFICATION_FAILED if tag verification fails, or CCS_ERROR if the input will cause a counter overflow or rounds < 2.
 */
ccs_res_t ccs_xchachaN_poly1305_decrypt(
    uint8_t rounds,
    const ccs_chacha_key_t key,
    const ccs_xchacha_nonce_t nonce,
    const ccs_poly1305_digest_t tag,
    size_t ciphertext_len,
    const uint8_t* ciphertext,
    size_t ad_len,
    const uint8_t* ad,
    uint8_t* plaintext
);

/**
 * @brief Verify and decrypt ciphertext with XChaCha20-Poly1305.
 *
 * @param key [CCS_CHACHA_KEYLEN] The ChaCha key.
 * @param nonce [CCS_XCHACHA_NONCELEN] The XChaCha nonce.
 * @param tag [CCS_POLY1305_LEN] The authentication tag to verify.
 * @param ciphertext_len Byte length of the ciphertext input.
 * @param ciphertext [ciphertext_len] The ciphertext input buffer.
 * @param ad_len Byte length of the unencrypted, authenticated data.
 * @param ad [ad_len] The unencrypted, authenticated data buffer.
 * @param plaintext [ciphertext_len] The plaintext output buffer.
 * @return CCS_OK on success, CCS_VERIFICATION_FAILED if tag verification fails, or CCS_ERROR if the input will cause a counter overflow.
 */
static inline ccs_res_t ccs_xchacha20_poly1305_decrypt(
    const ccs_chacha_key_t key,
    const ccs_xchacha_nonce_t nonce,
    const ccs_poly1305_digest_t tag,
    size_t ciphertext_len,
    const uint8_t* ciphertext,
    size_t ad_len,
    const uint8_t* ad,
    uint8_t* plaintext
) {
    return ccs_xchachaN_poly1305_decrypt(20, key, nonce, tag, ciphertext_len, ciphertext, ad_len, ad, plaintext);
}

#endif // CCS_XCCP

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // CCS_XCHACHA_POLY1305_H
