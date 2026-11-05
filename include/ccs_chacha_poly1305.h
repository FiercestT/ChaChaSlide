/**
 * @file ccs_chacha_poly1305.h
 * @brief ChaCha20-Poly1305 authenticated encryption interface.
 * @copyright Copyright (c) 2026 FiercestT
 */

#ifndef CCS_CHACHA_POLY1305_H
#define CCS_CHACHA_POLY1305_H

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#include "ccs_config.h"
#if CCS_NEED_CCP

#include "ccs_types.h"

// IETF
#if CCS_CCP_IETF || CCS_XCCP
/**
 * @brief Compute an IETF-format Poly1305 tag over ciphertext and authenticated data.
 *
 * Authenticates padded data followed by padded ciphertext and their little-endian
 * 64-bit byte lengths. Also used by XChaCha20-Poly1305.
 * The tag output may start at polykey; the key is consumed before the tag is written.
 *
 * @param polykey [CCS_POLY1305_KEYLEN] The one-time Poly1305 key. Never reuse this key.
 * @param text_len Byte length of the ciphertext input.
 * @param text [text_len] The ciphertext input buffer.
 * @param ad_len Byte length of the unencrypted, authenticated data.
 * @param ad [ad_len] The unencrypted, authenticated data buffer.
 * @param tag [CCS_POLY1305_LEN] The authentication tag output buffer.
 */
void ccs_chacha_poly1305_ietf_tag(
    const ccs_poly1305_key_t polykey,
    size_t text_len,
    const uint8_t* text,
    size_t ad_len,
    const uint8_t* ad,
    ccs_poly1305_digest_t tag
);
#endif // CCS_CCP_IETF || CCS_XCCP

#if CCS_CCP_IETF
/**
 * @brief Encrypt plaintext and authenticate unencrypted data with IETF ChaChaN-Poly1305.
 *
 * @param rounds Number of rounds, rounded down to even. Values 0 and 1 return CCS_ERROR.
 *
 * @param key [CCS_CHACHA_KEYLEN] The ChaCha key.
 * @param nonce [CCS_CHACHA_IETF_NONCELEN] The IETF ChaCha nonce.
 * @param plaintext_len Byte length of the plaintext input.
 * @param plaintext [plaintext_len] The plaintext input buffer.
 * @param ad_len Byte length of the unencrypted, authenticated data.
 * @param ad [ad_len] The unencrypted, authenticated data buffer.
 * @param ciphertext [plaintext_len] The ciphertext output buffer.
 * @param tag [CCS_POLY1305_LEN] The authentication tag output buffer.
 * @return CCS_OK on success or CCS_ERROR if the input will cause a counter overflow or rounds < 2.
 */
ccs_res_t ccs_chachaN_poly1305_ietf_encrypt(
    uint8_t rounds,
    const ccs_chacha_key_t key,
    const ccs_chacha_ietf_nonce_t nonce,
    size_t plaintext_len,
    const uint8_t* plaintext,
    size_t ad_len,
    const uint8_t* ad,
    uint8_t* ciphertext,
    ccs_poly1305_digest_t tag
);

/**
 * @brief Encrypt plaintext and authenticate unencrypted data with IETF ChaCha20-Poly1305.
 *
 * @param key [CCS_CHACHA_KEYLEN] The ChaCha key.
 * @param nonce [CCS_CHACHA_IETF_NONCELEN] The IETF ChaCha nonce.
 * @param plaintext_len Byte length of the plaintext input.
 * @param plaintext [plaintext_len] The plaintext input buffer.
 * @param ad_len Byte length of the unencrypted, authenticated data.
 * @param ad [ad_len] The unencrypted, authenticated data buffer.
 * @param ciphertext [plaintext_len] The ciphertext output buffer.
 * @param tag [CCS_POLY1305_LEN] The authentication tag output buffer.
 * @return CCS_OK on success or CCS_ERROR if the input will cause a counter overflow.
 */
static inline ccs_res_t ccs_chacha20_poly1305_ietf_encrypt(
    const ccs_chacha_key_t key,
    const ccs_chacha_ietf_nonce_t nonce,
    size_t plaintext_len,
    const uint8_t* plaintext,
    size_t ad_len,
    const uint8_t* ad,
    uint8_t* ciphertext,
    ccs_poly1305_digest_t tag
) {
    return ccs_chachaN_poly1305_ietf_encrypt(20, key, nonce, plaintext_len, plaintext, ad_len, ad, ciphertext, tag);
}

/**
 * @brief Verify and decrypt ciphertext with IETF ChaChaN-Poly1305.
 *
 * @param rounds Number of rounds, rounded down to even. Values 0 and 1 return CCS_ERROR.
 *
 * @param key [CCS_CHACHA_KEYLEN] The ChaCha key.
 * @param nonce [CCS_CHACHA_IETF_NONCELEN] The IETF ChaCha nonce.
 * @param tag [CCS_POLY1305_LEN] The authentication tag to verify.
 * @param ciphertext_len Byte length of the ciphertext input.
 * @param ciphertext [ciphertext_len] The ciphertext input buffer.
 * @param ad_len Byte length of the unencrypted, authenticated data.
 * @param ad [ad_len] The unencrypted, authenticated data buffer.
 * @param plaintext [ciphertext_len] The plaintext output buffer.
 * @return CCS_OK on success, CCS_VERIFICATION_FAILED if tag verification fails, or CCS_ERROR if the input will cause a counter overflow or rounds < 2.
 */
ccs_res_t ccs_chachaN_poly1305_ietf_decrypt(
    uint8_t rounds,
    const ccs_chacha_key_t key,
    const ccs_chacha_ietf_nonce_t nonce,
    const ccs_poly1305_digest_t tag,
    size_t ciphertext_len,
    const uint8_t* ciphertext,
    size_t ad_len,
    const uint8_t* ad,
    uint8_t* plaintext
);

/**
 * @brief Verify and decrypt ciphertext with IETF ChaCha20-Poly1305.
 *
 * @param key [CCS_CHACHA_KEYLEN] The ChaCha key.
 * @param nonce [CCS_CHACHA_IETF_NONCELEN] The IETF ChaCha nonce.
 * @param tag [CCS_POLY1305_LEN] The authentication tag to verify.
 * @param ciphertext_len Byte length of the ciphertext input.
 * @param ciphertext [ciphertext_len] The ciphertext input buffer.
 * @param ad_len Byte length of the unencrypted, authenticated data.
 * @param ad [ad_len] The unencrypted, authenticated data buffer.
 * @param plaintext [ciphertext_len] The plaintext output buffer.
 * @return CCS_OK on success, CCS_VERIFICATION_FAILED if tag verification fails, or CCS_ERROR if the input will cause a counter overflow.
 */
static inline ccs_res_t ccs_chacha20_poly1305_ietf_decrypt(
    const ccs_chacha_key_t key,
    const ccs_chacha_ietf_nonce_t nonce,
    const ccs_poly1305_digest_t tag,
    size_t ciphertext_len,
    const uint8_t* ciphertext,
    size_t ad_len,
    const uint8_t* ad,
    uint8_t* plaintext
) {
    return ccs_chachaN_poly1305_ietf_decrypt(20, key, nonce, tag, ciphertext_len, ciphertext, ad_len, ad, plaintext);
}

#endif // CCS_CCP_IETF

// D.J. Bernstein
#if CCS_CCP_DJB
/**
 * @brief Compute a D.J. Bernstein-format Poly1305 tag over ciphertext and authenticated data.
 *
 * Authenticates data, its little-endian 64-bit byte length, ciphertext, and its
 * little-endian 64-bit byte length, with no zero padding.
 * The tag output may start at polykey; the key is consumed before the tag is written.
 *
 * @param polykey [CCS_POLY1305_KEYLEN] The one-time Poly1305 key. Never reuse this key.
 * @param text_len Byte length of the ciphertext input.
 * @param text [text_len] The ciphertext input buffer.
 * @param ad_len Byte length of the unencrypted, authenticated data.
 * @param ad [ad_len] The unencrypted, authenticated data buffer.
 * @param tag [CCS_POLY1305_LEN] The authentication tag output buffer.
 */
void ccs_chacha_poly1305_djb_tag(
    const ccs_poly1305_key_t polykey,
    size_t text_len,
    const uint8_t* text,
    size_t ad_len,
    const uint8_t* ad,
    ccs_poly1305_digest_t tag
);
/**
 * @brief Encrypt plaintext and authenticate unencrypted data with D.J. Bernstein ChaChaN-Poly1305.
 *
 * @param rounds Number of rounds, rounded down to even. Values 0 and 1 return CCS_ERROR.
 *
 * @param key [CCS_CHACHA_KEYLEN] The ChaCha key.
 * @param nonce [CCS_CHACHA_DJB_NONCELEN] The D.J. Bernstein ChaCha nonce.
 * @param plaintext_len Byte length of the plaintext input.
 * @param plaintext [plaintext_len] The plaintext input buffer.
 * @param ad_len Byte length of the unencrypted, authenticated data.
 * @param ad [ad_len] The unencrypted, authenticated data buffer.
 * @param ciphertext [plaintext_len] The ciphertext output buffer.
 * @param tag [CCS_POLY1305_LEN] The authentication tag output buffer.
 * @return CCS_OK on success or CCS_ERROR if the input will cause a counter overflow or rounds < 2.
 */
ccs_res_t ccs_chachaN_poly1305_djb_encrypt(
    uint8_t rounds,
    const ccs_chacha_key_t key,
    const ccs_chacha_djb_nonce_t nonce,
    size_t plaintext_len,
    const uint8_t* plaintext,
    size_t ad_len,
    const uint8_t* ad,
    uint8_t* ciphertext,
    ccs_poly1305_digest_t tag
);

/**
 * @brief Encrypt plaintext and authenticate unencrypted data with D.J. Bernstein ChaCha20-Poly1305.
 *
 * @param key [CCS_CHACHA_KEYLEN] The ChaCha key.
 * @param nonce [CCS_CHACHA_DJB_NONCELEN] The D.J. Bernstein ChaCha nonce.
 * @param plaintext_len Byte length of the plaintext input.
 * @param plaintext [plaintext_len] The plaintext input buffer.
 * @param ad_len Byte length of the unencrypted, authenticated data.
 * @param ad [ad_len] The unencrypted, authenticated data buffer.
 * @param ciphertext [plaintext_len] The ciphertext output buffer.
 * @param tag [CCS_POLY1305_LEN] The authentication tag output buffer.
 * @return CCS_OK on success or CCS_ERROR if the input will cause a counter overflow.
 */
static inline ccs_res_t ccs_chacha20_poly1305_djb_encrypt(
    const ccs_chacha_key_t key,
    const ccs_chacha_djb_nonce_t nonce,
    size_t plaintext_len,
    const uint8_t* plaintext,
    size_t ad_len,
    const uint8_t* ad,
    uint8_t* ciphertext,
    ccs_poly1305_digest_t tag
) {
    return ccs_chachaN_poly1305_djb_encrypt(20, key, nonce, plaintext_len, plaintext, ad_len, ad, ciphertext, tag);
}

/**
 * @brief Verify and decrypt ciphertext with D.J. Bernstein ChaChaN-Poly1305.
 *
 * @param rounds Number of rounds, rounded down to even. Values 0 and 1 return CCS_ERROR.
 *
 * @param key [CCS_CHACHA_KEYLEN] The ChaCha key.
 * @param nonce [CCS_CHACHA_DJB_NONCELEN] The D.J. Bernstein ChaCha nonce.
 * @param tag [CCS_POLY1305_LEN] The authentication tag to verify.
 * @param ciphertext_len Byte length of the ciphertext input.
 * @param ciphertext [ciphertext_len] The ciphertext input buffer.
 * @param ad_len Byte length of the unencrypted, authenticated data.
 * @param ad [ad_len] The unencrypted, authenticated data buffer.
 * @param plaintext [ciphertext_len] The plaintext output buffer.
 * @return CCS_OK on success, CCS_VERIFICATION_FAILED if tag verification fails, or CCS_ERROR if the input will cause a counter overflow or rounds < 2.
 */
ccs_res_t ccs_chachaN_poly1305_djb_decrypt(
    uint8_t rounds,
    const ccs_chacha_key_t key,
    const ccs_chacha_djb_nonce_t nonce,
    const ccs_poly1305_digest_t tag,
    size_t ciphertext_len,
    const uint8_t* ciphertext,
    size_t ad_len,
    const uint8_t* ad,
    uint8_t* plaintext
);

/**
 * @brief Verify and decrypt ciphertext with D.J. Bernstein ChaCha20-Poly1305.
 *
 * @param key [CCS_CHACHA_KEYLEN] The ChaCha key.
 * @param nonce [CCS_CHACHA_DJB_NONCELEN] The D.J. Bernstein ChaCha nonce.
 * @param tag [CCS_POLY1305_LEN] The authentication tag to verify.
 * @param ciphertext_len Byte length of the ciphertext input.
 * @param ciphertext [ciphertext_len] The ciphertext input buffer.
 * @param ad_len Byte length of the unencrypted, authenticated data.
 * @param ad [ad_len] The unencrypted, authenticated data buffer.
 * @param plaintext [ciphertext_len] The plaintext output buffer.
 * @return CCS_OK on success, CCS_VERIFICATION_FAILED if tag verification fails, or CCS_ERROR if the input will cause a counter overflow.
 */
static inline ccs_res_t ccs_chacha20_poly1305_djb_decrypt(
    const ccs_chacha_key_t key,
    const ccs_chacha_djb_nonce_t nonce,
    const ccs_poly1305_digest_t tag,
    size_t ciphertext_len,
    const uint8_t* ciphertext,
    size_t ad_len,
    const uint8_t* ad,
    uint8_t* plaintext
) {
    return ccs_chachaN_poly1305_djb_decrypt(20, key, nonce, tag, ciphertext_len, ciphertext, ad_len, ad, plaintext);
}

#endif // CCS_CCP_DJB

#endif // CCS_NEED_CCP

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // CCS_CHACHA_POLY1305_H
