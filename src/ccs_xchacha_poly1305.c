/**
 * @file ccs_xchacha_poly1305.c
 * @brief XChaCha20-Poly1305 authenticated encryption implementation.
 * @copyright Copyright (c) 2026 FiercestT
 */

#include "ccs_xchacha_poly1305.h"

#if CCS_XCCP

#include "ccs_chacha_poly1305.h"
#include "ccs_internal.h"
#include "ccs_util.h"

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
) {
    if(rounds < 2)
        return CCS_ERROR;

    if(plaintext_len != 0 && (plaintext_len - 1) / CCS_CHACHA_BLOCKLEN > UINT64_MAX - 1)
        return CCS_ERROR;

    struct {
        ccs_chacha_key_t key;
        ccs_chacha_djb_nonce_t nonce;
    } derived;

    ccs_hchachaN(rounds, key, nonce, derived.key);
    for(uint8_t i = 0; i < CCS_CHACHA_DJB_NONCELEN; i++)
        derived.nonce[i] = nonce[16 + i];

    ccs_poly1305_key_t polykey = { 0 };
    ccs_chachaN_djb(rounds, 0, derived.key, derived.nonce, CCS_POLY1305_KEYLEN, polykey, polykey); // Poly1305 Keygen
    ccs_chachaN_djb(rounds, 1, derived.key, derived.nonce, plaintext_len, plaintext, ciphertext); // Ciphertext
    ccs_chacha_poly1305_ietf_tag(polykey, plaintext_len, ciphertext, ad_len, ad, tag); // MAC

    ccs_util_memzero(sizeof(polykey), polykey);
    ccs_util_memzero(sizeof(derived), &derived);

    return CCS_OK;
}

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
) {
    if(rounds < 2)
        return CCS_ERROR;

    if(ciphertext_len != 0 && (ciphertext_len - 1) / CCS_CHACHA_BLOCKLEN > UINT64_MAX - 1)
        return CCS_ERROR;

    struct {
        ccs_chacha_key_t key;
        ccs_chacha_djb_nonce_t nonce;
    } derived;

    ccs_hchachaN(rounds, key, nonce, derived.key);
    for(uint8_t i = 0; i < CCS_CHACHA_DJB_NONCELEN; i++)
        derived.nonce[i] = nonce[16 + i];

    uint8_t buffer[CCS_POLY1305_KEYLEN] = { 0 }; // Poly1305 key, then computed tag.
    ccs_chachaN_djb(rounds, 0, derived.key, derived.nonce, CCS_POLY1305_KEYLEN, buffer, buffer); // Poly1305 Keygen
    ccs_chacha_poly1305_ietf_tag(buffer, ciphertext_len, ciphertext, ad_len, ad, buffer); // MAC

    ccs_res_t res = ccs_poly1305_verify(tag, buffer);
    if(res == CCS_OK)
        ccs_chachaN_djb(rounds, 1, derived.key, derived.nonce, ciphertext_len, ciphertext, plaintext); // Plaintext

    ccs_util_memzero(sizeof(buffer), buffer);
    ccs_util_memzero(sizeof(derived), &derived);

    return res;
}

#endif // CCS_XCCP
