/**
 * @file ccs_chacha_poly1305.c
 * @brief ChaCha20-Poly1305 authenticated encryption implementation.
 * @copyright Copyright (c) 2026 FiercestT
 */

#include "ccs_chacha_poly1305.h"

#if CCS_NEED_CCP

#include "ccs_util.h"
#include "ccs_internal.h"

#if CCS_CCP_IETF || CCS_XCCP
void ccs_chacha_poly1305_ietf_tag(
    const ccs_poly1305_key_t polykey,
    size_t text_len,
    const uint8_t* text,
    size_t ad_len,
    const uint8_t* ad,
    ccs_poly1305_digest_t tag
) {
    uint8_t buffer[16] = { 0 };
    ccs_poly1305_ctx_t ctx;

    ccs_poly1305_init(&ctx, polykey);
    ccs_poly1305_update(&ctx, ad_len, ad);
    ccs_poly1305_update(&ctx, (-ad_len) % 16, buffer);
    ccs_poly1305_update(&ctx, text_len, text);
    ccs_poly1305_update(&ctx, (-text_len) % 16, buffer);
    ccs_util_store64le((uint64_t)ad_len, &buffer[0]);
    ccs_util_store64le((uint64_t)text_len, &buffer[8]);
    ccs_poly1305_update(&ctx, sizeof(buffer), buffer);
    ccs_poly1305_final(&ctx, tag);
}
#endif // CCS_CCP_IETF || CCS_XCCP

#if CCS_CCP_IETF
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
) {
    if(rounds < 2)
        return CCS_ERROR;

    if(plaintext_len != 0 && (plaintext_len - 1) / CCS_CHACHA_BLOCKLEN > UINT32_MAX - 1)
        return CCS_ERROR;

    ccs_poly1305_key_t polykey = { 0 };
    ccs_chachaN_ietf(rounds, 0, key, nonce, CCS_POLY1305_KEYLEN, polykey, polykey); // Poly1305 Keygen
    ccs_chachaN_ietf(rounds, 1, key, nonce, plaintext_len, plaintext, ciphertext); // Ciphertext
    ccs_chacha_poly1305_ietf_tag(polykey, plaintext_len, ciphertext, ad_len, ad, tag); // MAC

    ccs_util_memzero(sizeof(polykey), polykey);

    return CCS_OK;
}

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
) {
    if(rounds < 2)
        return CCS_ERROR;

    if(ciphertext_len != 0 && (ciphertext_len - 1) / CCS_CHACHA_BLOCKLEN > UINT32_MAX - 1)
        return CCS_ERROR;

    uint8_t buffer[CCS_POLY1305_KEYLEN] = { 0 }; // Poly1305 key, then computed tag.
    ccs_chachaN_ietf(rounds, 0, key, nonce, CCS_POLY1305_KEYLEN, buffer, buffer); // Poly1305 Keygen
    ccs_chacha_poly1305_ietf_tag(buffer, ciphertext_len, ciphertext, ad_len, ad, buffer); // MAC

    ccs_res_t res = ccs_poly1305_verify(tag, buffer);
    if(res == CCS_OK)
        ccs_chachaN_ietf(rounds, 1, key, nonce, ciphertext_len, ciphertext, plaintext); // Plaintext

    ccs_util_memzero(sizeof(buffer), buffer);

    return res;
}
#endif // CCS_CCP_IETF

#if CCS_CCP_DJB
void ccs_chacha_poly1305_djb_tag(
    const ccs_poly1305_key_t polykey,
    size_t text_len,
    const uint8_t* text,
    size_t ad_len,
    const uint8_t* ad,
    ccs_poly1305_digest_t tag
) {
    uint8_t length[8];
    ccs_poly1305_ctx_t ctx;

    // LibSodium compatible DJB framing (pre-IETF)
    ccs_poly1305_init(&ctx, polykey);
    ccs_poly1305_update(&ctx, ad_len, ad);
    ccs_util_store64le((uint64_t)ad_len, length);
    ccs_poly1305_update(&ctx, sizeof(length), length);
    ccs_poly1305_update(&ctx, text_len, text);
    ccs_util_store64le((uint64_t)text_len, length);
    ccs_poly1305_update(&ctx, sizeof(length), length);
    ccs_poly1305_final(&ctx, tag);
}

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
) {
    if(rounds < 2)
        return CCS_ERROR;

    if(plaintext_len != 0 && (plaintext_len - 1) / CCS_CHACHA_BLOCKLEN > UINT64_MAX - 1)
        return CCS_ERROR;

    ccs_poly1305_key_t polykey = { 0 };
    ccs_chachaN_djb(rounds, 0, key, nonce, CCS_POLY1305_KEYLEN, polykey, polykey); // Poly1305 Keygen
    ccs_chachaN_djb(rounds, 1, key, nonce, plaintext_len, plaintext, ciphertext); // Ciphertext
    ccs_chacha_poly1305_djb_tag(polykey, plaintext_len, ciphertext, ad_len, ad, tag); // MAC

    ccs_util_memzero(sizeof(polykey), polykey);

    return CCS_OK;
}

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
) {
    if(rounds < 2)
        return CCS_ERROR;

    if(ciphertext_len != 0 && (ciphertext_len - 1) / CCS_CHACHA_BLOCKLEN > UINT64_MAX - 1)
        return CCS_ERROR;

    uint8_t buffer[CCS_POLY1305_KEYLEN] = { 0 }; // Poly1305 key, then computed tag.
    ccs_chachaN_djb(rounds, 0, key, nonce, CCS_POLY1305_KEYLEN, buffer, buffer); // Poly1305 Keygen
    ccs_chacha_poly1305_djb_tag(buffer, ciphertext_len, ciphertext, ad_len, ad, buffer); // MAC

    ccs_res_t res = ccs_poly1305_verify(tag, buffer);
    if(res == CCS_OK)
        ccs_chachaN_djb(rounds, 1, key, nonce, ciphertext_len, ciphertext, plaintext); // Plaintext

    ccs_util_memzero(sizeof(buffer), buffer);

    return res;
}
#endif // CCS_CCP_DJB

#endif // CCS_NEED_CCP
