/**
 * @file ccs_internal.h
 * @brief Private cipher and authenticator interfaces.
 * @copyright Copyright (c) 2026 FiercestT
 */

#ifndef CCS_INTERNAL_H
#define CCS_INTERNAL_H

#include "ccs_types.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#if CCS_NEED_CC_IETF
ccs_res_t ccs_chachaN_ietf(
    uint8_t rounds,
    uint32_t ctr,
    const ccs_chacha_key_t key,
    const ccs_chacha_ietf_nonce_t nonce,
    size_t in_len,
    const uint8_t* in,
    uint8_t* out
);
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
);
#endif // CCS_NEED_CC_DJB

#if CCS_NEED_HCC
ccs_res_t ccs_hchachaN(
    uint8_t rounds,
    const ccs_chacha_key_t key,
    const ccs_hchacha_nonce_t nonce,
    uint8_t* out
);
#endif // CCS_NEED_HCC

#if CCS_NEED_XCC
ccs_res_t ccs_xchachaN(
    uint8_t rounds,
    uint64_t ctr,
    const ccs_chacha_key_t key,
    const ccs_xchacha_nonce_t nonce,
    size_t in_len,
    const uint8_t* in,
    uint8_t* out
);
#endif // CCS_NEED_XCC

#if CCS_NEED_POLY
ccs_res_t ccs_poly1305_init(
    ccs_poly1305_ctx_t* ctx,
    const ccs_poly1305_key_t key
);

ccs_res_t ccs_poly1305_update(
    ccs_poly1305_ctx_t* ctx,
    size_t in_len,
    const uint8_t* in
);

ccs_res_t ccs_poly1305_final(
    ccs_poly1305_ctx_t* ctx,
    ccs_poly1305_digest_t digest
);

ccs_res_t ccs_poly1305_verify(
    const ccs_poly1305_digest_t expected,
    const ccs_poly1305_digest_t actual
);
#endif // CCS_NEED_POLY

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // CCS_INTERNAL_H
