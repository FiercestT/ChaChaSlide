/**
 * @file ccs_types.h
 * @brief Shared public types for ChaChaSlide.
 * @copyright Copyright (c) 2026 FiercestT
 */

#ifndef CCS_TYPES_H
#define CCS_TYPES_H

#include <stddef.h>
#include <stdint.h>
#include "ccs_config.h"

typedef enum ccs_res_e {
    CCS_OK,
    CCS_ERROR,
    CCS_VERIFICATION_FAILED
} ccs_res_t;

#if CCS_NEED_CC
#define CCS_CHACHA_KEYLEN (32)
#define CCS_CHACHA_BLOCKLEN (64)
typedef uint8_t ccs_chacha_key_t[CCS_CHACHA_KEYLEN];
#endif // CCS_NEED_CC

#if CCS_NEED_CC_IETF
#define CCS_CHACHA_IETF_NONCELEN (12)
typedef uint8_t ccs_chacha_ietf_nonce_t[CCS_CHACHA_IETF_NONCELEN];
#endif // CCS_NEED_CC_IETF

#if CCS_NEED_CC_DJB
#define CCS_CHACHA_DJB_NONCELEN (8)
typedef uint8_t ccs_chacha_djb_nonce_t[CCS_CHACHA_DJB_NONCELEN];
#endif // CCS_NEED_CC_DJB

#if CCS_NEED_XCC || CCS_XCCP
#define CCS_XCHACHA_NONCELEN (24)
typedef uint8_t ccs_xchacha_nonce_t[CCS_XCHACHA_NONCELEN];
#endif // CCS_NEED_XCC || CCS_XCCP

#if CCS_NEED_HCC
#define CCS_HCHACHA_NONCELEN (16)
typedef uint8_t ccs_hchacha_nonce_t[CCS_HCHACHA_NONCELEN];
#endif // CCS_NEED_HCC

#if CCS_NEED_POLY
#define CCS_POLY1305_LEN      (16)
#define CCS_POLY1305_KEYLEN   (32)
#define CCS_POLY1305_BLOCKLEN (16)
typedef uint8_t ccs_poly1305_digest_t[CCS_POLY1305_LEN];
typedef uint8_t ccs_poly1305_key_t[CCS_POLY1305_KEYLEN];

typedef struct ccs_poly1305_ctx_s {
    uint32_t h[5]; // Accumulator
    uint32_t r[4]; // R part of Key
    uint32_t s[4]; // S part of Key
    uint8_t block[CCS_POLY1305_BLOCKLEN];
    uint8_t block_idx;
} ccs_poly1305_ctx_t;
#endif // CCS_NEED_POLY

#if CCS_B2S
#define CCS_BLAKE2S_LEN         (32)
#define CCS_BLAKE2S_KEYLEN      (32)
#define CCS_BLAKE2S_BLOCKLEN    (64)
#define CCS_BLAKE2S_SALTLEN     (8)
#define CCS_BLAKE2S_PERSONALLEN (8)
typedef uint8_t ccs_blake2s_digest_t[CCS_BLAKE2S_LEN];
typedef uint8_t ccs_blake2s_key_t[CCS_BLAKE2S_KEYLEN];
typedef uint8_t ccs_blake2s_salt_t[CCS_BLAKE2S_SALTLEN];
typedef uint8_t ccs_blake2s_personal_t[CCS_BLAKE2S_PERSONALLEN];

typedef struct ccs_blake2s_ctx_s {
    uint32_t h[8]; // Chaining state
    uint32_t t[2]; // Byte counter
    uint8_t block[CCS_BLAKE2S_BLOCKLEN];
    uint8_t block_idx;
    uint8_t digest_len;
    uint8_t f; // Final block flag
} ccs_blake2s_ctx_t;
#endif // CCS_B2S

#if CCS_B2B
#define CCS_BLAKE2B_LEN         (64)
#define CCS_BLAKE2B_KEYLEN      (64)
#define CCS_BLAKE2B_BLOCKLEN    (128)
#define CCS_BLAKE2B_SALTLEN     (16)
#define CCS_BLAKE2B_PERSONALLEN (16)
typedef uint8_t ccs_blake2b_digest_t[CCS_BLAKE2B_LEN];
typedef uint8_t ccs_blake2b_key_t[CCS_BLAKE2B_KEYLEN];
typedef uint8_t ccs_blake2b_salt_t[CCS_BLAKE2B_SALTLEN];
typedef uint8_t ccs_blake2b_personal_t[CCS_BLAKE2B_PERSONALLEN];

typedef struct ccs_blake2b_ctx_s {
    uint64_t h[8]; // Chaining state
    uint64_t t[2]; // Byte counter
    uint8_t block[CCS_BLAKE2B_BLOCKLEN];
    uint8_t block_idx;
    uint8_t digest_len;
    uint8_t f; // Final block flag
} ccs_blake2b_ctx_t;
#endif // CCS_B2B

#endif // CCS_TYPES_H
