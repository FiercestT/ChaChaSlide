/**
 * @file ccs_poly1305.h
 * @brief Poly1305 one-time authenticator interface.
 * @copyright Copyright (c) 2026 FiercestT
 */

#ifndef CCS_POLY1305_H
#define CCS_POLY1305_H

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#include "ccs_config.h"
#if CCS_POLY

#include "ccs_types.h"

/**
 * @brief Initialize an incremental Poly1305 computation.
 *
 * @param ctx The Poly1305 context to initialize. Does not need to be zeroed before init.
 * @param key [CCS_POLY1305_KEYLEN] The one-time Poly1305 key. Never reuse this key.
 * @return CCS_OK on success.
 */
ccs_res_t ccs_poly1305_init(
    ccs_poly1305_ctx_t* ctx,
    const ccs_poly1305_key_t key
);

/**
 * @brief Add input to an incremental Poly1305 computation.
 *
 * @param ctx The initialized Poly1305 context.
 * @param in_len Byte length of the input.
 * @param in [in_len] The input buffer.
 * @return CCS_OK on success.
 */
ccs_res_t ccs_poly1305_update(
    ccs_poly1305_ctx_t* ctx,
    size_t in_len,
    const uint8_t* in
);

/**
 * @brief Finalize an incremental Poly1305 computation.
 *
 * @param ctx The initialized Poly1305 context. Context is zeroed after use and must be re-initialized.
 * @param digest [CCS_POLY1305_LEN] The digest output buffer.
 * @return CCS_OK on success.
 */
ccs_res_t ccs_poly1305_final(
    ccs_poly1305_ctx_t* ctx,
    ccs_poly1305_digest_t digest
);

/**
 * @brief Verify two Poly1305 digests in constant time.
 *
 * @param expected [CCS_POLY1305_LEN] The expected Poly1305 digest.
 * @param actual [CCS_POLY1305_LEN] The Poly1305 digest to verify.
 * @return CCS_OK if both digests match or CCS_VERIFICATION_FAILED otherwise.
 */
ccs_res_t ccs_poly1305_verify(
    const ccs_poly1305_digest_t expected,
    const ccs_poly1305_digest_t actual
);
#endif // CCS_POLY

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // CCS_POLY1305_H
