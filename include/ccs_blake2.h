/**
 * @file ccs_blake2.h
 * @brief BLAKE2s and BLAKE2b hash interfaces.
 * @copyright Copyright (c) 2026 FiercestT
 */

#ifndef CCS_BLAKE2_H
#define CCS_BLAKE2_H

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#include "ccs_config.h"
#if CCS_NEED_B2

#include "ccs_types.h"

#if CCS_B2S
/**
 * @brief Initialize an unkeyed BLAKE2s computation.
 *
 * @param ctx The BLAKE2s context to initialize. Does not need to be zeroed before init.
 * @param digest_len Digest length in bytes, from 1 to CCS_BLAKE2S_LEN.
 * @return CCS_OK on success or CCS_ERROR if digest_len is 0 or greater than CCS_BLAKE2S_LEN.
 */
ccs_res_t ccs_blake2s_init(
    ccs_blake2s_ctx_t* ctx,
    uint8_t digest_len
);

/**
 * @brief Configure the key after BLAKE2s initialization, before update or final.
 *
 * @param ctx The initialized BLAKE2s context.
 * @param key [CCS_BLAKE2S_KEYLEN] The secret key.
 * @return CCS_OK on success.
 */
ccs_res_t ccs_blake2s_config_key(
    ccs_blake2s_ctx_t* ctx,
    const ccs_blake2s_key_t key
);

/**
 * @brief Configure the salt after BLAKE2s initialization, before update or final.
 *
 * @param ctx The initialized BLAKE2s context.
 * @param salt [CCS_BLAKE2S_SALTLEN] The salt.
 * @return CCS_OK on success.
 */
ccs_res_t ccs_blake2s_config_salt(
    ccs_blake2s_ctx_t* ctx,
    const ccs_blake2s_salt_t salt
);

/**
 * @brief Configure personalization after BLAKE2s initialization, before update or final.
 *
 * @param ctx The initialized BLAKE2s context.
 * @param personal [CCS_BLAKE2S_PERSONALLEN] The personalization.
 * @return CCS_OK on success.
 */
ccs_res_t ccs_blake2s_config_personal(
    ccs_blake2s_ctx_t* ctx,
    const ccs_blake2s_personal_t personal
);

/**
 * @brief Add input to an incremental BLAKE2s computation.
 *
 * @param ctx The initialized BLAKE2s context.
 * @param in_len Byte length of the input.
 * @param in [in_len] The input buffer.
 * @return CCS_OK on success.
 */
ccs_res_t ccs_blake2s_update(
    ccs_blake2s_ctx_t* ctx,
    size_t in_len,
    const uint8_t* in
);

/**
 * @brief Finalize an incremental BLAKE2s computation.
 *
 * @param ctx The initialized BLAKE2s context. Context is zeroed after use and must be re-initialized.
 * @param digest [ctx->digest_len] The digest output buffer.
 * @return CCS_OK on success.
 */
ccs_res_t ccs_blake2s_final(
    ccs_blake2s_ctx_t* ctx,
    ccs_blake2s_digest_t digest
);

#endif // CCS_B2S

#if CCS_B2B
/**
 * @brief Initialize an unkeyed BLAKE2b computation.
 *
 * @param ctx The BLAKE2b context to initialize. Does not need to be zeroed before init.
 * @param digest_len Digest length in bytes, from 1 to CCS_BLAKE2B_LEN.
 * @return CCS_OK on success or CCS_ERROR if digest_len is 0 or greater than CCS_BLAKE2B_LEN.
 */
ccs_res_t ccs_blake2b_init(
    ccs_blake2b_ctx_t* ctx,
    uint8_t digest_len
);

/**
 * @brief Configure the key after BLAKE2b initialization, before update or final.
 *
 * @param ctx The initialized BLAKE2b context.
 * @param key [CCS_BLAKE2B_KEYLEN] The secret key.
 * @return CCS_OK on success.
 */
ccs_res_t ccs_blake2b_config_key(
    ccs_blake2b_ctx_t* ctx,
    const ccs_blake2b_key_t key
);

/**
 * @brief Configure the salt after BLAKE2b initialization, before update or final.
 *
 * @param ctx The initialized BLAKE2b context.
 * @param salt [CCS_BLAKE2B_SALTLEN] The salt.
 * @return CCS_OK on success.
 */
ccs_res_t ccs_blake2b_config_salt(
    ccs_blake2b_ctx_t* ctx,
    const ccs_blake2b_salt_t salt
);

/**
 * @brief Configure personalization after BLAKE2b initialization, before update or final.
 *
 * @param ctx The initialized BLAKE2b context.
 * @param personal [CCS_BLAKE2B_PERSONALLEN] The personalization.
 * @return CCS_OK on success.
 */
ccs_res_t ccs_blake2b_config_personal(
    ccs_blake2b_ctx_t* ctx,
    const ccs_blake2b_personal_t personal
);

/**
 * @brief Add input to an incremental BLAKE2b computation.
 *
 * @param ctx The initialized BLAKE2b context.
 * @param in_len Byte length of the input.
 * @param in [in_len] The input buffer.
 * @return CCS_OK on success.
 */
ccs_res_t ccs_blake2b_update(
    ccs_blake2b_ctx_t* ctx,
    size_t in_len,
    const uint8_t* in
);

/**
 * @brief Finalize an incremental BLAKE2b computation.
 *
 * @param ctx The initialized BLAKE2b context. Context is zeroed after use and must be re-initialized.
 * @param digest [ctx->digest_len] The digest output buffer.
 * @return CCS_OK on success.
 */
ccs_res_t ccs_blake2b_final(
    ccs_blake2b_ctx_t* ctx,
    ccs_blake2b_digest_t digest
);

#endif // CCS_B2B

#endif // CCS_NEED_B2

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // CCS_BLAKE2_H
