/**
 * @file ccs_xchacha.c
 * @brief XChaCha stream cipher implementation.
 * @copyright Copyright (c) 2026 FiercestT
 */

#include "ccs_xchacha.h"
#include "ccs_internal.h"
#include "ccs_util.h"

#if CCS_NEED_XCC
ccs_res_t ccs_xchachaN(
    uint8_t rounds,
    uint64_t ctr,
    const ccs_chacha_key_t key,
    const ccs_xchacha_nonce_t nonce,
    size_t in_len,
    const uint8_t* in,
    uint8_t* out
) {
    if(rounds < 2)
        return CCS_ERROR;

    if(in_len != 0 && (in_len - 1) / CCS_CHACHA_BLOCKLEN > UINT64_MAX - ctr)
        return CCS_ERROR;

    ccs_chacha_key_t subkey;
    ccs_hchachaN(rounds, key, nonce, subkey);
    ccs_chachaN_djb(rounds, ctr, subkey, &nonce[16], in_len, in, out);

    ccs_util_memzero(sizeof(subkey), subkey);

    return CCS_OK;
}

#endif // CCS_NEED_XCC
