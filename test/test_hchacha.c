/**
 * @file test_hchacha.c
 * @copyright Copyright (c) 2026 FiercestT
 * @brief HChaCha tests, including its internal use by XChaCha.
 */

#include "ccs_chacha.h"
#include "../src/ccs_internal.h"
#include "test.h"

#if CCS_NEED_HCC
static void test_draft_vector(void) {
    // draft-irtf-cfrg-xchacha-03, section 2.2.1.
    ccs_chacha_key_t key;
    const ccs_hchacha_nonce_t nonce = {
        0, 0, 0, 9, 0, 0, 0, 0x4a, 0, 0, 0, 0, 0x31, 0x41, 0x59, 0x27
    };
    uint8_t out[34];

    for(size_t i = 0; i < sizeof(key); i++)
        key[i] = (uint8_t)i;
    memset(out, 0xa5, sizeof(out));
    assert(ccs_hchachaN(20, key, nonce, out + 1) == CCS_OK);
    test_hex(32, out + 1, "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc");
    assert(out[0] == 0xa5 && out[33] == 0xa5);
#if CCS_HCC
    assert(ccs_hchacha20(key, nonce, out + 1) == CCS_OK);
    test_hex(32, out + 1, "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc");
#endif
}

static void test_round_counts(void) {
    const ccs_chacha_key_t key = { 1 };
    const ccs_hchacha_nonce_t nonce = { 2 };
    uint8_t even[32], odd[32];

    for(unsigned int rounds = 2; rounds < 255; rounds += 2) {
        assert(ccs_hchachaN((uint8_t)rounds, key, nonce, even) == CCS_OK);
        assert(ccs_hchachaN((uint8_t)(rounds + 1), key, nonce, odd) == CCS_OK);
        assert(memcmp(even, odd, sizeof(even)) == 0);
    }
    for(uint8_t rounds = 0; rounds < 2; rounds++) {
        memset(odd, 0xa5, sizeof(odd));
        assert(ccs_hchachaN(rounds, key, nonce, odd) == CCS_ERROR);
        test_fill(sizeof(odd), odd, 0xa5);
    }
}
#endif // CCS_NEED_HCC

int main(void) {
#if CCS_NEED_HCC
    test_draft_vector();
    test_round_counts();
    return 0;
#else
    return 77;
#endif
}
