/**
 * @file test_xchacha.c
 * @copyright Copyright (c) 2026 FiercestT
 * @brief XChaCha stream cipher tests.
 */

#include "ccs_xchacha.h"
#include "test.h"

#if CCS_XCC
static void test_draft_counter_zero(void) {
    // First two keystream blocks, draft-irtf-cfrg-xchacha-03, A.2.1.
    ccs_chacha_key_t key;
    ccs_xchacha_nonce_t nonce;
    uint8_t out[128] = { 0 };

    for(size_t i = 0; i < sizeof(key); i++)
        key[i] = (uint8_t)(0x80 + i);
    for(size_t i = 0; i < sizeof(nonce); i++)
        nonce[i] = (uint8_t)(0x40 + i);
    nonce[23] = 0x58;
    assert(ccs_xchacha20(key, nonce, sizeof(out), out, out) == CCS_OK);
    test_hex(sizeof(out), out,
        "1131ce9a2a20ae0d67c8935c7789fa1025c9e5bb720fb96f11354fb97af0bd9a"
        "adec0863ba60cac8582c48f86cdfc48edd46a48642c5de62ccf11c7b21bf337d"
        "29624b4b1b140ace53740e405b2168540fd7d630c1f536fecd722fc3cddba7f4"
        "cca98cf9e47e5e64d115450f9b125b54449ff76141ca620a1f9cfcab2a1a8a25");
}

static void test_draft_counter_one(void) {
    // draft-irtf-cfrg-xchacha-03, A.3.2.2.
    ccs_chacha_key_t key;
    ccs_xchacha_nonce_t nonce;
    const uint8_t text[] = "The dhole (pronounced \"dole\") is also known as the Asiatic wild "
        "dog, red dog, and whistling dog. It is about the size of a German shepherd but looks "
        "more like a long-legged fox. This highly elusive and skilled jumper is classified "
        "with wolves, coyotes, jackals, and foxes in the taxonomic family Canidae.";
    uint8_t out[sizeof(text) - 1];

    for(size_t i = 0; i < sizeof(key); i++)
        key[i] = (uint8_t)(0x80 + i);
    for(size_t i = 0; i < sizeof(nonce); i++)
        nonce[i] = (uint8_t)(0x40 + i);
    nonce[23] = 0x58;
    assert(ccs_xchachaN(20, 1, key, nonce, sizeof(out), text, out) == CCS_OK);
    test_hex(sizeof(out), out,
        "7d0a2e6b7f7c65a236542630294e063b7ab9b555a5d5149aa21e4ae1e4fbce87"
        "ecc8e08a8b5e350abe622b2ffa617b202cfad72032a3037e76ffdcdc4376ee05"
        "3a190d7e46ca1de04144850381b9cb29f051915386b8a710b8ac4d027b8b050f"
        "7cba5854e028d564e453b8a968824173fc16488b8970cac828f11ae53cabd201"
        "12f87107df24ee6183d2274fe4c8b1485534ef2c5fbc1ec24bfc3663efaa08bc"
        "047d29d25043532db8391a8a3d776bf4372a6955827ccb0cdd4af403a7ce4c63"
        "d595c75a43e045f0cce1f29c8b93bd65afc5974922f214a40b7c402cdb91ae73"
        "c0b63615cdad0480680f16515a7ace9d39236464328a37743ffc28f4ddb324f4"
        "d0f5bbdc270c65b1749a6efff1fbaa09536175ccd29fb9e6057b307320d31683"
        "8a9c71f70b5b5907a66f7ea49aadc409");
    assert(ccs_xchachaN(20, 1, key, nonce, sizeof(out), out, out) == CCS_OK);
    assert(memcmp(out, text, sizeof(out)) == 0);
}

static void test_round_counts(void) {
    const ccs_chacha_key_t key = { 1 };
    const ccs_xchacha_nonce_t nonce = { 2 };
    const uint8_t in[65] = { 3 };
    uint8_t even[65], odd[65];

    for(unsigned int rounds = 2; rounds < 255; rounds += 2) {
        assert(ccs_xchachaN((uint8_t)rounds, 7, key, nonce, sizeof(in), in, even) == CCS_OK);
        assert(ccs_xchachaN((uint8_t)(rounds + 1), 7, key, nonce, sizeof(in), in, odd) == CCS_OK);
        assert(memcmp(even, odd, sizeof(even)) == 0);
    }
    for(uint8_t rounds = 0; rounds < 2; rounds++) {
        memset(odd, 0xa5, sizeof(odd));
        assert(ccs_xchachaN(rounds, 0, key, nonce, sizeof(in), in, odd) == CCS_ERROR);
        test_fill(sizeof(odd), odd, 0xa5);
        assert(ccs_xchachaN(rounds, 0, key, nonce, 0, NULL, NULL) == CCS_ERROR);
    }
}

static void test_lengths_and_in_place(void) {
    const ccs_chacha_key_t key = { 1 };
    const ccs_xchacha_nonce_t nonce = { 2 };
    uint8_t in[258], expected[257], out[259];

    for(size_t i = 0; i < sizeof(in); i++)
        in[i] = (uint8_t)i;
    assert(ccs_xchacha20(key, nonce, sizeof(expected), in + 1, expected) == CCS_OK);
    for(size_t len = 0; len <= sizeof(expected); len++) {
        memset(out, 0xa5, sizeof(out));
        assert(ccs_xchacha20(key, nonce, len, in + 1, out + 1) == CCS_OK);
        assert(memcmp(out + 1, expected, len) == 0);
        assert(out[0] == 0xa5);
        test_fill(sizeof(out) - len - 1, out + len + 1, 0xa5);
        assert(ccs_xchacha20(key, nonce, len, out + 1, out + 1) == CCS_OK);
        assert(memcmp(out + 1, in + 1, len) == 0);
    }
    assert(ccs_xchacha20(key, nonce, 0, NULL, NULL) == CCS_OK);
}

static void test_counter_carry(void) {
    const ccs_chacha_key_t key = { 1 };
    const ccs_xchacha_nonce_t nonce = { 2 };
    const uint8_t in[128] = { 0 };
    uint8_t out[128], next[64], low[64];

    assert(ccs_xchachaN(20, UINT32_MAX, key, nonce, sizeof(in), in, out) == CCS_OK);
    assert(ccs_xchachaN(20, UINT64_C(0x100000000), key, nonce, sizeof(next), in, next) == CCS_OK);
    assert(memcmp(out + 64, next, sizeof(next)) == 0);
    assert(ccs_xchacha20(key, nonce, sizeof(low), in, low) == CCS_OK);
    assert(memcmp(next, low, sizeof(next)) != 0);
}

static void test_counter_limit(void) {
    const ccs_chacha_key_t key = { 0 };
    const ccs_xchacha_nonce_t nonce = { 0 };
    const uint8_t in[129] = { 0 };
    uint8_t out[129], last[64];

    assert(ccs_xchachaN(20, UINT64_MAX, key, nonce, 0, NULL, NULL) == CCS_OK);
    assert(ccs_xchachaN(20, UINT64_MAX, key, nonce, 1, in, out) == CCS_OK);
    assert(ccs_xchachaN(20, UINT64_MAX, key, nonce, 64, in, last) == CCS_OK);
    assert(ccs_xchachaN(20, UINT64_MAX - 1, key, nonce, 128, in, out) == CCS_OK);
    assert(memcmp(out + 64, last, sizeof(last)) == 0);
    memset(out, 0xa5, sizeof(out));
    assert(ccs_xchachaN(20, UINT64_MAX, key, nonce, 65, in, out) == CCS_ERROR);
    test_fill(sizeof(out), out, 0xa5);
    assert(ccs_xchachaN(20, UINT64_MAX - 1, key, nonce, 129, in, out) == CCS_ERROR);
    test_fill(sizeof(out), out, 0xa5);
}
#endif // CCS_XCC

int main(void) {
#if CCS_XCC
    test_draft_counter_zero();
    test_draft_counter_one();
    test_round_counts();
    test_lengths_and_in_place();
    test_counter_carry();
    test_counter_limit();
    return 0;
#else
    return 77;
#endif
}
