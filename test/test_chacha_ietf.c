/**
 * @file test_chacha_ietf.c
 * @copyright Copyright (c) 2026 FiercestT
 * @brief IETF ChaCha tests.
 */

#include "ccs_chacha.h"
#include "test.h"

#if CCS_CC_IETF
static void test_rfc_block(void) {
    // RFC 8439, section 2.3.2.
    ccs_chacha_key_t key;
    const ccs_chacha_ietf_nonce_t nonce = { 0, 0, 0, 9, 0, 0, 0, 0x4a, 0, 0, 0, 0 };
    uint8_t out[64] = { 0 };

    for(size_t i = 0; i < sizeof(key); i++)
        key[i] = (uint8_t)i;
    assert(ccs_chachaN_ietf(20, 1, key, nonce, sizeof(out), out, out) == CCS_OK);
    test_hex(sizeof(out), out,
        "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e"
        "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e");
}

static void test_rfc_encrypt(void) {
    // RFC 8439, section 2.4.2. Includes a partial second block.
    ccs_chacha_key_t key;
    const ccs_chacha_ietf_nonce_t nonce = { 0, 0, 0, 0, 0, 0, 0, 0x4a, 0, 0, 0, 0 };
    const uint8_t text[] = "Ladies and Gentlemen of the class of '99: If I could offer you "
        "only one tip for the future, sunscreen would be it.";
    uint8_t out[sizeof(text) - 1];

    for(size_t i = 0; i < sizeof(key); i++)
        key[i] = (uint8_t)i;
    assert(ccs_chachaN_ietf(20, 1, key, nonce, sizeof(out), text, out) == CCS_OK);
    test_hex(sizeof(out), out,
        "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b"
        "f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8"
        "07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736"
        "5af90bbf74a35be6b40b8eedf2785e42874d");
    assert(ccs_chachaN_ietf(20, 1, key, nonce, sizeof(out), out, out) == CCS_OK);
    assert(memcmp(out, text, sizeof(out)) == 0);
}

static void test_zero_vector(void) {
    const ccs_chacha_key_t key = { 0 };
    const ccs_chacha_ietf_nonce_t nonce = { 0 };
    uint8_t out[64] = { 0 };

    assert(ccs_chacha20_ietf(key, nonce, sizeof(out), out, out) == CCS_OK);
    test_hex(sizeof(out), out,
        "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7"
        "da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586");
}

static void test_reduced_rounds(void) {
    // ChaCha8/12 all-zero key and nonce vectors (draft-strombergson-chacha-test-vectors).
    const ccs_chacha_key_t key = { 0 };
    const ccs_chacha_ietf_nonce_t nonce = { 0 };
    const uint8_t in[64] = { 0 };
    uint8_t out[64];

    assert(ccs_chachaN_ietf(8, 0, key, nonce, sizeof(in), in, out) == CCS_OK);
    test_hex(sizeof(out), out,
        "3e00ef2f895f40d67f5bb8e81f09a5a12c840ec3ce9a7f3b181be188ef711a1e"
        "984ce172b9216f419f445367456d5619314a42a3da86b001387bfdb80e0cfe42");
    assert(ccs_chachaN_ietf(12, 0, key, nonce, sizeof(in), in, out) == CCS_OK);
    test_hex(sizeof(out), out,
        "9bf49a6a0755f953811fce125f2683d50429c3bb49e074147e0089a52eae155f"
        "0564f879d27ae3c02ce82834acfa8c793a629f2ca0de6919610be82f411326be");
}

static void test_round_counts(void) {
    const ccs_chacha_key_t key = { 1 };
    const ccs_chacha_ietf_nonce_t nonce = { 2 };
    const uint8_t in[65] = { 3 };
    uint8_t even[65], odd[65];

    for(unsigned int rounds = 2; rounds < 255; rounds += 2) {
        assert(ccs_chachaN_ietf((uint8_t)rounds, 7, key, nonce, sizeof(in), in, even) == CCS_OK);
        assert(ccs_chachaN_ietf((uint8_t)(rounds + 1), 7, key, nonce, sizeof(in), in, odd) == CCS_OK);
        assert(memcmp(even, odd, sizeof(even)) == 0);
    }
    for(uint8_t rounds = 0; rounds < 2; rounds++) {
        memset(odd, 0xa5, sizeof(odd));
        assert(ccs_chachaN_ietf(rounds, 0, key, nonce, sizeof(in), in, odd) == CCS_ERROR);
        test_fill(sizeof(odd), odd, 0xa5);
        assert(ccs_chachaN_ietf(rounds, 0, key, nonce, 0, NULL, NULL) == CCS_ERROR);
    }
}

static void test_lengths_and_in_place(void) {
    const ccs_chacha_key_t key = { 1 };
    const ccs_chacha_ietf_nonce_t nonce = { 2 };
    uint8_t in[258], expected[257], out[259];

    for(size_t i = 0; i < sizeof(in); i++)
        in[i] = (uint8_t)i;
    assert(ccs_chacha20_ietf(key, nonce, sizeof(expected), in + 1, expected) == CCS_OK);
    for(size_t len = 0; len <= sizeof(expected); len++) {
        memset(out, 0xa5, sizeof(out));
        assert(ccs_chacha20_ietf(key, nonce, len, in + 1, out + 1) == CCS_OK);
        assert(memcmp(out + 1, expected, len) == 0);
        assert(out[0] == 0xa5);
        test_fill(sizeof(out) - len - 1, out + len + 1, 0xa5);
        assert(ccs_chacha20_ietf(key, nonce, len, out + 1, out + 1) == CCS_OK);
        assert(memcmp(out + 1, in + 1, len) == 0);
    }
    assert(ccs_chacha20_ietf(key, nonce, 0, NULL, NULL) == CCS_OK);
}

static void test_counter_limit(void) {
    const ccs_chacha_key_t key = { 0 };
    const ccs_chacha_ietf_nonce_t nonce = { 0 };
    const uint8_t in[129] = { 0 };
    uint8_t out[129], last[64];

    assert(ccs_chachaN_ietf(20, UINT32_MAX, key, nonce, 0, NULL, NULL) == CCS_OK);
    assert(ccs_chachaN_ietf(20, UINT32_MAX, key, nonce, 1, in, out) == CCS_OK);
    assert(ccs_chachaN_ietf(20, UINT32_MAX, key, nonce, 64, in, last) == CCS_OK);
    assert(ccs_chachaN_ietf(20, UINT32_MAX - 1, key, nonce, 128, in, out) == CCS_OK);
    assert(memcmp(out + 64, last, sizeof(last)) == 0);
    memset(out, 0xa5, sizeof(out));
    assert(ccs_chachaN_ietf(20, UINT32_MAX, key, nonce, 65, in, out) == CCS_ERROR);
    test_fill(sizeof(out), out, 0xa5);
    assert(ccs_chachaN_ietf(20, UINT32_MAX - 1, key, nonce, 129, in, out) == CCS_ERROR);
    test_fill(sizeof(out), out, 0xa5);
}
#endif // CCS_CC_IETF

int main(void) {
#if CCS_CC_IETF
    test_rfc_block();
    test_rfc_encrypt();
    test_zero_vector();
    test_reduced_rounds();
    test_round_counts();
    test_lengths_and_in_place();
    test_counter_limit();
    return 0;
#else
    return 77;
#endif
}
