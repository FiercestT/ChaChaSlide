/**
 * @file test_poly1305.c
 * @copyright Copyright (c) 2026 FiercestT
 * @brief Poly1305 vectors and incremental API tests.
 */

#include "ccs_poly1305.h"
#include "test.h"

#if CCS_POLY
static const ccs_poly1305_key_t rfc_key = {
    0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33,
    0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8,
    0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd,
    0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b
};
static const uint8_t rfc_text[] = "Cryptographic Forum Research Group";

static void test_rfc_vector(void) {
    // RFC 8439, section 2.5.2.
    ccs_poly1305_ctx_t ctx;
    uint8_t out[18];

    memset(&ctx, 0xa5, sizeof(ctx));
    memset(out, 0xa5, sizeof(out));
    assert(ccs_poly1305_init(&ctx, rfc_key) == CCS_OK);
    assert(ccs_poly1305_update(&ctx, sizeof(rfc_text) - 1, rfc_text) == CCS_OK);
    assert(ccs_poly1305_final(&ctx, out + 1) == CCS_OK);
    test_hex(16, out + 1, "a8061dc1305136c6c22b8baf0c0127a9");
    assert(out[0] == 0xa5 && out[17] == 0xa5);
    test_fill(sizeof(ctx), &ctx, 0);
}

static void test_empty(void) {
    ccs_poly1305_ctx_t ctx;
    ccs_poly1305_digest_t out;

    assert(ccs_poly1305_init(&ctx, rfc_key) == CCS_OK);
    assert(ccs_poly1305_update(&ctx, 0, NULL) == CCS_OK);
    assert(ccs_poly1305_final(&ctx, out) == CCS_OK);
    assert(memcmp(out, rfc_key + 16, sizeof(out)) == 0);
    test_fill(sizeof(ctx), &ctx, 0);
}

static void test_incremental(void) {
    ccs_poly1305_ctx_t ctx;
    ccs_poly1305_digest_t out;

    for(size_t split = 0; split < sizeof(rfc_text); split++) {
        assert(ccs_poly1305_init(&ctx, rfc_key) == CCS_OK);
        assert(ccs_poly1305_update(&ctx, split, rfc_text) == CCS_OK);
        assert(ccs_poly1305_update(&ctx, 0, NULL) == CCS_OK);
        assert(ccs_poly1305_update(&ctx, sizeof(rfc_text) - 1 - split, rfc_text + split) == CCS_OK);
        assert(ccs_poly1305_final(&ctx, out) == CCS_OK);
        test_hex(sizeof(out), out, "a8061dc1305136c6c22b8baf0c0127a9");
    }
    assert(ccs_poly1305_init(&ctx, rfc_key) == CCS_OK);
    for(size_t i = 0; i < sizeof(rfc_text) - 1; i++)
        assert(ccs_poly1305_update(&ctx, 1, rfc_text + i) == CCS_OK);
    assert(ccs_poly1305_final(&ctx, out) == CCS_OK);
    test_hex(sizeof(out), out, "a8061dc1305136c6c22b8baf0c0127a9");
}

static void test_zero_key(void) {
    const ccs_poly1305_key_t key = { 0 };
    uint8_t text[65];
    ccs_poly1305_ctx_t ctx;
    ccs_poly1305_digest_t out;

    memset(text, 0xff, sizeof(text));
    for(size_t len = 0; len <= sizeof(text); len++) {
        assert(ccs_poly1305_init(&ctx, key) == CCS_OK);
        assert(ccs_poly1305_update(&ctx, len, text) == CCS_OK);
        assert(ccs_poly1305_final(&ctx, out) == CCS_OK);
        test_fill(sizeof(out), out, 0);
    }
}

static void test_zero_r(void) {
    ccs_poly1305_key_t key = { 0 };
    uint8_t text[65];
    ccs_poly1305_ctx_t ctx;
    ccs_poly1305_digest_t out;

    memcpy(key + 16, rfc_key + 16, 16);
    memset(text, 0xff, sizeof(text));
    for(size_t len = 0; len <= sizeof(text); len++) {
        assert(ccs_poly1305_init(&ctx, key) == CCS_OK);
        assert(ccs_poly1305_update(&ctx, len, text) == CCS_OK);
        assert(ccs_poly1305_final(&ctx, out) == CCS_OK);
        assert(memcmp(out, key + 16, sizeof(out)) == 0);
    }
}

static void test_partial_reduction(void) {
    // RFC 8439, A.3, vector 5.
    const ccs_poly1305_key_t key = { 2 };
    uint8_t text[16];
    ccs_poly1305_ctx_t ctx;
    ccs_poly1305_digest_t out;

    memset(text, 0xff, sizeof(text));
    assert(ccs_poly1305_init(&ctx, key) == CCS_OK);
    assert(ccs_poly1305_update(&ctx, sizeof(text), text) == CCS_OK);
    assert(ccs_poly1305_final(&ctx, out) == CCS_OK);
    test_hex(sizeof(out), out, "03000000000000000000000000000000");
}

static void test_pad_overflow(void) {
    // RFC 8439, A.3, vector 6.
    ccs_poly1305_key_t key = { 2 };
    const uint8_t text[16] = { 2 };
    ccs_poly1305_ctx_t ctx;
    ccs_poly1305_digest_t out;

    memset(key + 16, 0xff, 16);
    assert(ccs_poly1305_init(&ctx, key) == CCS_OK);
    assert(ccs_poly1305_update(&ctx, sizeof(text), text) == CCS_OK);
    assert(ccs_poly1305_final(&ctx, out) == CCS_OK);
    test_hex(sizeof(out), out, "03000000000000000000000000000000");
}

static void test_limb_carry(void) {
    // RFC 8439, A.3, vector 7.
    const ccs_poly1305_key_t key = { 1 };
    uint8_t text[48] = { 0 };
    ccs_poly1305_ctx_t ctx;
    ccs_poly1305_digest_t out;

    memset(text, 0xff, 32);
    text[16] = 0xf0;
    text[32] = 0x11;
    assert(ccs_poly1305_init(&ctx, key) == CCS_OK);
    assert(ccs_poly1305_update(&ctx, sizeof(text), text) == CCS_OK);
    assert(ccs_poly1305_final(&ctx, out) == CCS_OK);
    test_hex(sizeof(out), out, "05000000000000000000000000000000");
}

static void test_exact_modulus(void) {
    // RFC 8439, A.3, vector 8.
    const ccs_poly1305_key_t key = { 1 };
    uint8_t text[48];
    ccs_poly1305_ctx_t ctx;
    ccs_poly1305_digest_t out;

    memset(text, 0xff, 16);
    memset(text + 16, 0xfe, 16);
    memset(text + 32, 1, 16);
    text[16] = 0xfb;
    assert(ccs_poly1305_init(&ctx, key) == CCS_OK);
    assert(ccs_poly1305_update(&ctx, sizeof(text), text) == CCS_OK);
    assert(ccs_poly1305_final(&ctx, out) == CCS_OK);
    test_fill(sizeof(out), out, 0);
}

static void test_below_modulus(void) {
    // RFC 8439, A.3, vector 9.
    const ccs_poly1305_key_t key = { 2 };
    uint8_t text[16];
    ccs_poly1305_ctx_t ctx;
    ccs_poly1305_digest_t out;

    memset(text, 0xff, sizeof(text));
    text[0] = 0xfd;
    assert(ccs_poly1305_init(&ctx, key) == CCS_OK);
    assert(ccs_poly1305_update(&ctx, sizeof(text), text) == CCS_OK);
    assert(ccs_poly1305_final(&ctx, out) == CCS_OK);
    test_hex(sizeof(out), out, "faffffffffffffffffffffffffffffff");
}

static void test_wide_intermediate(void) {
    // RFC 8439, A.3, vector 10.
    const ccs_poly1305_key_t key = { 1, 0, 0, 0, 0, 0, 0, 0, 4 };
    const uint8_t text[64] = {
        0xe3, 0x35, 0x94, 0xd7, 0x50, 0x5e, 0x43, 0xb9, 0, 0, 0, 0, 0, 0, 0, 0,
        0x33, 0x94, 0xd7, 0x50, 0x5e, 0x43, 0x79, 0xcd, 1, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        1
    };
    ccs_poly1305_ctx_t ctx;
    ccs_poly1305_digest_t out;

    assert(ccs_poly1305_init(&ctx, key) == CCS_OK);
    assert(ccs_poly1305_update(&ctx, sizeof(text), text) == CCS_OK);
    assert(ccs_poly1305_final(&ctx, out) == CCS_OK);
    test_hex(sizeof(out), out, "14000000000000005500000000000000");
}

static void test_wide_final(void) {
    // RFC 8439, A.3, vector 11.
    const ccs_poly1305_key_t key = { 1, 0, 0, 0, 0, 0, 0, 0, 4 };
    const uint8_t text[48] = {
        0xe3, 0x35, 0x94, 0xd7, 0x50, 0x5e, 0x43, 0xb9, 0, 0, 0, 0, 0, 0, 0, 0,
        0x33, 0x94, 0xd7, 0x50, 0x5e, 0x43, 0x79, 0xcd, 1
    };
    ccs_poly1305_ctx_t ctx;
    ccs_poly1305_digest_t out;

    assert(ccs_poly1305_init(&ctx, key) == CCS_OK);
    assert(ccs_poly1305_update(&ctx, sizeof(text), text) == CCS_OK);
    assert(ccs_poly1305_final(&ctx, out) == CCS_OK);
    test_hex(sizeof(out), out, "13000000000000000000000000000000");
}

static void test_block_boundaries(void) {
    // All-ones key/message: exercises clamping and long carry chains.
    // Fixed tags checked with Python cryptography Poly1305.
    static const size_t lengths[] = { 1, 15, 16, 17, 31, 32, 33, 255, 256, 257 };
    static const char* const expected[] = {
        "23feffef23f8ffef23f8ffef23f8ffef", "fbff27e6030028e6030028e6030028ee",
        "fbffff17faffff17faffff17faffff17", "7cfe7ff768f81f2763f8bf565df85f86",
        "5400a8ed4800481d4300e84c3d008884", "5400801f3f00204f3900c07e330060ae",
        "86fa6a437bf4ec24a274504dc37495bc", "c80cb43844f387946e5aa6085bdf67da",
        "c30c8c6a3af35fc6645a7e3a51df3f04", "2d5d96b08bcdc7a0a2dd87a44f5222c1"
    };
    ccs_poly1305_key_t key;
    ccs_poly1305_ctx_t ctx;
    ccs_poly1305_digest_t out;
    uint8_t text[258];

    memset(key, 0xff, sizeof(key));
    memset(text, 0xff, sizeof(text));
    for(size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); i++) {
        for(size_t split = 0; split <= lengths[i]; split++) {
            assert(ccs_poly1305_init(&ctx, key) == CCS_OK);
            assert(ccs_poly1305_update(&ctx, split, text + 1) == CCS_OK);
            assert(ccs_poly1305_update(&ctx, 0, NULL) == CCS_OK);
            assert(ccs_poly1305_update(&ctx, lengths[i] - split, text + 1 + split) == CCS_OK);
            assert(ccs_poly1305_final(&ctx, out) == CCS_OK);
            test_hex(sizeof(out), out, expected[i]);
        }
    }
}

static void test_verify(void) {
    ccs_poly1305_digest_t expected, actual;

    for(size_t i = 0; i < sizeof(expected); i++)
        expected[i] = (uint8_t)i;
    memcpy(actual, expected, sizeof(actual));
    assert(ccs_poly1305_verify(expected, actual) == CCS_OK);
    assert(ccs_poly1305_verify(expected, expected) == CCS_OK);
    for(size_t i = 0; i < sizeof(actual); i++) {
        for(unsigned int bit = 0; bit < 8; bit++) {
            actual[i] ^= (uint8_t)(1u << bit);
            assert(ccs_poly1305_verify(expected, actual) == CCS_VERIFICATION_FAILED);
            actual[i] ^= (uint8_t)(1u << bit);
        }
    }
}
#endif // CCS_POLY

int main(void) {
#if CCS_POLY
    test_rfc_vector();
    test_empty();
    test_incremental();
    test_zero_key();
    test_zero_r();
    test_partial_reduction();
    test_pad_overflow();
    test_limb_carry();
    test_exact_modulus();
    test_below_modulus();
    test_wide_intermediate();
    test_wide_final();
    test_block_boundaries();
    test_verify();
    return 0;
#else
    return 77;
#endif
}
