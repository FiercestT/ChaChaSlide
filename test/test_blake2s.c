/**
 * @file test_blake2s.c
 * @brief BLAKE2s tests. Additional vectors checked with Python hashlib.blake2s.
 * @copyright Copyright (c) 2026 FiercestT
 */

#include "ccs_blake2.h"
#include "test.h"

#if CCS_B2S
static void test_empty(void) {
    ccs_blake2s_ctx_t ctx;
    ccs_blake2s_digest_t out;

    memset(&ctx, 0xa5, sizeof(ctx));
    assert(ccs_blake2s_init(&ctx, sizeof(out)) == CCS_OK);
    assert(ccs_blake2s_update(&ctx, 0, NULL) == CCS_OK);
    assert(ccs_blake2s_final(&ctx, out) == CCS_OK);
    test_hex(sizeof(out), out, "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9");
    test_fill(sizeof(ctx), &ctx, 0);
}

static void test_abc(void) {
    // RFC 7693, appendix B.
    ccs_blake2s_ctx_t ctx;
    ccs_blake2s_digest_t out;
    const uint8_t text[] = "abc";

    assert(ccs_blake2s_init(&ctx, sizeof(out)) == CCS_OK);
    assert(ccs_blake2s_update(&ctx, sizeof(text) - 1, text) == CCS_OK);
    assert(ccs_blake2s_final(&ctx, out) == CCS_OK);
    test_hex(sizeof(out), out, "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982");
}

static void test_block_boundaries(void) {
    static const size_t lengths[] = { 63, 64, 65, 257 };
    static const char* const expected[] = {
        "e57cb79487dd57902432b250733813bd96a84efce59f650fac26e6696aefafc3",
        "56f34e8b96557e90c1f24b52d0c89d51086acf1b00f634cf1dde9233b8eaaa3e",
        "1b53ee94aaf34e4b159d48de352c7f0661d0a40edff95a0b1639b4090e974472",
        "7795ecf74355f1bdc9ee5818c357081b6a51b8dd801be35b1a872391014edeae"
    };
    uint8_t text[258], out[34];
    ccs_blake2s_ctx_t ctx;

    for(size_t i = 1; i < sizeof(text); i++)
        text[i] = (uint8_t)(i - 1);
    for(size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); i++) {
        memset(out, 0xa5, sizeof(out));
        assert(ccs_blake2s_init(&ctx, 32) == CCS_OK);
        assert(ccs_blake2s_update(&ctx, lengths[i], text + 1) == CCS_OK);
        assert(ccs_blake2s_final(&ctx, out + 1) == CCS_OK);
        test_hex(32, out + 1, expected[i]);
        assert(out[0] == 0xa5 && out[33] == 0xa5);
    }
}

static void test_incremental(void) {
    uint8_t text[257];
    ccs_blake2s_ctx_t ctx;
    ccs_blake2s_digest_t out;

    for(size_t i = 0; i < sizeof(text); i++)
        text[i] = (uint8_t)i;
    for(size_t split = 0; split <= sizeof(text); split++) {
        assert(ccs_blake2s_init(&ctx, sizeof(out)) == CCS_OK);
        assert(ccs_blake2s_update(&ctx, split, text) == CCS_OK);
        assert(ccs_blake2s_update(&ctx, 0, NULL) == CCS_OK);
        assert(ccs_blake2s_update(&ctx, sizeof(text) - split, text + split) == CCS_OK);
        assert(ccs_blake2s_final(&ctx, out) == CCS_OK);
        test_hex(sizeof(out), out, "7795ecf74355f1bdc9ee5818c357081b6a51b8dd801be35b1a872391014edeae");
    }
    assert(ccs_blake2s_init(&ctx, sizeof(out)) == CCS_OK);
    for(size_t i = 0; i < sizeof(text); i++)
        assert(ccs_blake2s_update(&ctx, 1, text + i) == CCS_OK);
    assert(ccs_blake2s_final(&ctx, out) == CCS_OK);
    test_hex(sizeof(out), out, "7795ecf74355f1bdc9ee5818c357081b6a51b8dd801be35b1a872391014edeae");
}

static void test_keyed_empty(void) {
    // BLAKE2 reference KAT: key = 00..1f, empty message.
    ccs_blake2s_key_t key;
    ccs_blake2s_ctx_t ctx;
    ccs_blake2s_digest_t out;

    for(size_t i = 0; i < sizeof(key); i++)
        key[i] = (uint8_t)i;
    memset(&ctx, 0xa5, sizeof(ctx));
    assert(ccs_blake2s_init(&ctx, sizeof(out)) == CCS_OK);
    assert(ccs_blake2s_config_key(&ctx, key) == CCS_OK);
    assert(ccs_blake2s_update(&ctx, 0, NULL) == CCS_OK);
    assert(ccs_blake2s_final(&ctx, out) == CCS_OK);
    test_hex(sizeof(out), out, "48a8997da407876b3d79c0d92325ad3b89cbb754d86ab71aee047ad345fd2c49");
    test_fill(sizeof(ctx), &ctx, 0);
}

static void test_keyed_incremental(void) {
    ccs_blake2s_key_t key;
    ccs_blake2s_ctx_t ctx;
    ccs_blake2s_digest_t out;
    uint8_t text[257];

    for(size_t i = 0; i < sizeof(key); i++)
        key[i] = (uint8_t)i;
    for(size_t i = 0; i < sizeof(text); i++)
        text[i] = (uint8_t)i;
    for(size_t split = 0; split <= sizeof(text); split++) {
        assert(ccs_blake2s_init(&ctx, sizeof(out)) == CCS_OK);
        assert(ccs_blake2s_config_key(&ctx, key) == CCS_OK);
        assert(ccs_blake2s_update(&ctx, split, text) == CCS_OK);
        assert(ccs_blake2s_update(&ctx, sizeof(text) - split, text + split) == CCS_OK);
        assert(ccs_blake2s_final(&ctx, out) == CCS_OK);
        test_hex(sizeof(out), out, "05d9a0be639d012180018bbd1f27b817da6edfd93649748bb688f2228290f0de");
    }
}

static void test_digest_lengths(void) {
    static const uint8_t lengths[] = { 1, 17, 31 };
    static const char* const expected[] = {
        "0d", "e8e884d3c0651b3dfbd4e212d16df1f512",
        "6ffb901930ebaf1d3cabe0b60c20de3bc9dd26269325629f1671304fe6bb26"
    };
    ccs_blake2s_ctx_t ctx;
    uint8_t out[34];

    for(size_t i = 0; i < sizeof(lengths); i++) {
        memset(out, 0xa5, sizeof(out));
        assert(ccs_blake2s_init(&ctx, lengths[i]) == CCS_OK);
        assert(ccs_blake2s_update(&ctx, 3, (const uint8_t*)"abc") == CCS_OK);
        assert(ccs_blake2s_final(&ctx, out + 1) == CCS_OK);
        test_hex(lengths[i], out + 1, expected[i]);
        assert(out[0] == 0xa5);
        test_fill(sizeof(out) - lengths[i] - 1, out + lengths[i] + 1, 0xa5);
    }
}

static void test_invalid_digest_lengths(void) {
    ccs_blake2s_ctx_t ctx;

    memset(&ctx, 0xa5, sizeof(ctx));
    assert(ccs_blake2s_init(&ctx, 0) == CCS_ERROR);
    test_fill(sizeof(ctx), &ctx, 0xa5);
    for(unsigned int len = 33; len <= 255; len++) {
        assert(ccs_blake2s_init(&ctx, (uint8_t)len) == CCS_ERROR);
        test_fill(sizeof(ctx), &ctx, 0xa5);
    }
}

static void test_salt(void) {
    const ccs_blake2s_salt_t salt = { 0, 1, 2, 3, 4, 5, 6, 7 };
    ccs_blake2s_ctx_t ctx;
    ccs_blake2s_digest_t out;

    assert(ccs_blake2s_init(&ctx, sizeof(out)) == CCS_OK);
    assert(ccs_blake2s_config_salt(&ctx, salt) == CCS_OK);
    assert(ccs_blake2s_update(&ctx, 3, (const uint8_t*)"abc") == CCS_OK);
    assert(ccs_blake2s_final(&ctx, out) == CCS_OK);
    test_hex(sizeof(out), out, "e97f81d103fc42502e198ec52dc5c10749b642c48655c1b453e2fcd2ff62ee2f");
}

static void test_personal(void) {
    const ccs_blake2s_personal_t personal = { 16, 17, 18, 19, 20, 21, 22, 23 };
    ccs_blake2s_ctx_t ctx;
    ccs_blake2s_digest_t out;

    assert(ccs_blake2s_init(&ctx, sizeof(out)) == CCS_OK);
    assert(ccs_blake2s_config_personal(&ctx, personal) == CCS_OK);
    assert(ccs_blake2s_update(&ctx, 3, (const uint8_t*)"abc") == CCS_OK);
    assert(ccs_blake2s_final(&ctx, out) == CCS_OK);
    test_hex(sizeof(out), out, "0409f98771cbd4333c78d6e2a5f559dce04517c7ec0033c43271a63e4db27256");
}

static void test_combined_parameters(void) {
    const ccs_blake2s_salt_t salt = { 0, 1, 2, 3, 4, 5, 6, 7 };
    const ccs_blake2s_personal_t personal = { 16, 17, 18, 19, 20, 21, 22, 23 };
    ccs_blake2s_key_t key;
    ccs_blake2s_ctx_t ctx;
    ccs_blake2s_digest_t out;

    for(size_t i = 0; i < sizeof(key); i++)
        key[i] = (uint8_t)i;
    assert(ccs_blake2s_init(&ctx, 17) == CCS_OK);
    assert(ccs_blake2s_config_key(&ctx, key) == CCS_OK);
    assert(ccs_blake2s_config_salt(&ctx, salt) == CCS_OK);
    assert(ccs_blake2s_config_personal(&ctx, personal) == CCS_OK);
    assert(ccs_blake2s_update(&ctx, 3, (const uint8_t*)"abc") == CCS_OK);
    assert(ccs_blake2s_final(&ctx, out) == CCS_OK);
    test_hex(17, out, "fa456cb12e01dd990ba2124e66a9fdbd9c");
    test_fill(sizeof(ctx), &ctx, 0);
}
#endif // CCS_B2S

int main(void) {
#if CCS_B2S
    test_empty();
    test_abc();
    test_block_boundaries();
    test_incremental();
    test_keyed_empty();
    test_keyed_incremental();
    test_digest_lengths();
    test_invalid_digest_lengths();
    test_salt();
    test_personal();
    test_combined_parameters();
    return 0;
#else
    return 77;
#endif
}
