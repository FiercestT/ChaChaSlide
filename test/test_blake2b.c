/**
 * @file test_blake2b.c
 * @copyright Copyright (c) 2026 FiercestT
 * @brief BLAKE2b tests. Additional vectors checked with Python hashlib.blake2b.
 */

#include "ccs_blake2.h"
#include "test.h"

#if CCS_B2B
static void test_empty(void) {
    ccs_blake2b_ctx_t ctx;
    ccs_blake2b_digest_t out;

    memset(&ctx, 0xa5, sizeof(ctx));
    assert(ccs_blake2b_init(&ctx, sizeof(out)) == CCS_OK);
    assert(ccs_blake2b_update(&ctx, 0, NULL) == CCS_OK);
    assert(ccs_blake2b_final(&ctx, out) == CCS_OK);
    test_hex(sizeof(out), out,
        "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d"
        "25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce");
    test_fill(sizeof(ctx), &ctx, 0);
}

static void test_abc(void) {
    // RFC 7693, appendix A.
    ccs_blake2b_ctx_t ctx;
    ccs_blake2b_digest_t out;
    const uint8_t text[] = "abc";

    assert(ccs_blake2b_init(&ctx, sizeof(out)) == CCS_OK);
    assert(ccs_blake2b_update(&ctx, sizeof(text) - 1, text) == CCS_OK);
    assert(ccs_blake2b_final(&ctx, out) == CCS_OK);
    test_hex(sizeof(out), out,
        "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1"
        "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923");
}

static void test_block_boundaries(void) {
    static const size_t lengths[] = { 127, 128, 129, 257 };
    static const char* const expected[] = {
        "b6292669ccd38d5f01caae96ba272c76a879a45743afa0725d83b9ebb26665b73"
        "1f1848c52f11972b6644f554c064fa90780dbbbf3a89d4fc31f67df3e5857ef",
        "2319e3789c47e2daa5fe807f61bec2a1a6537fa03f19ff32e87eecbfd64b7e0e8"
        "ccff439ac333b040f19b0c4ddd11a61e24ac1fe0f10a039806c5dcc0da3d115",
        "f59711d44a031d5f97a9413c065d1e614c417ede998590325f49bad2fd444d3e4"
        "418be19aec4e11449ac1a57207898bc57d76a1bcf3566292c20c683a5c4648f",
        "d8bfe068de0b4f9fa876a3f8024eb9f7b0029fd5dcf251199e065cee89e1a282"
        "c8dbf0442f2ade7294ac1c6be19b388dc990c34d8cb79f5f10c54fa813834fda"
    };
    uint8_t text[258], out[66];
    ccs_blake2b_ctx_t ctx;

    for(size_t i = 1; i < sizeof(text); i++)
        text[i] = (uint8_t)(i - 1);
    for(size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); i++) {
        memset(out, 0xa5, sizeof(out));
        assert(ccs_blake2b_init(&ctx, 64) == CCS_OK);
        assert(ccs_blake2b_update(&ctx, lengths[i], text + 1) == CCS_OK);
        assert(ccs_blake2b_final(&ctx, out + 1) == CCS_OK);
        test_hex(64, out + 1, expected[i]);
        assert(out[0] == 0xa5 && out[65] == 0xa5);
    }
}

static void test_incremental(void) {
    uint8_t text[257];
    ccs_blake2b_ctx_t ctx;
    ccs_blake2b_digest_t out;

    for(size_t i = 0; i < sizeof(text); i++)
        text[i] = (uint8_t)i;
    for(size_t split = 0; split <= sizeof(text); split++) {
        assert(ccs_blake2b_init(&ctx, sizeof(out)) == CCS_OK);
        assert(ccs_blake2b_update(&ctx, split, text) == CCS_OK);
        assert(ccs_blake2b_update(&ctx, 0, NULL) == CCS_OK);
        assert(ccs_blake2b_update(&ctx, sizeof(text) - split, text + split) == CCS_OK);
        assert(ccs_blake2b_final(&ctx, out) == CCS_OK);
        test_hex(sizeof(out), out,
            "d8bfe068de0b4f9fa876a3f8024eb9f7b0029fd5dcf251199e065cee89e1a282"
            "c8dbf0442f2ade7294ac1c6be19b388dc990c34d8cb79f5f10c54fa813834fda");
    }
    assert(ccs_blake2b_init(&ctx, sizeof(out)) == CCS_OK);
    for(size_t i = 0; i < sizeof(text); i++)
        assert(ccs_blake2b_update(&ctx, 1, text + i) == CCS_OK);
    assert(ccs_blake2b_final(&ctx, out) == CCS_OK);
    test_hex(sizeof(out), out,
        "d8bfe068de0b4f9fa876a3f8024eb9f7b0029fd5dcf251199e065cee89e1a282"
        "c8dbf0442f2ade7294ac1c6be19b388dc990c34d8cb79f5f10c54fa813834fda");
}

static void test_keyed_empty(void) {
    // BLAKE2 reference KAT: key = 00..3f, empty message.
    ccs_blake2b_key_t key;
    ccs_blake2b_ctx_t ctx;
    ccs_blake2b_digest_t out;

    for(size_t i = 0; i < sizeof(key); i++)
        key[i] = (uint8_t)i;
    memset(&ctx, 0xa5, sizeof(ctx));
    assert(ccs_blake2b_init(&ctx, sizeof(out)) == CCS_OK);
    assert(ccs_blake2b_config_key(&ctx, key) == CCS_OK);
    assert(ccs_blake2b_update(&ctx, 0, NULL) == CCS_OK);
    assert(ccs_blake2b_final(&ctx, out) == CCS_OK);
    test_hex(sizeof(out), out,
        "10ebb67700b1868efb4417987acf4690ae9d972fb7a590c2f02871799aaa4786b"
        "5e996e8f0f4eb981fc214b005f42d2ff4233499391653df7aefcbc13fc51568");
    test_fill(sizeof(ctx), &ctx, 0);
}

static void test_keyed_incremental(void) {
    ccs_blake2b_key_t key;
    ccs_blake2b_ctx_t ctx;
    ccs_blake2b_digest_t out;
    uint8_t text[257];

    for(size_t i = 0; i < sizeof(key); i++)
        key[i] = (uint8_t)i;
    for(size_t i = 0; i < sizeof(text); i++)
        text[i] = (uint8_t)i;
    for(size_t split = 0; split <= sizeof(text); split++) {
        assert(ccs_blake2b_init(&ctx, sizeof(out)) == CCS_OK);
        assert(ccs_blake2b_config_key(&ctx, key) == CCS_OK);
        assert(ccs_blake2b_update(&ctx, split, text) == CCS_OK);
        assert(ccs_blake2b_update(&ctx, sizeof(text) - split, text + split) == CCS_OK);
        assert(ccs_blake2b_final(&ctx, out) == CCS_OK);
        test_hex(sizeof(out), out,
            "3a9e68b5a91ccd5de231647907c427b82dcbeaaca7077a71474516d44a6c96a2"
            "30590534bd9f3bafa8143f8be67b3abce7b6405329664c47c0c22f5f53ac1369");
    }
}

static void test_digest_lengths(void) {
    static const uint8_t lengths[] = { 1, 17, 63 };
    static const char* const expected[] = {
        "6b", "658fb5b767c736b82b1a7fa7050454344c",
        "eb5324bb0b0f9ca27381f22f5e49604d7c341b77371fe5bf61fb643c8ab481c7"
        "555ef17c9b9e7c92f0daafff6c0d748cab97d2b267bf53f8225c173ea26f3e"
    };
    ccs_blake2b_ctx_t ctx;
    uint8_t out[66];

    for(size_t i = 0; i < sizeof(lengths); i++) {
        memset(out, 0xa5, sizeof(out));
        assert(ccs_blake2b_init(&ctx, lengths[i]) == CCS_OK);
        assert(ccs_blake2b_update(&ctx, 3, (const uint8_t*)"abc") == CCS_OK);
        assert(ccs_blake2b_final(&ctx, out + 1) == CCS_OK);
        test_hex(lengths[i], out + 1, expected[i]);
        assert(out[0] == 0xa5);
        test_fill(sizeof(out) - lengths[i] - 1, out + lengths[i] + 1, 0xa5);
    }
}

static void test_invalid_digest_lengths(void) {
    ccs_blake2b_ctx_t ctx;

    memset(&ctx, 0xa5, sizeof(ctx));
    assert(ccs_blake2b_init(&ctx, 0) == CCS_ERROR);
    test_fill(sizeof(ctx), &ctx, 0xa5);
    for(unsigned int len = 65; len <= 255; len++) {
        assert(ccs_blake2b_init(&ctx, (uint8_t)len) == CCS_ERROR);
        test_fill(sizeof(ctx), &ctx, 0xa5);
    }
}

static void test_salt(void) {
    const ccs_blake2b_salt_t salt = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    ccs_blake2b_ctx_t ctx;
    ccs_blake2b_digest_t out;

    assert(ccs_blake2b_init(&ctx, sizeof(out)) == CCS_OK);
    assert(ccs_blake2b_config_salt(&ctx, salt) == CCS_OK);
    assert(ccs_blake2b_update(&ctx, 3, (const uint8_t*)"abc") == CCS_OK);
    assert(ccs_blake2b_final(&ctx, out) == CCS_OK);
    test_hex(sizeof(out), out,
        "026d34896f691fd4e5577618f5a71193cb3ed1c9df63ba2c68cf6513f0d6e831"
        "1d3832d94f4fd1ade2936f087405efaf91069ddb89230f80a5958106e74c86c8");
}

static void test_personal(void) {
    const ccs_blake2b_personal_t personal = { 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31 };
    ccs_blake2b_ctx_t ctx;
    ccs_blake2b_digest_t out;

    assert(ccs_blake2b_init(&ctx, sizeof(out)) == CCS_OK);
    assert(ccs_blake2b_config_personal(&ctx, personal) == CCS_OK);
    assert(ccs_blake2b_update(&ctx, 3, (const uint8_t*)"abc") == CCS_OK);
    assert(ccs_blake2b_final(&ctx, out) == CCS_OK);
    test_hex(sizeof(out), out,
        "986fe4800270fec2aea05fe329a247f116512df049846d05a50bb7a79dc432cec"
        "957b2dbe269aadfefddd08a781ae44ad97323aad20b0f70ff6b3fb884c32d3a");
}

static void test_combined_parameters(void) {
    const ccs_blake2b_salt_t salt = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    const ccs_blake2b_personal_t personal = { 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31 };
    ccs_blake2b_key_t key;
    ccs_blake2b_ctx_t ctx;
    ccs_blake2b_digest_t out;

    for(size_t i = 0; i < sizeof(key); i++)
        key[i] = (uint8_t)i;
    assert(ccs_blake2b_init(&ctx, 17) == CCS_OK);
    assert(ccs_blake2b_config_key(&ctx, key) == CCS_OK);
    assert(ccs_blake2b_config_salt(&ctx, salt) == CCS_OK);
    assert(ccs_blake2b_config_personal(&ctx, personal) == CCS_OK);
    assert(ccs_blake2b_update(&ctx, 3, (const uint8_t*)"abc") == CCS_OK);
    assert(ccs_blake2b_final(&ctx, out) == CCS_OK);
    test_hex(17, out, "a660b0a5bb5e2a7a87693424f7d92b9d04");
    test_fill(sizeof(ctx), &ctx, 0);
}
#endif // CCS_B2B

int main(void) {
#if CCS_B2B
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
