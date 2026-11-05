/**
 * @file test_chacha_poly1305_ietf.c
 * @copyright Copyright (c) 2026 FiercestT
 * @brief IETF ChaCha-Poly1305 tests.
 */

#include "ccs_chacha_poly1305.h"
#include "test.h"

#if CCS_CCP_IETF
// RFC 8439, section 2.8.2.
static const ccs_chacha_key_t key = {
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
    0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
    0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f
};
static const ccs_chacha_ietf_nonce_t nonce = { 7, 0, 0, 0, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47 };
static const uint8_t ad[] = { 0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7 };
static const uint8_t text[] = "Ladies and Gentlemen of the class of '99: If I could offer you "
    "only one tip for the future, sunscreen would be it.";

static void test_rfc_vector(void) {
    uint8_t out[sizeof(text) - 1], plain[sizeof(text) - 1];
    ccs_poly1305_digest_t tag;

    assert(ccs_chacha20_poly1305_ietf_encrypt(key, nonce, sizeof(out), text, sizeof(ad), ad, out, tag) == CCS_OK);
    test_hex(sizeof(out), out,
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
        "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
        "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
        "3ff4def08e4b7a9de576d26586cec64b6116");
    test_hex(sizeof(tag), tag, "1ae10b594f09e26a7e902ecbd0600691");
    assert(ccs_chacha20_poly1305_ietf_decrypt(key, nonce, tag, sizeof(out), out, sizeof(ad), ad, plain) == CCS_OK);
    assert(memcmp(plain, text, sizeof(plain)) == 0);
}

static void test_empty(void) {
    ccs_poly1305_digest_t tag;

    // Independently checked with Python cryptography ChaCha20Poly1305.
    assert(ccs_chacha20_poly1305_ietf_encrypt(key, nonce, 0, NULL, 0, NULL, NULL, tag) == CCS_OK);
    test_hex(sizeof(tag), tag, "a0784d7a4716f3feb4f64e7f4b39bf04");
    assert(ccs_chacha20_poly1305_ietf_decrypt(key, nonce, tag, 0, NULL, 0, NULL, NULL) == CCS_OK);
    tag[0] ^= 1;
    assert(ccs_chacha20_poly1305_ietf_decrypt(key, nonce, tag, 0, NULL, 0, NULL, NULL) == CCS_VERIFICATION_FAILED);
}

static void test_lengths_and_in_place(void) {
    static const size_t lengths[] = { 0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129 };
    uint8_t input[130], auth[130], out[131], inplace[131];
    ccs_poly1305_digest_t tag, inplace_tag;

    for(size_t i = 0; i < sizeof(input); i++) {
        input[i] = (uint8_t)i;
        auth[i] = (uint8_t)(255 - i);
    }
    for(size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); i++) {
        for(size_t j = 0; j < sizeof(lengths) / sizeof(lengths[0]); j++) {
            const size_t len = lengths[i], ad_len = lengths[j];
            const uint8_t* in = len ? input + 1 : NULL;
            const uint8_t* aad = ad_len ? auth + 1 : NULL;
            memset(out, 0xa5, sizeof(out));
            memset(inplace, 0xa5, sizeof(inplace));
            memcpy(inplace + 1, input + 1, len);
            assert(ccs_chacha20_poly1305_ietf_encrypt(key, nonce, len, in, ad_len, aad, out + 1, tag) == CCS_OK);
            assert(ccs_chacha20_poly1305_ietf_encrypt(key, nonce, len, inplace + 1, ad_len, aad, inplace + 1, inplace_tag) == CCS_OK);
            assert(memcmp(out, inplace, sizeof(out)) == 0);
            assert(memcmp(tag, inplace_tag, sizeof(tag)) == 0);
            assert(out[0] == 0xa5);
            test_fill(sizeof(out) - len - 1, out + len + 1, 0xa5);
            assert(ccs_chacha20_poly1305_ietf_decrypt(key, nonce, tag, len, inplace + 1, ad_len, aad, inplace + 1) == CCS_OK);
            assert(memcmp(inplace + 1, input + 1, len) == 0);
            assert(inplace[0] == 0xa5);
            test_fill(sizeof(inplace) - len - 1, inplace + len + 1, 0xa5);
        }
    }
}

static void test_bad_tag(void) {
    uint8_t out[sizeof(text) - 1], plain[sizeof(out)], saved[sizeof(out)];
    ccs_poly1305_digest_t tag;

    assert(ccs_chacha20_poly1305_ietf_encrypt(key, nonce, sizeof(out), text, sizeof(ad), ad, out, tag) == CCS_OK);
    memcpy(saved, out, sizeof(out));
    for(size_t i = 0; i < sizeof(tag); i++) {
        for(unsigned int bit = 0; bit < 8; bit++) {
            tag[i] ^= (uint8_t)(1u << bit);
            memset(plain, 0xa5, sizeof(plain));
            assert(ccs_chacha20_poly1305_ietf_decrypt(key, nonce, tag, sizeof(out), out, sizeof(ad), ad, plain) == CCS_VERIFICATION_FAILED);
            test_fill(sizeof(plain), plain, 0xa5);
            assert(ccs_chacha20_poly1305_ietf_decrypt(key, nonce, tag, sizeof(out), out, sizeof(ad), ad, out) == CCS_VERIFICATION_FAILED);
            assert(memcmp(out, saved, sizeof(out)) == 0);
            tag[i] ^= (uint8_t)(1u << bit);
        }
    }
}

static void test_bad_ciphertext(void) {
    uint8_t out[sizeof(text) - 1], plain[sizeof(out)];
    ccs_poly1305_digest_t tag;

    assert(ccs_chacha20_poly1305_ietf_encrypt(key, nonce, sizeof(out), text, sizeof(ad), ad, out, tag) == CCS_OK);
    memset(plain, 0xa5, sizeof(plain));
    for(size_t i = 0; i < sizeof(out); i++) {
        out[i] ^= 1;
        assert(ccs_chacha20_poly1305_ietf_decrypt(key, nonce, tag, sizeof(out), out, sizeof(ad), ad, plain) == CCS_VERIFICATION_FAILED);
        test_fill(sizeof(plain), plain, 0xa5);
        out[i] ^= 1;
    }
    assert(ccs_chacha20_poly1305_ietf_decrypt(key, nonce, tag, sizeof(out) - 1, out, sizeof(ad), ad, plain) == CCS_VERIFICATION_FAILED);
    test_fill(sizeof(plain), plain, 0xa5);
}

static void test_bad_ad(void) {
    uint8_t out[sizeof(text) - 1], plain[sizeof(out)], changed[sizeof(ad)];
    ccs_poly1305_digest_t tag;

    assert(ccs_chacha20_poly1305_ietf_encrypt(key, nonce, sizeof(out), text, sizeof(ad), ad, out, tag) == CCS_OK);
    memcpy(changed, ad, sizeof(ad));
    memset(plain, 0xa5, sizeof(plain));
    for(size_t i = 0; i < sizeof(changed); i++) {
        changed[i] ^= 1;
        assert(ccs_chacha20_poly1305_ietf_decrypt(key, nonce, tag, sizeof(out), out, sizeof(changed), changed, plain) == CCS_VERIFICATION_FAILED);
        test_fill(sizeof(plain), plain, 0xa5);
        changed[i] ^= 1;
    }
    assert(ccs_chacha20_poly1305_ietf_decrypt(key, nonce, tag, sizeof(out), out, sizeof(ad) - 1, ad, plain) == CCS_VERIFICATION_FAILED);
    test_fill(sizeof(plain), plain, 0xa5);
}

static void test_bad_key(void) {
    uint8_t out[sizeof(text) - 1], plain[sizeof(out)];
    ccs_chacha_key_t changed;
    ccs_poly1305_digest_t tag;

    assert(ccs_chacha20_poly1305_ietf_encrypt(key, nonce, sizeof(out), text, sizeof(ad), ad, out, tag) == CCS_OK);
    memcpy(changed, key, sizeof(key));
    memset(plain, 0xa5, sizeof(plain));
    for(size_t i = 0; i < sizeof(changed); i++) {
        changed[i] ^= 1;
        assert(ccs_chacha20_poly1305_ietf_decrypt(changed, nonce, tag, sizeof(out), out, sizeof(ad), ad, plain) == CCS_VERIFICATION_FAILED);
        test_fill(sizeof(plain), plain, 0xa5);
        changed[i] ^= 1;
    }
}

static void test_bad_nonce(void) {
    uint8_t out[sizeof(text) - 1], plain[sizeof(out)];
    ccs_chacha_ietf_nonce_t changed;
    ccs_poly1305_digest_t tag;

    assert(ccs_chacha20_poly1305_ietf_encrypt(key, nonce, sizeof(out), text, sizeof(ad), ad, out, tag) == CCS_OK);
    memcpy(changed, nonce, sizeof(nonce));
    memset(plain, 0xa5, sizeof(plain));
    for(size_t i = 0; i < sizeof(changed); i++) {
        changed[i] ^= 1;
        assert(ccs_chacha20_poly1305_ietf_decrypt(key, changed, tag, sizeof(out), out, sizeof(ad), ad, plain) == CCS_VERIFICATION_FAILED);
        test_fill(sizeof(plain), plain, 0xa5);
        changed[i] ^= 1;
    }
}

static void test_round_counts(void) {
    static const uint8_t rounds[] = { 2, 8, 12, 20, 254 };
    uint8_t even[sizeof(text) - 1], odd[sizeof(even)], plain[sizeof(even)];
    ccs_poly1305_digest_t even_tag, odd_tag;

    for(size_t i = 0; i < sizeof(rounds); i++) {
        assert(ccs_chachaN_poly1305_ietf_encrypt(rounds[i], key, nonce, sizeof(even), text, sizeof(ad), ad, even, even_tag) == CCS_OK);
        assert(ccs_chachaN_poly1305_ietf_encrypt(rounds[i] + 1, key, nonce, sizeof(odd), text, sizeof(ad), ad, odd, odd_tag) == CCS_OK);
        assert(memcmp(even, odd, sizeof(even)) == 0);
        assert(memcmp(even_tag, odd_tag, sizeof(even_tag)) == 0);
        assert(ccs_chachaN_poly1305_ietf_decrypt(rounds[i] + 1, key, nonce, even_tag, sizeof(even), even, sizeof(ad), ad, plain) == CCS_OK);
        assert(memcmp(plain, text, sizeof(plain)) == 0);
    }
}

static void test_invalid_rounds(void) {
    uint8_t out[sizeof(text) - 1];
    ccs_poly1305_digest_t tag;

    memset(out, 0xa5, sizeof(out));
    memset(tag, 0xa5, sizeof(tag));
    for(uint8_t rounds = 0; rounds < 2; rounds++) {
        assert(ccs_chachaN_poly1305_ietf_encrypt(rounds, key, nonce, sizeof(out), text, sizeof(ad), ad, out, tag) == CCS_ERROR);
        test_fill(sizeof(out), out, 0xa5);
        test_fill(sizeof(tag), tag, 0xa5);
        assert(ccs_chachaN_poly1305_ietf_decrypt(rounds, key, nonce, tag, sizeof(out), text, sizeof(ad), ad, out) == CCS_ERROR);
        test_fill(sizeof(out), out, 0xa5);
        assert(ccs_chachaN_poly1305_ietf_encrypt(rounds, key, nonce, 0, NULL, 0, NULL, NULL, tag) == CCS_ERROR);
        assert(ccs_chachaN_poly1305_ietf_decrypt(rounds, key, nonce, tag, 0, NULL, 0, NULL, NULL) == CCS_ERROR);
        test_fill(sizeof(tag), tag, 0xa5);
    }
}

static void test_counter_overflow(void) {
#if SIZE_MAX > UINT32_MAX
    // Counter 0 is reserved for the MAC key. Reject before reading any input.
    const size_t len = (size_t)UINT32_MAX * 64 + 1;
    uint8_t out = 0xa5;
    ccs_poly1305_digest_t tag;

    memset(tag, 0xa5, sizeof(tag));
    assert(ccs_chacha20_poly1305_ietf_encrypt(key, nonce, len, NULL, 0, NULL, &out, tag) == CCS_ERROR);
    assert(out == 0xa5);
    test_fill(sizeof(tag), tag, 0xa5);
    assert(ccs_chacha20_poly1305_ietf_decrypt(key, nonce, tag, len, NULL, 0, NULL, &out) == CCS_ERROR);
    assert(out == 0xa5);
#endif
}

static void test_tag_framing(void) {
    // Fixed framing vectors checked with Python cryptography Poly1305.
    static const size_t lengths[][2] = { { 0, 0 }, { 1, 1 }, { 15, 15 }, { 16, 16 }, { 17, 17 }, { 63, 0 }, { 64, 16 }, { 65, 17 } };
    static const char* const expected[] = {
        "5092d416599bdd1f62a4e6286badef31", "5af9182758bd583113b38b80de6f9041",
        "26f166740102b2f909f021b93fb08211", "40652d99922c0cfa57f17d98a5003645",
        "a2780bd9430d0c8a404ce1871a408b4a", "f0b25d38d334c174d3be92139d2d9c8a",
        "d3c545cde992e84ae01736f6579bb843", "dcbd4a8dfbcb1af2af51ac1989e5bf91"
    };
    ccs_poly1305_key_t polykey, alias;
    ccs_poly1305_digest_t tag;
    uint8_t input[65], auth[17];

    for(size_t i = 0; i < sizeof(polykey); i++)
        polykey[i] = (uint8_t)i;
    for(size_t i = 0; i < sizeof(input); i++)
        input[i] = (uint8_t)i;
    for(size_t i = 0; i < sizeof(auth); i++)
        auth[i] = (uint8_t)i;
    for(size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); i++) {
        ccs_chacha_poly1305_ietf_tag(polykey, lengths[i][0], input, lengths[i][1], auth, tag);
        test_hex(sizeof(tag), tag, expected[i]);
        memcpy(alias, polykey, sizeof(alias));
        ccs_chacha_poly1305_ietf_tag(alias, lengths[i][0], input, lengths[i][1], auth, alias);
        assert(memcmp(alias, tag, sizeof(tag)) == 0);
        assert(memcmp(alias + 16, polykey + 16, 16) == 0);
    }
}
#endif // CCS_CCP_IETF

int main(void) {
#if CCS_CCP_IETF
    test_rfc_vector();
    test_empty();
    test_lengths_and_in_place();
    test_bad_tag();
    test_bad_ciphertext();
    test_bad_ad();
    test_bad_key();
    test_bad_nonce();
    test_round_counts();
    test_invalid_rounds();
    test_counter_overflow();
    test_tag_framing();
    return 0;
#else
    return 77;
#endif
}
