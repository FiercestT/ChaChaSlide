/**
 * @file test_chacha_poly1305_djb.c
 * @copyright Copyright (c) 2026 FiercestT
 * @brief D.J. Bernstein ChaCha-Poly1305 tests.
 */

#include "ccs_chacha_poly1305.h"
#include "test.h"

#if CCS_CCP_DJB
// libsodium test/default/aead_chacha20poly1305.c and .exp, first vector.
static const ccs_chacha_key_t key = {
    0x42, 0x90, 0xbc, 0xb1, 0x54, 0x17, 0x35, 0x31,
    0xf3, 0x14, 0xaf, 0x57, 0xf3, 0xbe, 0x3b, 0x50,
    0x06, 0xda, 0x37, 0x1e, 0xce, 0x27, 0x2a, 0xfa,
    0x1b, 0x5d, 0xbd, 0xd1, 0x10, 0x0a, 0x10, 0x07
};
static const ccs_chacha_djb_nonce_t nonce = { 0xcd, 0x7c, 0xf6, 0x7b, 0xe3, 0x9c, 0x79, 0x4a };
static const uint8_t ad[] = { 0x87, 0xe2, 0x29, 0xd4, 0x50, 0x08, 0x45, 0xa0, 0x79, 0xc0 };
static const uint8_t text[] = { 0x86, 0xd0, 0x99, 0x74, 0x84, 0x0b, 0xde, 0xd2, 0xa5, 0xca };

static void test_libsodium_vector(void) {
    uint8_t out[sizeof(text)], plain[sizeof(text)];
    ccs_poly1305_digest_t tag;

    assert(ccs_chacha20_poly1305_djb_encrypt(key, nonce, sizeof(text), text, sizeof(ad), ad, out, tag) == CCS_OK);
    test_hex(sizeof(out), out, "e3e446f7ede9a19b62a4");
    test_hex(sizeof(tag), tag, "677dabf4e3d24b876bb284753896e1d6");
    assert(ccs_chacha20_poly1305_djb_decrypt(key, nonce, tag, sizeof(out), out, sizeof(ad), ad, plain) == CCS_OK);
    assert(memcmp(plain, text, sizeof(plain)) == 0);
}

static void test_libsodium_no_ad(void) {
    uint8_t out[sizeof(text)];
    ccs_poly1305_digest_t tag;

    memcpy(out, text, sizeof(out));
    assert(ccs_chacha20_poly1305_djb_encrypt(key, nonce, sizeof(out), out, 0, NULL, out, tag) == CCS_OK);
    test_hex(sizeof(out), out, "e3e446f7ede9a19b62a4");
    test_hex(sizeof(tag), tag, "69e7789bcd954e658ed38423e23161dc");
    assert(ccs_chacha20_poly1305_djb_decrypt(key, nonce, tag, sizeof(out), out, 0, NULL, out) == CCS_OK);
    assert(memcmp(out, text, sizeof(out)) == 0);
}

static void test_empty(void) {
    ccs_poly1305_digest_t tag;

    // Independently checked with Python cryptography ChaCha20 and Poly1305.
    assert(ccs_chacha20_poly1305_djb_encrypt(key, nonce, 0, NULL, 0, NULL, NULL, tag) == CCS_OK);
    test_hex(sizeof(tag), tag, "420d885351d029b85a0d5bca1e620ece");
    assert(ccs_chacha20_poly1305_djb_decrypt(key, nonce, tag, 0, NULL, 0, NULL, NULL) == CCS_OK);
    tag[0] ^= 1;
    assert(ccs_chacha20_poly1305_djb_decrypt(key, nonce, tag, 0, NULL, 0, NULL, NULL) == CCS_VERIFICATION_FAILED);
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
            assert(ccs_chacha20_poly1305_djb_encrypt(key, nonce, len, in, ad_len, aad, out + 1, tag) == CCS_OK);
            assert(ccs_chacha20_poly1305_djb_encrypt(key, nonce, len, inplace + 1, ad_len, aad, inplace + 1, inplace_tag) == CCS_OK);
            assert(memcmp(out, inplace, sizeof(out)) == 0);
            assert(memcmp(tag, inplace_tag, sizeof(tag)) == 0);
            assert(out[0] == 0xa5);
            test_fill(sizeof(out) - len - 1, out + len + 1, 0xa5);
            assert(ccs_chacha20_poly1305_djb_decrypt(key, nonce, tag, len, inplace + 1, ad_len, aad, inplace + 1) == CCS_OK);
            assert(memcmp(inplace + 1, input + 1, len) == 0);
            assert(inplace[0] == 0xa5);
            test_fill(sizeof(inplace) - len - 1, inplace + len + 1, 0xa5);
        }
    }
}

static void test_bad_tag(void) {
    uint8_t out[sizeof(text)], plain[sizeof(text)], saved[sizeof(text)];
    ccs_poly1305_digest_t tag;

    assert(ccs_chacha20_poly1305_djb_encrypt(key, nonce, sizeof(out), text, sizeof(ad), ad, out, tag) == CCS_OK);
    memcpy(saved, out, sizeof(out));
    for(size_t i = 0; i < sizeof(tag); i++) {
        for(unsigned int bit = 0; bit < 8; bit++) {
            tag[i] ^= (uint8_t)(1u << bit);
            memset(plain, 0xa5, sizeof(plain));
            assert(ccs_chacha20_poly1305_djb_decrypt(key, nonce, tag, sizeof(out), out, sizeof(ad), ad, plain) == CCS_VERIFICATION_FAILED);
            test_fill(sizeof(plain), plain, 0xa5);
            assert(ccs_chacha20_poly1305_djb_decrypt(key, nonce, tag, sizeof(out), out, sizeof(ad), ad, out) == CCS_VERIFICATION_FAILED);
            assert(memcmp(out, saved, sizeof(out)) == 0);
            tag[i] ^= (uint8_t)(1u << bit);
        }
    }
}

static void test_bad_ciphertext(void) {
    uint8_t out[sizeof(text)], plain[sizeof(text)];
    ccs_poly1305_digest_t tag;

    assert(ccs_chacha20_poly1305_djb_encrypt(key, nonce, sizeof(out), text, sizeof(ad), ad, out, tag) == CCS_OK);
    memset(plain, 0xa5, sizeof(plain));
    for(size_t i = 0; i < sizeof(out); i++) {
        out[i] ^= 1;
        assert(ccs_chacha20_poly1305_djb_decrypt(key, nonce, tag, sizeof(out), out, sizeof(ad), ad, plain) == CCS_VERIFICATION_FAILED);
        test_fill(sizeof(plain), plain, 0xa5);
        out[i] ^= 1;
    }
    assert(ccs_chacha20_poly1305_djb_decrypt(key, nonce, tag, sizeof(out) - 1, out, sizeof(ad), ad, plain) == CCS_VERIFICATION_FAILED);
    test_fill(sizeof(plain), plain, 0xa5);
}

static void test_bad_ad(void) {
    uint8_t out[sizeof(text)], plain[sizeof(text)], changed[sizeof(ad)];
    ccs_poly1305_digest_t tag;

    assert(ccs_chacha20_poly1305_djb_encrypt(key, nonce, sizeof(out), text, sizeof(ad), ad, out, tag) == CCS_OK);
    memcpy(changed, ad, sizeof(ad));
    memset(plain, 0xa5, sizeof(plain));
    for(size_t i = 0; i < sizeof(changed); i++) {
        changed[i] ^= 1;
        assert(ccs_chacha20_poly1305_djb_decrypt(key, nonce, tag, sizeof(out), out, sizeof(changed), changed, plain) == CCS_VERIFICATION_FAILED);
        test_fill(sizeof(plain), plain, 0xa5);
        changed[i] ^= 1;
    }
    assert(ccs_chacha20_poly1305_djb_decrypt(key, nonce, tag, sizeof(out), out, sizeof(ad) - 1, ad, plain) == CCS_VERIFICATION_FAILED);
    test_fill(sizeof(plain), plain, 0xa5);
}

static void test_bad_key(void) {
    uint8_t out[sizeof(text)], plain[sizeof(text)];
    ccs_chacha_key_t changed;
    ccs_poly1305_digest_t tag;

    assert(ccs_chacha20_poly1305_djb_encrypt(key, nonce, sizeof(out), text, sizeof(ad), ad, out, tag) == CCS_OK);
    memcpy(changed, key, sizeof(key));
    memset(plain, 0xa5, sizeof(plain));
    for(size_t i = 0; i < sizeof(changed); i++) {
        changed[i] ^= 1;
        assert(ccs_chacha20_poly1305_djb_decrypt(changed, nonce, tag, sizeof(out), out, sizeof(ad), ad, plain) == CCS_VERIFICATION_FAILED);
        test_fill(sizeof(plain), plain, 0xa5);
        changed[i] ^= 1;
    }
}

static void test_bad_nonce(void) {
    uint8_t out[sizeof(text)], plain[sizeof(text)];
    ccs_chacha_djb_nonce_t changed;
    ccs_poly1305_digest_t tag;

    assert(ccs_chacha20_poly1305_djb_encrypt(key, nonce, sizeof(out), text, sizeof(ad), ad, out, tag) == CCS_OK);
    memcpy(changed, nonce, sizeof(nonce));
    memset(plain, 0xa5, sizeof(plain));
    for(size_t i = 0; i < sizeof(changed); i++) {
        changed[i] ^= 1;
        assert(ccs_chacha20_poly1305_djb_decrypt(key, changed, tag, sizeof(out), out, sizeof(ad), ad, plain) == CCS_VERIFICATION_FAILED);
        test_fill(sizeof(plain), plain, 0xa5);
        changed[i] ^= 1;
    }
}

static void test_round_counts(void) {
    static const uint8_t rounds[] = { 2, 8, 12, 20, 254 };
    uint8_t even[sizeof(text)], odd[sizeof(text)], plain[sizeof(text)];
    ccs_poly1305_digest_t even_tag, odd_tag;

    for(size_t i = 0; i < sizeof(rounds); i++) {
        assert(ccs_chachaN_poly1305_djb_encrypt(rounds[i], key, nonce, sizeof(even), text, sizeof(ad), ad, even, even_tag) == CCS_OK);
        assert(ccs_chachaN_poly1305_djb_encrypt(rounds[i] + 1, key, nonce, sizeof(odd), text, sizeof(ad), ad, odd, odd_tag) == CCS_OK);
        assert(memcmp(even, odd, sizeof(even)) == 0);
        assert(memcmp(even_tag, odd_tag, sizeof(even_tag)) == 0);
        assert(ccs_chachaN_poly1305_djb_decrypt(rounds[i] + 1, key, nonce, even_tag, sizeof(even), even, sizeof(ad), ad, plain) == CCS_OK);
        assert(memcmp(plain, text, sizeof(plain)) == 0);
    }
}

static void test_invalid_rounds(void) {
    uint8_t out[sizeof(text)];
    ccs_poly1305_digest_t tag;

    memset(out, 0xa5, sizeof(out));
    memset(tag, 0xa5, sizeof(tag));
    for(uint8_t rounds = 0; rounds < 2; rounds++) {
        assert(ccs_chachaN_poly1305_djb_encrypt(rounds, key, nonce, sizeof(out), text, sizeof(ad), ad, out, tag) == CCS_ERROR);
        test_fill(sizeof(out), out, 0xa5);
        test_fill(sizeof(tag), tag, 0xa5);
        assert(ccs_chachaN_poly1305_djb_decrypt(rounds, key, nonce, tag, sizeof(out), text, sizeof(ad), ad, out) == CCS_ERROR);
        test_fill(sizeof(out), out, 0xa5);
        assert(ccs_chachaN_poly1305_djb_encrypt(rounds, key, nonce, 0, NULL, 0, NULL, NULL, tag) == CCS_ERROR);
        assert(ccs_chachaN_poly1305_djb_decrypt(rounds, key, nonce, tag, 0, NULL, 0, NULL, NULL) == CCS_ERROR);
        test_fill(sizeof(tag), tag, 0xa5);
    }
}

static void test_tag_framing(void) {
    // Fixed framing vectors checked with Python cryptography Poly1305.
    static const size_t lengths[][2] = { { 0, 0 }, { 1, 1 }, { 15, 15 }, { 16, 16 }, { 17, 17 }, { 63, 0 }, { 64, 16 }, { 65, 17 } };
    static const char* const expected[] = {
        "5092d416599bdd1f62a4e6286badef31", "c535abaa3f89a6b6d82b5f1d94f26723",
        "7ad84d1f4186f99e42167d14d2311c38", "ccd60c2fb0e14c343945d5c94cfe2e22",
        "e1ef28592d8223360547f5b2d0a7e727", "4fad86ba01037eac5f99b06b61cf6c9f",
        "c44ee9ba35c1c43b7afd2fba0e772bb2", "71b61c834d15dc69baf582db3ff48de8"
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
        ccs_chacha_poly1305_djb_tag(polykey, lengths[i][0], input, lengths[i][1], auth, tag);
        test_hex(sizeof(tag), tag, expected[i]);
        memcpy(alias, polykey, sizeof(alias));
        ccs_chacha_poly1305_djb_tag(alias, lengths[i][0], input, lengths[i][1], auth, alias);
        assert(memcmp(alias, tag, sizeof(tag)) == 0);
        assert(memcmp(alias + 16, polykey + 16, 16) == 0);
    }
}
#endif // CCS_CCP_DJB

int main(void) {
#if CCS_CCP_DJB
    test_libsodium_vector();
    test_libsodium_no_ad();
    test_empty();
    test_lengths_and_in_place();
    test_bad_tag();
    test_bad_ciphertext();
    test_bad_ad();
    test_bad_key();
    test_bad_nonce();
    test_round_counts();
    test_invalid_rounds();
    test_tag_framing();
    return 0;
#else
    return 77;
#endif
}
