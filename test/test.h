/**
 * @file test.h
 * @brief Small test helpers. Assertions stay enabled in release builds.
 * @copyright Copyright (c) 2026 FiercestT
 */

#ifndef CCS_TEST_H
#define CCS_TEST_H

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <stdint.h>
#include <string.h>

static inline void test_hex(size_t len, const uint8_t* actual, const char* expected) {
    static const char hex[] = "0123456789abcdef";

    assert(strlen(expected) == 2 * len);
    for(size_t i = 0; i < len; i++) {
        assert(hex[actual[i] >> 4] == expected[2 * i]);
        assert(hex[actual[i] & 15] == expected[2 * i + 1]);
    }
}

static inline void test_fill(size_t len, const void* actual, uint8_t value) {
    const uint8_t* bytes = actual;

    for(size_t i = 0; i < len; i++)
        assert(bytes[i] == value);
}

#endif // CCS_TEST_H
