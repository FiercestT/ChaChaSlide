/**
 * @file ccs_util.h
 * @brief Internal utility interface for ChaChaSlide.
 * @copyright Copyright (c) 2026 FiercestT
 */

#ifndef CCS_UTIL_H
#define CCS_UTIL_H

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#include "ccs_types.h"

#if defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__)
#define CCS_LITTLE_ENDIAN (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
#elif defined(_WIN32) || defined(__ARMEL__) || defined(__AARCH64EL__)
#define CCS_LITTLE_ENDIAN 1
#else
#define CCS_LITTLE_ENDIAN 0
#endif

/**
 * @brief Overwrite a memory region with zeroes.
 *
 * @param in_len Byte length of the memory region.
 * @param in The memory region to overwrite.
 */
static inline void ccs_util_memzero(size_t in_len, void* in) {
    for(size_t i = 0; i < in_len; i++) {
        ((volatile uint8_t*)in)[i] = 0;
    }
}

/**
 * @brief Load a little-endian 32-bit integer.
 *
 * @param in [4] The input buffer.
 * @return The decoded 32-bit integer.
 */
static inline uint32_t ccs_util_load32le(const uint8_t* in) {
    return ((uint32_t)in[0])
         | ((uint32_t)in[1] << 8)
         | ((uint32_t)in[2] << 16)
         | ((uint32_t)in[3] << 24);
}

/**
 * @brief Load a little-endian 64-bit integer.
 *
 * @param in [8] The input buffer.
 * @return The decoded 64-bit integer.
 */
static inline uint64_t ccs_util_load64le(const uint8_t* in) {
    return ((uint64_t)ccs_util_load32le(in))
         | ((uint64_t)ccs_util_load32le(&in[4]) << 32);
}

/**
 * @brief Store a 32-bit integer in little-endian order.
 *
 * @param value The integer to encode.
 * @param out [4] The output buffer.
 */
static inline void ccs_util_store32le(uint32_t value, uint8_t* out) {
    out[0] = (uint8_t)(value);
    out[1] = (uint8_t)(value >> 8);
    out[2] = (uint8_t)(value >> 16);
    out[3] = (uint8_t)(value >> 24);
}

/**
 * @brief Store a 64-bit integer in little-endian order.
 *
 * @param value The integer to encode.
 * @param out [8] The output buffer.
 */
static inline void ccs_util_store64le(uint64_t value, uint8_t* out) {
    ccs_util_store32le((uint32_t)value, out);
    ccs_util_store32le((uint32_t)(value >> 32), &out[4]);
}

/**
 * @brief Left rotate a 32-bit input by an amount.
 * 
 * @param shift The amount to rotate. Must be 1-31 or behavior is undefined.
 * @param value The value to rotate.
 * @return uint32_t The rotated value.
 */
static inline uint32_t ccs_util_rotl32(uint8_t shift, uint32_t value) {
    return (value << shift) | (value >> (32 - shift));
}

/**
 * @brief Right rotate a 32-bit input by an amount.
 * 
 * @param shift The amount to rotate. Must be 1-31 or behavior is undefined.
 * @param value The value to rotate.
 * @return uint32_t The rotated value.
 */
static inline uint32_t ccs_util_rotr32(uint8_t shift, uint32_t value) {
    return (value >> shift) | (value << (32 - shift));
}

/**
 * @brief Left rotate a 64-bit input by an amount.
 * 
 * @param shift The amount to rotate. Must be 1-63 or behavior is undefined.
 * @param value The value to rotate.
 * @return uint64_t The rotated value.
 */
static inline uint64_t ccs_util_rotl64(uint8_t shift, uint64_t value) {
    return (value << shift) | (value >> (64 - shift));
}

/**
 * @brief Right rotate a 64-bit input by an amount.
 * 
 * @param shift The amount to rotate. Must be 1-63 or behavior is undefined.
 * @param value The value to rotate.
 * @return uint64_t The rotated value.
 */
static inline uint64_t ccs_util_rotr64(uint8_t shift, uint64_t value) {
    return (value >> shift) | (value << (64 - shift));
}

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // CCS_UTIL_H
