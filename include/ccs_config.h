/**
 * @file ccs_config.h
 * @brief Compile-time feature configuration for ChaChaSlide.
 * @copyright Copyright (c) 2026 FiercestT
 */

#ifndef CCS_CONFIG_H
#define CCS_CONFIG_H

// Enable Stream Ciphers
#define CCS_CC_IETF  1 // IETF ChaCha20
#define CCS_CC_DJB   1 // D.J. Bernstein ChaCha20
#define CCS_XCC      1 // XChaCha20

// Enable AEAD Modes
#define CCS_CCP_IETF 1 // IETF ChaCha20-Poly1305
#define CCS_CCP_DJB  1 // D.J. Bernstein ChaCha20-Poly1305
#define CCS_XCCP     1 // XChaCha20-Poly1305

// Enable One Time Authenticators
#define CCS_POLY     1 // Poly1305. 0 = Not Exposed (Generic fallback if AEAD is enabled). 1 = Generic. 2 = 32->32. 3 = 8-bit. See readme for details.

// Enable Hash Functions
#define CCS_B2S      1 // BLAKE2s
#define CCS_B2B      1 // BLAKE2b

// Expose Extra Functions
#define CCS_HCC      0 // HChaCha20

// Computed implementation dependencies, not public API exposure. Do Not Touch.
#define CCS_NEED_CCP     (CCS_CCP_IETF || CCS_CCP_DJB || CCS_XCCP)
#define CCS_NEED_XCC     (CCS_XCC)
#define CCS_NEED_CC_IETF (CCS_CC_IETF || CCS_CCP_IETF)
#define CCS_NEED_CC_DJB  (CCS_CC_DJB || CCS_CCP_DJB || CCS_NEED_XCC || CCS_XCCP)
#define CCS_NEED_POLY    (CCS_POLY || CCS_NEED_CCP)
#define CCS_NEED_HCC     (CCS_HCC || CCS_NEED_XCC || CCS_XCCP)
#define CCS_NEED_CC      (CCS_NEED_CC_IETF || CCS_NEED_CC_DJB || CCS_NEED_HCC)
#define CCS_NEED_B2      (CCS_B2S || CCS_B2B)

#if CCS_POLY < 0 || CCS_POLY > 3
#error "CCS_POLY must be 0 (disabled), 1 (generic), 2 (32->32), or 3 (8-bit)"
#endif

#endif // CCS_CONFIG_H
