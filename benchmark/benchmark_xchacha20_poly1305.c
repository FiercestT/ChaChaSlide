/**
 * @file benchmark_xchacha20_poly1305.c
 * @copyright Copyright (c) 2026 FiercestT
 * @brief XChaCha20-Poly1305 in-place encryption benchmark.
 */

#include "benchmark.h"

#if CCS_XCCP
benchmark_result_t benchmark_xchacha20_poly1305(size_t input_len, size_t times) {
    benchmark_result_t total = { 0 };
    uint8_t* input = benchmark_alloc(input_len);
    ccs_chacha_key_t key;
    ccs_xchacha_nonce_t nonce;
    ccs_poly1305_digest_t tag;

    benchmark_random(sizeof(key), key);

    for(size_t i = 0; i < times; i++) {
        benchmark_random(input_len, input);
        benchmark_random(sizeof(nonce), nonce);
        const benchmark_timer_t start = benchmark_start();
        const ccs_res_t status = ccs_xchacha20_poly1305_encrypt(
            key, nonce, input_len, input, 0, NULL, input, tag
        );
        benchmark_end(start, &total);
        benchmark_check(status);
        benchmark_sink ^= tag[0];
    }

    free(input);
    return benchmark_average(total, times);
}
#endif // CCS_XCCP
