/**
 * @file benchmark_chacha20_poly1305_djb.c
 * @copyright Copyright (c) 2026 FiercestT
 * @brief D.J. Bernstein ChaCha20-Poly1305 in-place encryption benchmark.
 */

#include "benchmark.h"

#if CCS_CCP_DJB
benchmark_result_t benchmark_chacha20_poly1305_djb(size_t input_len, size_t times) {
    benchmark_result_t total = { 0 };
    uint8_t* input = benchmark_alloc(input_len);
    ccs_chacha_key_t key;
    ccs_chacha_djb_nonce_t nonce;
    ccs_poly1305_digest_t tag;

    benchmark_random(sizeof(key), key);
    for(size_t i = 0; i < times; i++) {
        benchmark_random(input_len, input);
        benchmark_random(sizeof(nonce), nonce);
        const benchmark_timer_t start = benchmark_start();
        const ccs_res_t status = ccs_chacha20_poly1305_djb_encrypt(
            key, nonce, input_len, input, 0, NULL, input, tag
        );
        benchmark_end(start, &total);
        benchmark_check(status);
        benchmark_sink ^= tag[0];
    }

    free(input);
    return benchmark_average(total, times);
}
#endif // CCS_CCP_DJB
