/**
 * @file benchmark_poly1305.c
 * @copyright Copyright (c) 2026 FiercestT
 * @brief Poly1305 init/update/final benchmark.
 */

#include "benchmark.h"

#if CCS_POLY
benchmark_result_t benchmark_poly1305(size_t input_len, size_t times) {
    benchmark_result_t total = { 0 };
    uint8_t* input = benchmark_alloc(input_len);
    ccs_poly1305_key_t key;
    ccs_poly1305_digest_t digest;
    ccs_poly1305_ctx_t ctx;

    for(size_t i = 0; i < times; i++) {
        benchmark_random(input_len, input);
        benchmark_random(sizeof(key), key);
        const benchmark_timer_t start = benchmark_start();
        int status = ccs_poly1305_init(&ctx, key);
        status |= ccs_poly1305_update(&ctx, input_len, input);
        status |= ccs_poly1305_final(&ctx, digest);
        benchmark_end(start, &total);
        benchmark_check(status);
        benchmark_sink ^= digest[0];
    }

    free(input);
    return benchmark_average(total, times);
}
#endif // CCS_POLY
