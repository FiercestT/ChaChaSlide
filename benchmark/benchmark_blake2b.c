/**
 * @file benchmark_blake2b.c
 * @copyright Copyright (c) 2026 FiercestT
 * @brief BLAKE2b init/update/final benchmark.
 */

#include "benchmark.h"

#if CCS_B2B
benchmark_result_t benchmark_blake2b(size_t input_len, size_t times) {
    benchmark_result_t total = { 0 };
    uint8_t* input = benchmark_alloc(input_len);
    ccs_blake2b_digest_t digest;
    ccs_blake2b_ctx_t ctx;

    for(size_t i = 0; i < times; i++) {
        benchmark_random(input_len, input);
        const benchmark_timer_t start = benchmark_start();
        int status = ccs_blake2b_init(&ctx, CCS_BLAKE2B_LEN);
        status |= ccs_blake2b_update(&ctx, input_len, input);
        status |= ccs_blake2b_final(&ctx, digest);
        benchmark_end(start, &total);
        benchmark_check(status);
        benchmark_sink ^= digest[0];
    }

    free(input);
    return benchmark_average(total, times);
}
#endif // CCS_B2B
