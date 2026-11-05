/**
 * @file benchmark_blake2s.c
 * @copyright Copyright (c) 2026 FiercestT
 * @brief BLAKE2s init/update/final benchmark.
 */

#include "benchmark.h"

#if CCS_B2S
benchmark_result_t benchmark_blake2s(size_t input_len, size_t times) {
    benchmark_result_t total = { 0 };
    uint8_t* input = benchmark_alloc(input_len);
    ccs_blake2s_digest_t digest;
    ccs_blake2s_ctx_t ctx;

    for(size_t i = 0; i < times; i++) {
        benchmark_random(input_len, input);
        const benchmark_timer_t start = benchmark_start();
        int status = ccs_blake2s_init(&ctx, CCS_BLAKE2S_LEN);
        status |= ccs_blake2s_update(&ctx, input_len, input);
        status |= ccs_blake2s_final(&ctx, digest);
        benchmark_end(start, &total);
        benchmark_check(status);
        benchmark_sink ^= digest[0];
    }

    free(input);
    return benchmark_average(total, times);
}
#endif // CCS_B2S
