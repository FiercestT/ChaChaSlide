/**
 * @file benchmark_chacha20_ietf.c
 * @copyright Copyright (c) 2026 FiercestT
 * @brief IETF ChaCha20 in-place encryption benchmark.
 */

#include "benchmark.h"

#if CCS_CC_IETF
benchmark_result_t benchmark_chacha20_ietf(size_t input_len, size_t times) {
    benchmark_result_t total = { 0 };
    uint8_t* input = benchmark_alloc(input_len);
    ccs_chacha_key_t key;
    ccs_chacha_ietf_nonce_t nonce;

    benchmark_random(sizeof(key), key);

    for(size_t i = 0; i < times; i++) {
        benchmark_random(input_len, input);
        benchmark_random(sizeof(nonce), nonce);
        const benchmark_timer_t start = benchmark_start();
        const ccs_res_t status = ccs_chacha20_ietf(key, nonce, input_len, input, input);
        benchmark_end(start, &total);
        benchmark_check(status);
        if(input_len)
            benchmark_sink ^= input[0];
    }

    free(input);
    return benchmark_average(total, times);
}
#endif // CCS_CC_IETF
