/**
 * @file main.c
 * @copyright Copyright (c) 2026 FiercestT
 * @brief Run all enabled algorithm benchmarks.
 */

#include "benchmark.h"

volatile uint8_t benchmark_sink;

static inline void benchmark_run(
    const char* name,
    benchmark_result_t (*benchmark)(size_t, size_t)
) {
#if BENCHMARK_EMBEDDED
    const size_t input_sizes[] = { 16, 64, 256, 1024 };
#else
    const size_t input_sizes[] = { 64, 256, 1024, 4096, 16384, 65536, 1048576 };
#endif

    srand(1);
    for(size_t i = 0; i < sizeof(input_sizes) / sizeof(input_sizes[0]); i++) {
        const size_t size = input_sizes[i];
        const benchmark_result_t result = benchmark(size, BENCHMARK_TIMES);
        const double throughput = result.seconds > 0 ? size / result.seconds / 1048576.0 : 0;

        printf("%-25s %10zu %14.2f ", name, size, throughput);
        if(result.cycles > 0)
            printf("%12.2f %14.3f %14.0f\n", result.cycles / size, result.seconds * 1e6, result.cycles);
        else
            printf("%12s %14.3f %14s\n", "N/A", result.seconds * 1e6, "N/A");
    }
}

int main(void) {
    printf("%-25s %10s %14s %12s %14s %14s\n",
        "Function", "Bytes", "MiB/s", "Ticks/B", "us/op", "Ticks/op");

#if CCS_CC_IETF
    benchmark_run("chacha20_ietf", benchmark_chacha20_ietf);
#endif
#if CCS_CC_DJB
    benchmark_run("chacha20_djb", benchmark_chacha20_djb);
#endif
#if CCS_XCC
    benchmark_run("xchacha20", benchmark_xchacha20);
#endif
#if CCS_CCP_IETF
    benchmark_run("chacha20_poly1305_ietf", benchmark_chacha20_poly1305_ietf);
#endif
#if CCS_CCP_DJB
    benchmark_run("chacha20_poly1305_djb", benchmark_chacha20_poly1305_djb);
#endif
#if CCS_XCCP
    benchmark_run("xchacha20_poly1305", benchmark_xchacha20_poly1305);
#endif
#if CCS_POLY
    benchmark_run("poly1305", benchmark_poly1305);
#endif
#if CCS_B2S
    benchmark_run("blake2s", benchmark_blake2s);
#endif
#if CCS_B2B
    benchmark_run("blake2b", benchmark_blake2b);
#endif

    return 0;
}
