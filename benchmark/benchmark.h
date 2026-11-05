/**
 * @file benchmark.h
 * @copyright Copyright (c) 2026 FiercestT
 * @brief Shared benchmark timing and reporting helpers.
 */

#ifndef CCS_BENCHMARK_H
#define CCS_BENCHMARK_H

#ifndef _WIN32
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#endif

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "../include/ccs.h"

#ifdef _WIN32
#include <windows.h>
#endif

#if defined(__AVR__) || \
    ((defined(__arm__) || defined(__thumb__)) && \
     !defined(__linux__) && !defined(__APPLE__) && !defined(_WIN32))
#define BENCHMARK_EMBEDDED 1
#else
#define BENCHMARK_EMBEDDED 0
#endif

#ifndef BENCHMARK_TIMES
#define BENCHMARK_TIMES 100
#endif

#if BENCHMARK_TIMES < 1
#error "BENCHMARK_TIMES must be positive"
#endif

#if BENCHMARK_EMBEDDED
#if defined(__AVR__)
#include <avr/io.h>
#include <avr/interrupt.h>
#ifndef F_CPU
#error "Set F_CPU to the board's CPU frequency in Hz"
#endif
#if !defined(TCCR1A) || !defined(TCCR1B) || !defined(TCNT1) || !defined(TIMSK1)
#error "This AVR does not have the supported 16-bit Timer1"
#endif

// Reserves Timer1; /64 gives a 262 ms wrap interval at 16 MHz.
// Each timed call must finish before one wrap. Keep the CPU clock fixed.
static inline void benchmark_timer_init(void) {
    uint8_t interrupts = SREG;
    cli();
    TIMSK1 = 0;
    TCCR1A = 0;
#ifdef TCCR1C
    TCCR1C = 0;
#endif
    TCCR1B = (1 << CS11) | (1 << CS10);
    TCNT1 = 0;
    SREG = interrupts;
}

static inline uint32_t benchmark_timer_ticks(void) {
    uint8_t interrupts = SREG;
    cli();
    uint16_t ticks = TCNT1;
    SREG = interrupts;
    return ticks;
}

#define BENCHMARK_CPU_HZ F_CPU
#define BENCHMARK_TICK_CYCLES 64UL
#define BENCHMARK_TICK_MASK UINT16_MAX

#elif defined(__ARM_ARCH_6M__) || defined(__ARM_ARCH_7M__) || \
      defined(__ARM_ARCH_7EM__) || defined(__ARM_ARCH_8M_BASE__) || \
      defined(__ARM_ARCH_8M_MAIN__) || defined(__ARM_ARCH_8_1M_MAIN__)
// Uses the CMSIS clock value supplied by the board's normal startup code.
extern uint32_t SystemCoreClock;
#define BENCHMARK_SYSTICK_CTRL (*(volatile uint32_t*)0xE000E010UL)
#define BENCHMARK_SYSTICK_LOAD (*(volatile uint32_t*)0xE000E014UL)
#define BENCHMARK_SYSTICK_VAL  (*(volatile uint32_t*)0xE000E018UL)

// Reserves SysTick, including its interrupt. Not compatible with an RTOS tick.
// Each call must finish within 2^24 CPU cycles (210 ms at 80 MHz).
static inline void benchmark_timer_init(void) {
    BENCHMARK_SYSTICK_CTRL = 0;
    BENCHMARK_SYSTICK_LOAD = 0xFFFFFFUL;
    BENCHMARK_SYSTICK_VAL = 0;
    *(volatile uint32_t*)0xE000ED04UL = 1UL << 25; // Clear pending SysTick IRQ.
    BENCHMARK_SYSTICK_CTRL = 5; // Enable, CPU clock, no interrupt.
    while(BENCHMARK_SYSTICK_VAL == 0) {
    }
}

static inline uint32_t benchmark_timer_ticks(void) {
    return BENCHMARK_SYSTICK_VAL;
}

#define BENCHMARK_CPU_HZ SystemCoreClock
#define BENCHMARK_TICK_CYCLES 1UL
#define BENCHMARK_TICK_MASK 0xFFFFFFUL

#else
#error "Bare-metal ARM timing supports Cortex-M cores with SysTick"
#endif
#define BENCHMARK_HAS_CYCLES 1

#elif defined(_M_IX86) || defined(_M_X64)
#include <intrin.h>
#define BENCHMARK_HAS_CYCLES 1
#elif defined(__i386__) || defined(__x86_64__)
#include <x86intrin.h>
#define BENCHMARK_HAS_CYCLES 1
#else
#define BENCHMARK_HAS_CYCLES 0
#endif

typedef struct benchmark_result_s {
    double seconds;
    double cycles;
} benchmark_result_t;

typedef struct benchmark_timer_s {
#if BENCHMARK_EMBEDDED
    uint32_t ticks;
#else
    double seconds;
    uint64_t cycles;
#endif
} benchmark_timer_t;

extern volatile uint8_t benchmark_sink;

static inline void benchmark_random(size_t input_len, uint8_t* input) {
    for(size_t i = 0; i < input_len; i++)
        input[i] = (uint8_t)rand();
}

static inline uint8_t* benchmark_alloc(size_t input_len) {
    uint8_t* input = malloc(input_len ? input_len : 1);
    if(!input) {
        fprintf(stderr, "Benchmark allocation failed.\n");
        exit(EXIT_FAILURE);
    }
    return input;
}

static inline void benchmark_check(int status) {
    if(status != CCS_OK) {
        fprintf(stderr, "Benchmark algorithm failed.\n");
        exit(EXIT_FAILURE);
    }
}

#if !BENCHMARK_EMBEDDED
static inline double benchmark_now(void) {
#ifdef _WIN32
    LARGE_INTEGER now, frequency;
    if(!QueryPerformanceFrequency(&frequency) || !QueryPerformanceCounter(&now)) {
        fprintf(stderr, "Benchmark timer failed.\n");
        exit(EXIT_FAILURE);
    }
    return (double)now.QuadPart / (double)frequency.QuadPart;
#else
    struct timespec now;
    if(clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        fprintf(stderr, "Benchmark timer failed.\n");
        exit(EXIT_FAILURE);
    }
    return (double)now.tv_sec + (double)now.tv_nsec / 1e9;
#endif
}
#endif

static inline void benchmark_barrier(void) {
#if defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__("" ::: "memory");
#elif defined(_MSC_VER)
    _ReadWriteBarrier();
#endif
}

#if !BENCHMARK_EMBEDDED
static inline uint64_t benchmark_cycles(void) {
#if BENCHMARK_HAS_CYCLES
    _mm_lfence();
    uint64_t cycles = __rdtsc();
    _mm_lfence();
    return cycles;
#else
    return 0;
#endif
}
#endif

static inline benchmark_timer_t benchmark_start(void) {
    benchmark_timer_t timer;
#if BENCHMARK_EMBEDDED
    static int initialized = 0;
    if(!initialized) {
        benchmark_timer_init();
        initialized = 1;
    }
    timer.ticks = benchmark_timer_ticks();
#else
    timer.seconds = benchmark_now();
    timer.cycles = benchmark_cycles();
#endif
    benchmark_barrier();
    return timer;
}

static inline void benchmark_end(benchmark_timer_t start, benchmark_result_t* total) {
    benchmark_barrier();
#if BENCHMARK_EMBEDDED
#ifdef __AVR__
    uint32_t ticks = (benchmark_timer_ticks() - start.ticks) & BENCHMARK_TICK_MASK;
#else
    uint32_t ticks = (start.ticks - benchmark_timer_ticks()) & BENCHMARK_TICK_MASK;
#endif
    double cycles = (double)ticks * BENCHMARK_TICK_CYCLES;
    total->seconds += cycles / BENCHMARK_CPU_HZ;
    total->cycles += cycles;
#else
    uint64_t cycles = benchmark_cycles();
    double seconds = benchmark_now();
    total->seconds += seconds - start.seconds;
    total->cycles += (double)(cycles - start.cycles);
#endif
}

static inline benchmark_result_t benchmark_average(benchmark_result_t total, size_t times) {
    if(times) {
        total.seconds /= (double)times;
        total.cycles /= (double)times;
    }
    return total;
}

#if CCS_CC_IETF
benchmark_result_t benchmark_chacha20_ietf(size_t input_len, size_t times);
#endif
#if CCS_CC_DJB
benchmark_result_t benchmark_chacha20_djb(size_t input_len, size_t times);
#endif
#if CCS_XCC
benchmark_result_t benchmark_xchacha20(size_t input_len, size_t times);
#endif
#if CCS_CCP_IETF
benchmark_result_t benchmark_chacha20_poly1305_ietf(size_t input_len, size_t times);
#endif
#if CCS_CCP_DJB
benchmark_result_t benchmark_chacha20_poly1305_djb(size_t input_len, size_t times);
#endif
#if CCS_XCCP
benchmark_result_t benchmark_xchacha20_poly1305(size_t input_len, size_t times);
#endif
#if CCS_POLY
benchmark_result_t benchmark_poly1305(size_t input_len, size_t times);
#endif
#if CCS_B2S
benchmark_result_t benchmark_blake2s(size_t input_len, size_t times);
#endif
#if CCS_B2B
benchmark_result_t benchmark_blake2b(size_t input_len, size_t times);
#endif

#endif // CCS_BENCHMARK_H
