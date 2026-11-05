# ChaChaSlide

A lightweight, portable C library implementing ChaCha20, XChaCha20, ChaCha20-Poly1305, XChaCha20-Poly1305, IETF & Bernstein variants, N rounds, BLAKE2s/b.

The library is optimized for code size while matching or beating throughput of comparable crypto libraries at -O3. For reference, ChaCha20-Poly1305 compiles to just 2.2KB at -Os and ~5.1KB at -O3 on Windows.

## Features

Features can be toggled in `ccs_config.h`.

| Category | Feature |
| --- | --- |
| Stream Ciphers | IETF ChaCha20 (96-bit nonce, 32-bit counter) [[1]](#references) |
| | D.J. Bernstein ChaCha20 (64-bit nonce, 64-bit counter) [[2]](#references) |
| | XChaCha20 (192-bit nonce, 64-bit counter) [[3]](#references) |
| AEAD Modes | IETF ChaCha20-Poly1305 [[1]](#references) |
| | D.J. Bernstein ChaCha20-Poly1305 [[4]](#references) (compatible with LibSodium) |
| | XChaCha20-Poly1305 [[3]](#references), [[4]](#references) |
| One Time Authenticators | Poly1305 [[1]](#references) |
| Hash Functions | BLAKE2s [[5]](#references) |
| | BLAKE2b [[5]](#references) |

All (X)ChaCha and (X)ChaCha-Poly1305 functions support custom number of rounds through their ChaChaN APIs, allowing for ChaCha12 or ChaCha8. ChaChaN supports custom counter start.

## Getting Started

[Code Examples](./example/)

#### CMake
1. Add this project using `add_subdirectory(path/to/ChaChaSlide)` (CMake 3.16+, GCC/Clang).
2. Link your application to either `ccs-size` or `ccs-speed` using `target_link_libraries()`.
3. Configure `include/ccs_config.h` for the features you want to keep.
4. Tests and benchmarks are off by default. Enable `BUILD_TESTING` for tests or `BUILD_BENCHMARKS` for the benchmark runner.

LTO is enabled when supported. Set `CMAKE_INTERPROCEDURAL_OPTIMIZATION=OFF` to disable it.

## Code Size

Bytes per feature, including dependencies. Rows are not additive due to feature overlap.<sup>1</sup>

Compiling and end application with LTO will further reduce ~100B when using fixed round counts (e.g. ChaCha20 instead of ChaChaN). 

#### `-Os`, Bytes

| Feature | Windows x86-64 | Linux x86-64 | Cortex-M0+<sup>2</sup> | Cortex-M3<sup>2</sup> | AArch64 | AVR ATmega328P<sup>2</sup> |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| ChaCha20 IETF | 560 | 504 | 516 | 464 | 620 | 1,518 |
| ChaCha20 DJB | 544 | 495 | 524 | 484 | 620 | 1,768 |
| XChaCha20 | 832 | 816 | 668 | 728 | 936 | 2,360 |
| ChaCha20-Poly1305 IETF | 2,240 | 2,035 | 2,052 | 1,868 | 2,288 | 4,132 |
| ChaCha20-Poly1305 DJB | 2,128 | 1,914 | 2,028 | 1,836 | 2,200 | 4,144 |
| XChaCha20-Poly1305 | 2,496 | 2,315 | 2,316 | 2,112 | 2,612 | 4,716 |
| Poly1305 | 1,072 | 947 | 1,194 | 930 | 1,080 | 1,852 |
| BLAKE2s | 1,248 | 1,135 | 998 | 904 | 1,324 | 2,098 |
| BLAKE2b | 1,408 | 1,292 | 1,358 | 1,280 | 1,412 | 3,620 |
| HChaCha20 | 496 | 434 | 464 | 420 | 568 | 1,238 |
| Default suite | 6,784 | 6,228 | 5,488 | 5,316 | 7,196 | 13,068 |

#### `-O3`, Bytes

| Feature | Windows x86-64 | Linux x86-64 | Cortex-M0+<sup>2</sup> | Cortex-M3<sup>2</sup> | AArch64 | AVR ATmega328P<sup>2</sup> |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| ChaCha20 IETF | 1,712 | 1,459 | 1,568 | 1,304 | 1,548 | 5,756 |
| ChaCha20 DJB | 1,712 | 1,555 | 1,576 | 1,292 | 1,488 | 6,204 |
| XChaCha20 | 2,512 | 2,323 | 2,340 | 1,980 | 2,320 | 10,180 |
| ChaCha20-Poly1305 IETF | 5,072 | 4,798 | 5,624 | 4,268 | 4,200 | 15,266 |
| ChaCha20-Poly1305 DJB | 4,976 | 4,478 | 5,516 | 4,260 | 3,992 | 15,178 |
| XChaCha20-Poly1305 | 5,744 | 5,598 | 6,796 | 4,980 | 5,052 | 19,586 |
| Poly1305 | 2,736 | 2,335 | 3,440 | 2,672 | 2,020 | 7,862 |
| BLAKE2s | 5,376 | 5,561 | 6,180 | 5,368 | 5,788 | 26,766 |
| BLAKE2b | 7,056 | 7,225 | 22,436 | 16,928 | 6,920 | -<sup>3</sup> |
| HChaCha20 | 704 | 666 | 1,016 | 712 | 836 | 3,582 |
| Default suite | 21,984 | 21,598 | 38,424 | 29,828 | 21,436 | 205,008<sup>3</sup> |

<sup>1</sup> Full-API linked code, constants, and initialized data. Excludes runtime startup, RAM, and debug metadata. GCC 16.1 (Windows), 13.4 (Cortex-M), 14.2 (others). Uses LTO within the library.

<sup>2</sup> CCS_POLY=2 on Cortex-M, 3 on AVR, 1 elsewhere.

<sup>3</sup> Exceeds the ATmega328P's 32 KiB flash. 

## Benchmarks

### Ryzen 7 9800X3D

Windows 11 x86-64. GCC 16.1. LTO. MiB/s.

<table>
<thead>
<tr><th rowspan="2">Operation</th><th colspan="2">64 KiB</th><th colspan="2">1 KiB</th></tr>
<tr><th>-O3</th><th>-Os</th><th>-O3</th><th>-Os</th></tr>
</thead>
<tbody>
<tr><td>ChaCha20 IETF</td><td>1,246.1</td><td>457.6</td><td>1,147.5</td><td>457.8</td></tr>
<tr><td>ChaCha20 DJB</td><td>1,223.8</td><td>471.8</td><td>1,150.2</td><td>446.7</td></tr>
<tr><td>XChaCha20</td><td>1,228.5</td><td>467.3</td><td>1,063.8</td><td>425.3</td></tr>
<tr><td>ChaCha20-Poly1305 encrypt</td><td>906.9</td><td>406.8</td><td>800.5</td><td>357.9</td></tr>
<tr><td>ChaCha20-Poly1305 DJB encrypt</td><td>915.1</td><td>408.4</td><td>788.2</td><td>355.2</td></tr>
<tr><td>XChaCha20-Poly1305 encrypt</td><td>916.7</td><td>406.6</td><td>753.5</td><td>342.2</td></tr>
<tr><td>Poly1305</td><td>3,624.0</td><td>3,148.9</td><td>2,906.4</td><td>2,393.5</td></tr>
<tr><td>BLAKE2s-256</td><td>975.5</td><td>335.7</td><td>895.9</td><td>330.7</td></tr>
<tr><td>BLAKE2b-512</td><td>1,451.3</td><td>334.6</td><td>1,204.2</td><td>300.9</td></tr>
</tbody>
</table>

### STM32C031 

Inexpensive barebones ARM Cortex-M0+ microcontroller.

Pending

### ATMEGA328P

Legacy 8-bit Microcontroller on an Arduino Uno.

Pending

## Comparisons

Monocypher 4.0.3 · libsodium 1.0.22 · wolfCrypt 5.9.4. Same host, compiler, and workloads. Handwritten SIMD/assembly backends disabled for raw comparison.

### Code Size

Added bytes when statically linked, excluding the common baseline.<sup>1</sup> 

#### `-Os`, Bytes

| Requested operations | CCS | Monocypher | libsodium | wolfCrypt |
| --- | ---: | ---: | ---: | ---: |
| ChaCha20 IETF | 464 | 1,356 | 3,168 | 1,172 |
| ChaCha20 DJB | 448 | 1,288 | 3,184 | - |
| XChaCha20 | 752 | 1,528 | 3,728 | 2,140 |
| ChaCha20-Poly1305 IETF | 2,292 | 3,436 | 5,836 | 4,000 |
| ChaCha20-Poly1305 DJB | 2,148 | - | 5,660 | - |
| XChaCha20-Poly1305 | 2,552 | 3,480 | 6,412 | 4,964 |
| Poly1305 | 928 | 1,068 | 2,976 | 1,480 |
| BLAKE2s | 1,304 | - | - | 8,016 |
| BLAKE2b | 1,528 | 6,876 | 8,416 | 10,104 |
| Common suite<sup>2</sup> | 4,044 | 10,468 | 13,020 | 14,356 |

#### `-O3`, Bytes

| Requested operations | CCS | Monocypher | libsodium | wolfCrypt |
| --- | ---: | ---: | ---: | ---: |
| ChaCha20 IETF | 1,540 | 3,920 | 4,576 | 3,940 |
| ChaCha20 DJB | 1,636 | 3,856 | 4,576 | - |
| XChaCha20 | 2,372 | 4,176 | 5,120 | 6,820 |
| ChaCha20-Poly1305 IETF | 5,036 | 7,652 | 10,644 | 11,528 |
| ChaCha20-Poly1305 DJB | 4,976 | - | 10,468 | - |
| XChaCha20-Poly1305 | 5,876 | 7,896 | 11,348 | 12,620 |
| Poly1305 | 2,376 | 1,720 | 6,080 | 2,552 |
| BLAKE2s | 6,488 | - | - | 14,304 |
| BLAKE2b | 8,376 | 8,776 | 9,504 | 12,632 |
| Common suite<sup>2</sup> | 13,696 | 16,852 | 18,520 | 23,644 |

"\-" = Unsupported

<sup>1</sup> AEAD includes encrypt/decrypt; BLAKE2 includes keyed/unkeyed hashing. 

<sup>2</sup> Common suite: IETF ChaCha20, IETF AEAD, Poly1305, and BLAKE2b.

### Comparison Benchmarks

Handwritten SIMD and assembly disabled for raw comparison. Includes key setup and finalization. AEAD uses empty AD.

#### `-Os`, 64KiB Input, MiB/s

| Operation | CCS | Monocypher | libsodium | wolfCrypt |
| --- | ---: | ---: | ---: | ---: |
| ChaCha20 IETF | 474.5 | 956.1 | 1,175.6 | 1,002.6 |
| ChaCha20 DJB | 473.7 | 956.8 | 1,177.7 | - |
| XChaCha20 | 473.7 | 954.0 | 1,176.2 | 997.3 |
| ChaCha20-Poly1305 encrypt | 412.7 | 740.2 | 876.3 | 762.8 |
| ChaCha20-Poly1305 decrypt | 412.0 | 737.6 | 875.3 | 762.3 |
| ChaCha20-Poly1305 DJB encrypt | 410.7 | - | 876.6 | - |
| ChaCha20-Poly1305 DJB decrypt | 410.4 | - | 873.7 | - |
| XChaCha20-Poly1305 encrypt | 409.9 | 739.1 | 874.4 | 768.3 |
| XChaCha20-Poly1305 decrypt | 409.2 | 736.9 | 875.8 | 770.0 |
| Poly1305 | 3,180.2 | 3,299.2 | 3,443.1 | 3,234.8 |
| BLAKE2s-256 | 348.0 | - | - | 644.9 |
| BLAKE2s-256 keyed | 347.0 | - | - | 644.6 |
| BLAKE2b-512 | 332.6 | 1,292.4 | 1,443.5 | 1,034.1 |
| BLAKE2b-512 keyed | 332.2 | 1,287.0 | 1,435.8 | 1,031.3 |

#### `-O3`, 64KiB Input, MiB/s

| Operation | CCS | Monocypher | libsodium | wolfCrypt |
| --- | ---: | ---: | ---: | ---: |
| ChaCha20 IETF | 1,246.5 | 1,198.4 | 1,226.5 | 1,142.4 |
| ChaCha20 DJB | 1,242.2 | 1,199.7 | 1,224.9 | - |
| XChaCha20 | 1,239.8 | 1,197.6 | 1,224.4 | 1,141.4 |
| ChaCha20-Poly1305 encrypt | 927.0 | 899.0 | 903.9 | 861.0 |
| ChaCha20-Poly1305 decrypt | 926.0 | 899.0 | 903.6 | 860.8 |
| ChaCha20-Poly1305 DJB encrypt | 924.1 | - | 902.5 | - |
| ChaCha20-Poly1305 DJB decrypt | 924.0 | - | 902.8 | - |
| XChaCha20-Poly1305 encrypt | 922.8 | 898.1 | 903.4 | 859.0 |
| XChaCha20-Poly1305 decrypt | 922.2 | 898.2 | 900.8 | 858.7 |
| Poly1305 | 3,628.3 | 3,604.5 | 3,470.6 | 3,506.2 |
| BLAKE2s-256 | 990.6 | - | - | 1,136.6 |
| BLAKE2s-256 keyed | 990.0 | - | - | 1,134.2 |
| BLAKE2b-512 | 1,515.8 | 1,897.7 | 1,742.2 | 1,155.0 |
| BLAKE2b-512 keyed | 1,513.8 | 1,894.5 | 1,735.9 | 1,155.1 |

## Security
ChaChaSlide is not formally audited. Its implementations are validated against a large set of test vectors. All functions are constant time (on tested platforms with GCC), with the exception of Poly1305, which depends on the selected multiply implementation and CPU architecture (read below). While custom round counts are supported, this is intended for ChaCha8 and ChaCha12, which have been the subject of cryptanalysis. Using custom rounds is an experiment that this library supports.

<details>
<summary>About Constant Time Poly1305</summary>
Poly1305 relies on a 32->64 multiply, which may not be constant time in hardware or are implemented with variable time software helpers depending on the CPU architecture. This may expose Poly1305 to a side channel timing attacks.

ChaChaSlide has 3 implementations of the Poly1305 multiply to select, which will compile to constant time code depending on the platform and implementation used. Performance will be reduced.

Select `CCS_POLY` in `include/ccs_config.h`:

- **0: Off** Poly1305 is not exposed. However, using AEAD modes (ChaCha20-Poly1305) will default to the Generic implementation.
- **1: Generic:** Normal multiplication. Fastest choice on all platforms. Use on platforms that have constant time 32->64 multipliers. 
- **2: 32->32:** Forces 15-bit multiplies and will work on platforms with 32->32 multipliers. Best for inexpensive ARM Cortex-M microcontrollers (M0/M0+/M3).
- **3: 8-bit:** Optimized for 8-bit architectures with 16-bit accumulators. E.g. AVR, PIC.

| Platform | Recommended `CCS_POLY` selection |
| --- | --- |
| Modern x86-64 | 1 |
| Cortex-M0/M0+/M1/M3/M23 | 2 |
| Cortex-M4/M7 | 1 |
| Other Cortex and AArch64 | 1 or 2 |
| AVR with hardware multiply | 3 |
| PIC18 | 3 |
| Other without hardware multiply | Conditional |
| RISC-V | Conditional |

Monocypher, wolfCrypt and LibSodium do not guarantee constant time Poly1305 if the CPU does not have a constant time multiplier. The reduced speed of a constant time ChaChaSlide implementation is not directly comparable to a non constant time benchmark of a comparable library due to the potential side channel vulnerability.
</details>

## FAQ
- Can we go smaller: Yes! Quite a bit, but we lose a lot more performance and introduce some footguns (e.g. allowing counter overflow). 
- Can we go faster: A little bit. ChaChaSlide pushes the limits on my hardware, and the speedups are architecture dependant (e.g. taking advantage of 64-bit operations), and might displace code designed for -Os (e.g. loop unrolling and array-less computation). 
- Why not create two sources for size and speed optimized code: This is on the table, but one codebase keeps the project simpler.
- Why include BLAKE2: BLAKE2 is based on the core ChaCha ARX permutation and is compact. Win win.
- Why not BLAKE3: It may be added. 
- Is the project finished: The library is fully functional.

## References
[1] Y. Nir and A. Langley, “ChaCha20 and Poly1305 for IETF protocols,” RFC 8439, Jun. 2018, doi: [10.17487/RFC8439](https://doi.org/10.17487/RFC8439).

[2] D. J. Bernstein, “ChaCha, a variant of Salsa20,” Jan. 28, 2008. [Online]. Available: https://cr.yp.to/chacha/chacha-20080128.pdf

[3] S. Arciszewski, “XChaCha: eXtended-nonce ChaCha and AEAD_XChaCha20_Poly1305,” Internet-Draft draft-irtf-cfrg-xchacha-03, Jan. 2020, expired. [Online]. Available: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03

[4] The libsodium Project, “ChaCha20-Poly1305,” *The Sodium Crypto Library*. Accessed: Nov. 4, 2026. [Online]. Available: https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305

[5] M.-J. O. Saarinen and J.-P. Aumasson, “The BLAKE2 cryptographic hash and message authentication code (MAC),” RFC 7693, Nov. 2015, doi: [10.17487/RFC7693](https://doi.org/10.17487/RFC7693).
