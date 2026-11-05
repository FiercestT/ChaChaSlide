cmake_minimum_required(VERSION 3.16)
project(ChaChaSlide LANGUAGES C)

option(BUILD_TESTING "Build tests" OFF)
option(BUILD_BENCHMARKS "Build the benchmark runner" OFF)

if(NOT DEFINED CMAKE_INTERPROCEDURAL_OPTIMIZATION)
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION ON)
endif()
if(CMAKE_INTERPROCEDURAL_OPTIMIZATION)
    include(CheckIPOSupported)
    check_ipo_supported(RESULT CCS_IPO_SUPPORTED OUTPUT CCS_IPO_ERROR LANGUAGES C)
    if(NOT CCS_IPO_SUPPORTED)
        message(STATUS "LTO unavailable; building without it: ${CCS_IPO_ERROR}")
        set(CMAKE_INTERPROCEDURAL_OPTIMIZATION OFF)
    endif()
endif()

set(CCS_SOURCES
    src/ccs_blake2.c
    src/ccs_chacha.c
    src/ccs_chacha_poly1305.c
    src/ccs_poly1305.c
    src/ccs_xchacha.c
    src/ccs_xchacha_poly1305.c
)

add_library(ccs-size STATIC ${CCS_SOURCES})
add_library(ccs-speed STATIC ${CCS_SOURCES})

foreach(target IN ITEMS ccs-size ccs-speed)
    target_include_directories(${target} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
    set_target_properties(${target} PROPERTIES
        C_STANDARD 99
        C_STANDARD_REQUIRED YES
        C_EXTENSIONS NO
    )
    target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic)
endforeach()

target_compile_options(ccs-size PRIVATE -Os)
target_compile_options(ccs-speed PRIVATE -O3)

if(BUILD_TESTING)
    include(CTest)
    add_subdirectory(test)
endif()

if(BUILD_BENCHMARKS)
    add_subdirectory(benchmark)
endif()
