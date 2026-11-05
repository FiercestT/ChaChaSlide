set(CCS_BENCHMARK_SOURCES
    main.c
    benchmark_blake2s.c
    benchmark_blake2b.c
    benchmark_chacha20_ietf.c
    benchmark_chacha20_djb.c
    benchmark_xchacha20.c
    benchmark_poly1305.c
    benchmark_chacha20_poly1305_ietf.c
    benchmark_chacha20_poly1305_djb.c
    benchmark_xchacha20_poly1305.c
)

foreach(mode IN ITEMS size speed)
    set(target benchmark-${mode})
    add_executable(${target} ${CCS_BENCHMARK_SOURCES})
    target_link_libraries(${target} PRIVATE ccs-${mode})
    target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic)
    if(mode STREQUAL "size")
        target_compile_options(${target} PRIVATE -Os)
    else()
        target_compile_options(${target} PRIVATE -O3)
    endif()
    set_target_properties(${target} PROPERTIES
        C_STANDARD 99
        C_STANDARD_REQUIRED YES
        C_EXTENSIONS NO
    )
endforeach()
