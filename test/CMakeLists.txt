set(CCS_TESTS
    blake2s
    blake2b
    chacha_ietf
    chacha_djb
    hchacha
    xchacha
    poly1305
    chacha_poly1305_ietf
    chacha_poly1305_djb
    xchacha_poly1305
)

foreach(algo IN LISTS CCS_TESTS)
    foreach(mode IN ITEMS size speed)
        set(target test-${algo}-${mode})
        add_executable(${target} test_${algo}.c)
        target_link_libraries(${target} PRIVATE ccs-${mode})
        target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic)
        set_target_properties(${target} PROPERTIES
            C_STANDARD 99
            C_STANDARD_REQUIRED YES
            C_EXTENSIONS NO
        )
        add_test(NAME ${algo}-${mode} COMMAND ${target})
        set_tests_properties(${algo}-${mode} PROPERTIES SKIP_RETURN_CODE 77)
    endforeach()
endforeach()
