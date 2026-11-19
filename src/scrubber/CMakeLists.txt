# src/scrubber/CMakeLists.txt - Static ELF Scrubber & Binary Sanitizer Build

# Scrubber static library for CLI and unit tests
add_library(nullgate_scrubber_lib STATIC
    elf_scrubber.c
)

target_include_directories(nullgate_scrubber_lib
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/include
)

# Standalone CLI binary: nullgate-scrubber
add_executable(nullgate-scrubber
    main.c
)

target_link_libraries(nullgate-scrubber PRIVATE
    nullgate_scrubber_lib
)

target_include_directories(nullgate-scrubber PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/include
)

verify_cet_target(nullgate-scrubber)
