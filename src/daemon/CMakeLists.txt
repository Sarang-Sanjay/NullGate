# src/daemon/CMakeLists.txt - Security Daemon Build Configuration

set(DAEMON_SOURCES
    main.c
    policy_loader.c
    attestation.c
)

add_executable(nullgate-daemon ${DAEMON_SOURCES})

# Ensure the BPF skeleton header is generated before compiling the daemon
add_dependencies(nullgate-daemon nullgate_bpf)

target_include_directories(nullgate-daemon PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_BINARY_DIR}/src/bpf
)

target_link_libraries(nullgate-daemon PRIVATE
    BPF::libbpf
    crypto
)

# Enforce Intel CET (IBT + SHSTK) on nullgate-daemon executable
verify_cet_target(nullgate-daemon)
