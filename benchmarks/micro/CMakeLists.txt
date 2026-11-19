# benchmarks/micro/CMakeLists.txt - Call-Gate & Syscall Micro-benchmarks
# Intel CET & Optimization Enforcement

add_executable(bench_callgate_rdtscp bench_callgate_rdtscp.c)
target_include_directories(bench_callgate_rdtscp PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/src/libnullgate
)
target_link_libraries(bench_callgate_rdtscp PRIVATE
    nullgate
    m
)
target_compile_options(bench_callgate_rdtscp PRIVATE
    -O3
    -fcf-protection=full
    -Wall
    -Wextra
)
verify_cet_target(bench_callgate_rdtscp)

add_executable(bench_syscall_lsm bench_syscall_lsm.c)
target_include_directories(bench_syscall_lsm PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/src/libnullgate
)
target_link_libraries(bench_syscall_lsm PRIVATE
    nullgate
    m
)
target_compile_options(bench_syscall_lsm PRIVATE
    -O3
    -fcf-protection=full
    -Wall
    -Wextra
)
verify_cet_target(bench_syscall_lsm)

add_executable(bench_ipc_latency bench_ipc_latency.c)
target_include_directories(bench_ipc_latency PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/src/libnullgate
)
target_link_libraries(bench_ipc_latency PRIVATE
    nullgate
    m
)
target_compile_options(bench_ipc_latency PRIVATE
    -O3
    -fcf-protection=full
    -Wall
    -Wextra
)
verify_cet_target(bench_ipc_latency)
