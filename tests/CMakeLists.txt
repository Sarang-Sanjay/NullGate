# tests/CMakeLists.txt - Unit Test Build & CTest Configuration
# Phase 1 & Phase 2 Test Targets with Intel CET & NX Stack Verification

# 1. PKU Unit Test
add_executable(test_pku unit/test_pku.c)
target_link_libraries(test_pku PRIVATE nullgate)
verify_cet_target(test_pku)
add_test(NAME test_pku COMMAND test_pku)

# 2. Callgate Unit Test
add_executable(test_callgate unit/test_callgate.c)
target_link_libraries(test_callgate PRIVATE nullgate)
verify_cet_target(test_callgate)
add_test(NAME test_callgate COMMAND test_callgate)

# 3. Adversarial Stress & Vulnerability Test Suite
add_executable(stress_test_suite
    stress/stress_test_suite.c
    stress/adversarial_compartment.S
)
target_link_libraries(stress_test_suite PRIVATE nullgate pthread)
verify_cet_target(stress_test_suite)
add_test(NAME stress_test_suite COMMAND stress_test_suite)

# 4. Anti-Snooping Unit Test (Pillar 2)
add_executable(test_anti_snoop unit/test_anti_snoop.c)
target_link_libraries(test_anti_snoop PRIVATE nullgate)
verify_cet_target(test_anti_snoop)
add_test(NAME test_anti_snoop COMMAND test_anti_snoop)

# 5. Self-Tampering Unit Test (Pillar 3)
add_executable(test_self_tamper unit/test_self_tamper.c)
target_link_libraries(test_self_tamper PRIVATE nullgate)
verify_cet_target(test_self_tamper)
add_test(NAME test_self_tamper COMMAND test_self_tamper)

# 6. Fork Inheritance Unit Test (Pillar 6)
add_executable(test_fork_inheritance unit/test_fork_inheritance.c)
target_link_libraries(test_fork_inheritance PRIVATE nullgate)
verify_cet_target(test_fork_inheritance)
add_test(NAME test_fork_inheritance COMMAND test_fork_inheritance)

# 7. W^X Memory Protection Unit Test (Pillar 8)
add_executable(test_mmap_wx unit/test_mmap_wx.c)
target_link_libraries(test_mmap_wx PRIVATE nullgate)
verify_cet_target(test_mmap_wx)
add_test(NAME test_mmap_wx COMMAND test_mmap_wx)

# 8. Phase 2 Ultra-Intense Adversarial Stress Test Suite
add_executable(phase2_stress_test_suite stress/phase2_stress_test_suite.c)
target_link_libraries(phase2_stress_test_suite PRIVATE nullgate pthread)
verify_cet_target(phase2_stress_test_suite)
add_test(NAME phase2_stress_test_suite COMMAND phase2_stress_test_suite)

# 9. ELF Scrubber Unit Test (Pillar 4)
add_executable(test_scrubber unit/test_scrubber.c)
target_link_libraries(test_scrubber PRIVATE nullgate_scrubber_lib)
target_include_directories(test_scrubber PRIVATE ${CMAKE_SOURCE_DIR}/src/scrubber)
verify_cet_target(test_scrubber)
add_test(NAME test_scrubber COMMAND test_scrubber)

# 10. Asynchronous Signal & Altstack Unit Test (Pillar 5)
add_executable(test_signal unit/test_signal.c)
target_link_libraries(test_signal PRIVATE nullgate)
verify_cet_target(test_signal)
add_test(NAME test_signal COMMAND test_signal)

# 11. CET ELF Note & Stack Non-Executability Audit Test (All Binaries)
add_test(
    NAME test_cet_note
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/unit/test_cet_note.sh
        $<TARGET_FILE:nullgate-daemon>
        $<TARGET_FILE:nullgate-scrubber>
        $<TARGET_FILE:nullgate>
        $<TARGET_FILE:test_pku>
        $<TARGET_FILE:test_callgate>
        $<TARGET_FILE:stress_test_suite>
        $<TARGET_FILE:test_anti_snoop>
        $<TARGET_FILE:test_self_tamper>
        $<TARGET_FILE:test_fork_inheritance>
        $<TARGET_FILE:test_mmap_wx>
        $<TARGET_FILE:phase2_stress_test_suite>
        $<TARGET_FILE:test_scrubber>
        $<TARGET_FILE:test_signal>
        $<TARGET_FILE:test_ptrace_proc>
        $<TARGET_FILE:test_bpf_seccomp_tamper>
        $<TARGET_FILE:test_sigreturn_forge>
        $<TARGET_FILE:test_uring_escape>
        $<TARGET_FILE:test_confused_deputy>
        $<TARGET_FILE:bench_callgate_rdtscp>
        $<TARGET_FILE:bench_syscall_lsm>
        $<TARGET_FILE:phase3_stress_test_suite>
        $<TARGET_FILE:test_ipc>
        $<TARGET_FILE:bench_ipc_latency>
        $<TARGET_FILE:test_sqlite_sandbox>
        $<TARGET_FILE:bench_sqlite_runner>
)

# 12. LLVM 18 Compiler Pass Integration Test (Pillar 4)
if(LLVM18_FOUND)
    add_test(
        NAME test_llvm_pass
        COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/unit/test_llvm_pass.sh
            $<TARGET_FILE:NullGatePass>
    )
endif()

# 13. Red-Team: Adversarial Procfs & Ptrace Snooping Test (Pillar 2, Group F)
add_executable(test_ptrace_proc security/test_ptrace_proc.c)
target_link_libraries(test_ptrace_proc PRIVATE nullgate)
verify_cet_target(test_ptrace_proc)
add_test(NAME test_ptrace_proc COMMAND test_ptrace_proc)

# 14. Red-Team: BPF & Seccomp Self-Tampering Penetration Test (Pillar 3, Group F)
add_executable(test_bpf_seccomp_tamper security/test_bpf_seccomp_tamper.c)
target_link_libraries(test_bpf_seccomp_tamper PRIVATE nullgate)
verify_cet_target(test_bpf_seccomp_tamper)
add_test(NAME test_bpf_seccomp_tamper COMMAND test_bpf_seccomp_tamper)

# 15. Red-Team: SROP Sigreturn Forgery Attack Test (Pillar 5, Group F)
add_executable(test_sigreturn_forge security/test_sigreturn_forge.c)
target_link_libraries(test_sigreturn_forge PRIVATE nullgate)
verify_cet_target(test_sigreturn_forge)
add_test(NAME test_sigreturn_forge COMMAND test_sigreturn_forge)

# 16. Red-Team: io_uring Compartment Escape Attack Test (Pillar 7, Group F)
add_executable(test_uring_escape security/test_uring_escape.c)
target_link_libraries(test_uring_escape PRIVATE nullgate)
verify_cet_target(test_uring_escape)
add_test(NAME test_uring_escape COMMAND test_uring_escape)

# 17. Red-Team: Confused Deputy Syscall Infiltration Test (Pillar 7, Group F)
add_executable(test_confused_deputy security/test_confused_deputy.c)
target_link_libraries(test_confused_deputy PRIVATE nullgate)
verify_cet_target(test_confused_deputy)
add_test(NAME test_confused_deputy COMMAND test_confused_deputy)

# 18. Phase 3 Ultra-Intense Adversarial Stress Test Suite
add_executable(phase3_stress_test_suite stress/phase3_stress_test_suite.c)
target_include_directories(phase3_stress_test_suite PRIVATE ${CMAKE_SOURCE_DIR}/src/scrubber)
target_link_libraries(phase3_stress_test_suite PRIVATE nullgate nullgate_scrubber_lib pthread)
verify_cet_target(phase3_stress_test_suite)
add_test(NAME phase3_stress_test_suite COMMAND phase3_stress_test_suite)

# 19. Hardware-Isolated Stack Pool Unit Test (Pillars 1, 4, 5, Group B)
add_executable(test_stack_pool unit/test_stack_pool.c)
target_link_libraries(test_stack_pool PRIVATE nullgate pthread)
verify_cet_target(test_stack_pool)
add_test(NAME test_stack_pool COMMAND test_stack_pool)

# 20. Transparent Library Interposition & Shim Unit Test (Pillars 1, 4, 5, Group B)
add_library(mock_target SHARED unit/mock_target.c)
verify_cet_target(mock_target)

add_executable(test_shim unit/test_shim.c)
target_link_libraries(test_shim PRIVATE nullgate nullgate_shim mock_target pthread ${CMAKE_DL_LIBS})
verify_cet_target(test_shim)
add_test(NAME test_shim COMMAND test_shim)

# 21. Zero-Copy Hardware PKU SPSC IPC Unit Test (Pillars 1, 7, Group C)
add_executable(test_ipc unit/test_ipc.c)
target_link_libraries(test_ipc PRIVATE nullgate pthread)
verify_cet_target(test_ipc)
add_test(NAME test_ipc COMMAND test_ipc)

# 22. SQLite UDF Multi-Vector Escape Penetration Test (Pillars 1, 2, 7, Group D)
add_executable(test_sqlite_sandbox security/test_sqlite_sandbox.c)
target_include_directories(test_sqlite_sandbox PRIVATE
    ${PROJECT_SOURCE_DIR}/benchmarks/sqlite
)
target_link_libraries(test_sqlite_sandbox PRIVATE nullgate_sqlite nullgate pthread)
verify_cet_target(test_sqlite_sandbox)
add_test(NAME test_sqlite_sandbox COMMAND test_sqlite_sandbox)

# 23. Phase 4 Ultra-Intense Concurrency, Fuzzing & Key Recycling Stress Test (Group E)
add_executable(phase4_stress_test_suite stress/phase4_stress_test_suite.c)
target_include_directories(phase4_stress_test_suite PRIVATE
    ${PROJECT_SOURCE_DIR}/src/libnullgate
)
target_link_libraries(phase4_stress_test_suite PRIVATE nullgate pthread)
verify_cet_target(phase4_stress_test_suite)
add_test(NAME phase4_stress_test_suite COMMAND phase4_stress_test_suite)

# 24. Repository-Wide Comprehensive Security Audit Test (Pillars 1-8, Group E, Step 19)
add_executable(test_complete_audit
    security/test_complete_audit.c
    ${PROJECT_SOURCE_DIR}/src/daemon/policy_parser.c
)
target_include_directories(test_complete_audit PRIVATE
    ${PROJECT_SOURCE_DIR}/src/libnullgate
    ${PROJECT_SOURCE_DIR}/src/scrubber
    ${PROJECT_SOURCE_DIR}/src/daemon
)
target_link_libraries(test_complete_audit PRIVATE nullgate nullgate_scrubber_lib pthread)
verify_cet_target(test_complete_audit)
add_test(NAME test_complete_audit COMMAND test_complete_audit)



