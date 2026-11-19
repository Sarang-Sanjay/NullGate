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

# 9. CET ELF Note & Stack Non-Executability Audit Test (All Binaries)
add_test(
    NAME test_cet_note
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/unit/test_cet_note.sh
        $<TARGET_FILE:nullgate-daemon>
        $<TARGET_FILE:nullgate>
        $<TARGET_FILE:test_pku>
        $<TARGET_FILE:test_callgate>
        $<TARGET_FILE:stress_test_suite>
        $<TARGET_FILE:test_anti_snoop>
        $<TARGET_FILE:test_self_tamper>
        $<TARGET_FILE:test_fork_inheritance>
        $<TARGET_FILE:test_mmap_wx>
        $<TARGET_FILE:phase2_stress_test_suite>
)
