# src/cli/CMakeLists.txt - Administrative CLI Build Configuration

add_executable(nullgate-ctl nullgate_ctl.c)

target_include_directories(nullgate-ctl PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

# Enforce Intel CET (IBT + SHSTK) on nullgate-ctl
verify_cet_target(nullgate-ctl)
