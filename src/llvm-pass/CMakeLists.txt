# src/llvm-pass/CMakeLists.txt - LLVM 18 Compiler Pass Build Pipeline

add_library(NullGatePass SHARED
    NullGatePass.cpp
)

target_include_directories(NullGatePass PRIVATE
    ${LLVM18_INCLUDE_DIRS}
    ${CMAKE_SOURCE_DIR}/include
)

target_compile_options(NullGatePass PRIVATE
    -fno-rtti
    -Wno-unused-parameter
)

set_target_properties(NullGatePass PROPERTIES
    PREFIX "lib"
    OUTPUT_NAME "NullGatePass"
)

verify_cet_target(NullGatePass)
