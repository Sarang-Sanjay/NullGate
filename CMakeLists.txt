cmake_minimum_required(VERSION 3.20)

# Project declaration with C, C++, and Assembly support
project(NullGate
    VERSION 0.1.0
    DESCRIPTION "Kernel-enforced domain compartmentalization & PKU memory isolation"
    LANGUAGES C CXX ASM
)

# Standard specifications
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Module path for custom Find packages
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

# Mandatory compiler and linker flags for Intel CET (IBT + SHSTK)
add_compile_options(
    $<$<COMPILE_LANGUAGE:C>:-Wall>
    $<$<COMPILE_LANGUAGE:C>:-Wextra>
    $<$<COMPILE_LANGUAGE:C>:-Werror>
    $<$<COMPILE_LANGUAGE:C>:-fcf-protection=full>
    $<$<COMPILE_LANGUAGE:C>:-mshstk>
    $<$<COMPILE_LANGUAGE:CXX>:-Wall>
    $<$<COMPILE_LANGUAGE:CXX>:-Wextra>
    $<$<COMPILE_LANGUAGE:CXX>:-Werror>
    $<$<COMPILE_LANGUAGE:CXX>:-fcf-protection=full>
    $<$<COMPILE_LANGUAGE:CXX>:-mshstk>
    $<$<COMPILE_LANGUAGE:ASM>:-fcf-protection=full>
    $<$<COMPILE_LANGUAGE:ASM>:-mshstk>
)

add_link_options(-fcf-protection=full)

# Global include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Discovery modules
include(VerifyCET)
find_package(BPF REQUIRED)
find_package(LLVM18 REQUIRED)

# Enable CTest framework
enable_testing()

# Project subdirectories
add_subdirectory(src/bpf)
add_subdirectory(src/daemon)
add_subdirectory(src/cli)
add_subdirectory(src/libnullgate)
add_subdirectory(src/scrubber)
if(LLVM18_FOUND)
    add_subdirectory(src/llvm-pass)
endif()
add_subdirectory(tests)
add_subdirectory(benchmarks)

