cmake_minimum_required(VERSION 3.20)

# Project declaration with C, C++, and Assembly support
project(NullGate
    VERSION 1.0.0
    DESCRIPTION "Hardware-Enforced Intra-Process Systems Compartmentalization Platform"
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
include(GNUInstallDirs)

# Mandatory compiler and linker flags for Intel CET (IBT + SHSTK)
add_compile_options(
    $<$<COMPILE_LANGUAGE:C>:-Wall>
    $<$<COMPILE_LANGUAGE:C>:-Wextra>
    $<$<COMPILE_LANGUAGE:C>:-Werror>
    $<$<COMPILE_LANGUAGE:C>:-fcf-protection=full>
    $<$<COMPILE_LANGUAGE:C>:-mshstk>
    $<$<COMPILE_LANGUAGE:C>:-fstack-protector-all>
    $<$<COMPILE_LANGUAGE:CXX>:-Wall>
    $<$<COMPILE_LANGUAGE:CXX>:-Wextra>
    $<$<COMPILE_LANGUAGE:CXX>:-Werror>
    $<$<COMPILE_LANGUAGE:CXX>:-fcf-protection=full>
    $<$<COMPILE_LANGUAGE:CXX>:-mshstk>
    $<$<COMPILE_LANGUAGE:CXX>:-fstack-protector-all>
    $<$<COMPILE_LANGUAGE:ASM>:-fcf-protection=full>
    $<$<COMPILE_LANGUAGE:ASM>:-mshstk>
)

add_link_options(-fcf-protection=full -Wl,-z,relro,-z,now)

# Global include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Discovery modules
include(VerifyCET)
find_package(BPF REQUIRED)
find_package(LLVM18 REQUIRED)

# Option for test suite compilation
option(BUILD_TESTING "Build the automated test suite" ON)

# Project subdirectories
add_subdirectory(src/bpf)
add_subdirectory(src/daemon)
add_subdirectory(src/cli)
add_subdirectory(src/libnullgate)
add_subdirectory(src/scrubber)
if(LLVM18_FOUND)
    add_subdirectory(src/llvm-pass)
endif()

if(BUILD_TESTING)
    enable_testing()
    add_subdirectory(tests)
endif()

add_subdirectory(benchmarks)

# ------------------------------------------------------------------------------
# Installation Rules & Pkg-Config Generation
# ------------------------------------------------------------------------------

# Generate and install pkg-config definition
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/nullgate.pc.in"
    "${CMAKE_CURRENT_BINARY_DIR}/nullgate.pc"
    @ONLY
)

install(FILES "${CMAKE_CURRENT_BINARY_DIR}/nullgate.pc"
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig"
)

# Install public headers
install(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/include/"
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/nullgate"
    FILES_MATCHING PATTERN "*.h"
)

# Install umbrella header directly to includedir
install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/include/nullgate.h"
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
)

# Install shared and static runtime libraries
install(TARGETS nullgate nullgate_static nullgate_shim
    EXPORT NullGateTargets
    LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
    INCLUDES DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
)

# Install administrative daemon, CLI, and static scrubber binaries
install(TARGETS nullgate-daemon nullgate-ctl nullgate-scrubber
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
)
