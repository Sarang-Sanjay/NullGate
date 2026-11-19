# FindLLVM18.cmake - Locates LLVM 18 development files and sets up LLVMConfig

# 1. Locate llvm-config (prefer llvm-config-18)
find_program(LLVM_CONFIG_EXECUTABLE
    NAMES llvm-config-18 llvm-config
    DOC "Path to llvm-config-18 tool"
)

if(LLVM_CONFIG_EXECUTABLE)
    execute_process(
        COMMAND "${LLVM_CONFIG_EXECUTABLE}" --version
        OUTPUT_VARIABLE LLVM_RAW_VERSION
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
    )

    execute_process(
        COMMAND "${LLVM_CONFIG_EXECUTABLE}" --cmakedir
        OUTPUT_VARIABLE LLVM_CMAKEDIR
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
    )

    execute_process(
        COMMAND "${LLVM_CONFIG_EXECUTABLE}" --includedir
        OUTPUT_VARIABLE LLVM_INCLUDEDIR
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
    )

    execute_process(
        COMMAND "${LLVM_CONFIG_EXECUTABLE}" --libdir
        OUTPUT_VARIABLE LLVM_LIBDIR
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
    )

    execute_process(
        COMMAND "${LLVM_CONFIG_EXECUTABLE}" --cxxflags
        OUTPUT_VARIABLE LLVM_CXXFLAGS
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
    )

    string(REGEX MATCH "^[0-9]+" LLVM_MAJOR "${LLVM_RAW_VERSION}")
    if(LLVM_MAJOR EQUAL 18)
        set(LLVM18_VERSION "${LLVM_RAW_VERSION}")
        set(LLVM18_INCLUDE_DIRS "${LLVM_INCLUDEDIR}")
        set(LLVM18_LIBRARY_DIRS "${LLVM_LIBDIR}")
        set(LLVM18_CMAKEDIR "${LLVM_CMAKEDIR}")
        set(LLVM18_CXX_FLAGS "${LLVM_CXXFLAGS}")
        set(LLVM_DIR "${LLVM_CMAKEDIR}")
    endif()
endif()

# Fallback: check standard paths if llvm-config not in path
if(NOT LLVM18_CMAKEDIR AND EXISTS "/usr/lib/llvm-18/lib/cmake/llvm")
    set(LLVM_DIR "/usr/lib/llvm-18/lib/cmake/llvm")
    set(LLVM18_CMAKEDIR "/usr/lib/llvm-18/lib/cmake/llvm")
    set(LLVM18_INCLUDE_DIRS "/usr/lib/llvm-18/include")
    set(LLVM18_LIBRARY_DIRS "/usr/lib/llvm-18/lib")
    set(LLVM18_VERSION "18.1.3")
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(LLVM18
    REQUIRED_VARS LLVM18_INCLUDE_DIRS LLVM18_CMAKEDIR LLVM18_VERSION
    VERSION_VAR LLVM18_VERSION
)

if(LLVM18_FOUND)
    # Forward to native CMake LLVM package configuration when building pass
    if(NOT LLVM_FOUND AND EXISTS "${LLVM18_CMAKEDIR}/LLVMConfig.cmake")
        find_package(LLVM 18 QUIET CONFIG HINTS "${LLVM18_CMAKEDIR}")
    endif()
endif()
