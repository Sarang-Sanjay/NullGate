# FindBPF.cmake - Locates bpftool, libbpf, Clang BPF compiler and defines add_bpf_program()

find_package(PkgConfig QUIET)

# 1. Locate bpftool
find_program(BPFTOOL_EXECUTABLE
    NAMES bpftool
    DOC "Path to bpftool executable"
)

# 2. Locate Clang for BPF target (prefer clang-18)
find_program(CLANG_BPF_EXECUTABLE
    NAMES clang-18 clang
    DOC "Path to Clang compiler supporting -target bpf"
)

# 3. Locate libbpf headers and library
if(PKG_CONFIG_FOUND)
    pkg_check_modules(PC_LIBBPF QUIET libbpf)
endif()

find_path(LIBBPF_INCLUDE_DIRS
    NAMES bpf/libbpf.h
    HINTS ${PC_LIBBPF_INCLUDEDIR} ${PC_LIBBPF_INCLUDE_DIRS}
    PATHS /usr/include /usr/local/include
)

find_library(LIBBPF_LIBRARIES
    NAMES bpf
    HINTS ${PC_LIBBPF_LIBDIR} ${PC_LIBBPF_LIBRARY_DIRS}
    PATHS /usr/lib /usr/local/lib /usr/lib/x86_64-linux-gnu
)

# Extract libbpf version if possible
if(LIBBPF_INCLUDE_DIRS AND EXISTS "${LIBBPF_INCLUDE_DIRS}/bpf/libbpf_version.h")
    file(STRINGS "${LIBBPF_INCLUDE_DIRS}/bpf/libbpf_version.h" LIBBPF_MAJOR_LINE REGEX "^#define[ \t]+LIBBPF_MAJOR_VERSION[ \t]+[0-9]+")
    file(STRINGS "${LIBBPF_INCLUDE_DIRS}/bpf/libbpf_version.h" LIBBPF_MINOR_LINE REGEX "^#define[ \t]+LIBBPF_MINOR_VERSION[ \t]+[0-9]+")
    string(REGEX MATCH "[0-9]+" LIBBPF_MAJOR "${LIBBPF_MAJOR_LINE}")
    string(REGEX MATCH "[0-9]+" LIBBPF_MINOR "${LIBBPF_MINOR_LINE}")
    set(LIBBPF_VERSION "${LIBBPF_MAJOR}.${LIBBPF_MINOR}")
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(BPF
    REQUIRED_VARS BPFTOOL_EXECUTABLE CLANG_BPF_EXECUTABLE LIBBPF_LIBRARIES LIBBPF_INCLUDE_DIRS
    VERSION_VAR LIBBPF_VERSION
)

if(BPF_FOUND)
    if(NOT TARGET BPF::libbpf)
        add_library(BPF::libbpf UNKNOWN IMPORTED)
        set_target_properties(BPF::libbpf PROPERTIES
            IMPORTED_LOCATION "${LIBBPF_LIBRARIES}"
            INTERFACE_INCLUDE_DIRECTORIES "${LIBBPF_INCLUDE_DIRS}"
        )
    endif()
endif()

#
# add_bpf_program:
# Compiles each .bpf.c source into an individual .bpf.o object,
# links them into a single unified .bpf.o via 'bpftool gen object',
# and generates a single unified .skel.h skeleton header via 'bpftool gen skeleton'.
#
function(add_bpf_program TARGET_NAME)
    cmake_parse_arguments(ARG "" "OUTPUT_DIR" "SOURCES;INCLUDES;HEADERS" ${ARGN})

    if(NOT ARG_SOURCES)
        message(FATAL_ERROR "add_bpf_program(${TARGET_NAME}): No SOURCES specified.")
    endif()

    if(NOT ARG_OUTPUT_DIR)
        set(ARG_OUTPUT_DIR "${CMAKE_CURRENT_BINARY_DIR}")
    endif()

    file(MAKE_DIRECTORY "${ARG_OUTPUT_DIR}")

    # Build include flags for clang BPF invocation
    set(BPF_INC_FLAGS "")
    foreach(inc_dir ${ARG_INCLUDES})
        list(APPEND BPF_INC_FLAGS "-I${inc_dir}")
    endforeach()

    set(BPF_OBJS "")

    # Compile each .bpf.c to individual .bpf.o
    foreach(src ${ARG_SOURCES})
        get_filename_component(src_abs "${src}" ABSOLUTE)
        get_filename_component(src_we "${src}" NAME_WE)
        set(obj_out "${CMAKE_CURRENT_BINARY_DIR}/${src_we}.bpf.o")

        add_custom_command(
            OUTPUT "${obj_out}"
            COMMAND "${CLANG_BPF_EXECUTABLE}"
                    -target bpf
                    -D__BPF__
                    -O2 -g
                    -Wall -Werror
                    -Wno-missing-declarations
                    -Wno-compare-distinct-pointer-types
                    ${BPF_INC_FLAGS}
                    -c "${src_abs}"
                    -o "${obj_out}"
            DEPENDS "${src_abs}" ${ARG_HEADERS}
            COMMENT "[BPF] Compiling ${src} -> ${src_we}.bpf.o"
            VERBATIM
        )
        list(APPEND BPF_OBJS "${obj_out}")
    endforeach()

    # Link all .bpf.o into unified object
    set(UNIFIED_BPF_OBJ "${CMAKE_CURRENT_BINARY_DIR}/${TARGET_NAME}.bpf.o")
    add_custom_command(
        OUTPUT "${UNIFIED_BPF_OBJ}"
        COMMAND "${BPFTOOL_EXECUTABLE}" gen object "${UNIFIED_BPF_OBJ}" ${BPF_OBJS}
        DEPENDS ${BPF_OBJS}
        COMMENT "[BPF] Linking unified object ${TARGET_NAME}.bpf.o via bpftool"
        VERBATIM
    )

    # Generate skeleton header from unified object
    set(SKEL_HEADER "${ARG_OUTPUT_DIR}/${TARGET_NAME}.skel.h")
    add_custom_command(
        OUTPUT "${SKEL_HEADER}"
        COMMAND "${BPFTOOL_EXECUTABLE}" gen skeleton "${UNIFIED_BPF_OBJ}" > "${SKEL_HEADER}"
        DEPENDS "${UNIFIED_BPF_OBJ}"
        COMMENT "[BPF] Generating skeleton ${TARGET_NAME}.skel.h via bpftool"
        VERBATIM
    )

    # Custom target for this BPF program
    add_custom_target(${TARGET_NAME}_bpf ALL
        DEPENDS "${SKEL_HEADER}"
    )

    set_target_properties(${TARGET_NAME}_bpf PROPERTIES
        UNIFIED_OBJECT "${UNIFIED_BPF_OBJ}"
        SKELETON_HEADER "${SKEL_HEADER}"
    )
endfunction()
