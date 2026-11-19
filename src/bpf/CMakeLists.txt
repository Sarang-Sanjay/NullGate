# src/bpf/CMakeLists.txt - eBPF Subsystem Build Configuration

# Source files for NullGate BPF subsystem
set(BPF_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/nullgate_lsm.bpf.c
    ${CMAKE_CURRENT_SOURCE_DIR}/nullgate_uring.bpf.c
    ${CMAKE_CURRENT_SOURCE_DIR}/nullgate_sync.bpf.c
)

# Header dependencies for BPF compilation (auto-rebuild on header change)
set(BPF_HEADERS
    ${CMAKE_SOURCE_DIR}/include/nullgate_abi.h
    ${CMAKE_SOURCE_DIR}/include/nullgate_policy.h
    ${CMAKE_CURRENT_SOURCE_DIR}/nullgate_maps.bpf.h
    ${CMAKE_CURRENT_SOURCE_DIR}/nullgate_helpers.bpf.h
    ${CMAKE_CURRENT_SOURCE_DIR}/nullgate_snoop.bpf.h
    ${CMAKE_CURRENT_SOURCE_DIR}/nullgate_tamper.bpf.h
    ${CMAKE_CURRENT_SOURCE_DIR}/nullgate_lifecycle.bpf.h
    ${CMAKE_CURRENT_SOURCE_DIR}/nullgate_mprotect.bpf.h
)

# Include paths required for BPF compilation
set(BPF_INCLUDES
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# Target directory for generated skeleton header
set(BPF_SKEL_DIR "${CMAKE_BINARY_DIR}/src/bpf")

# Invoke add_bpf_program defined in cmake/FindBPF.cmake:
# 1. Compiles each *.bpf.c to individual *.bpf.o
# 2. Links all *.bpf.o into unified nullgate.bpf.o via 'bpftool gen object'
# 3. Emits unified nullgate.skel.h via 'bpftool gen skeleton'
add_bpf_program(nullgate
    SOURCES ${BPF_SOURCES}
    HEADERS ${BPF_HEADERS}
    INCLUDES ${BPF_INCLUDES}
    OUTPUT_DIR ${BPF_SKEL_DIR}
)
