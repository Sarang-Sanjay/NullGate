# src/libnullgate/CMakeLists.txt - Userspace Compartmentalization Runtime Build

set(LIBNULLGATE_SOURCES
    init.c
    pku.c
    callgate.S
    signal.c
    signal_trampoline.S
    stack_pool.c
    ipc.c
)

# Shared library: libnullgate.so
add_library(nullgate SHARED ${LIBNULLGATE_SOURCES})

target_include_directories(nullgate
    PUBLIC
        ${CMAKE_SOURCE_DIR}/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
)

# Static library: libnullgate.a
add_library(nullgate_static STATIC ${LIBNULLGATE_SOURCES})
set_target_properties(nullgate_static PROPERTIES OUTPUT_NAME nullgate)

target_include_directories(nullgate_static
    PUBLIC
        ${CMAKE_SOURCE_DIR}/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
)

# Enforce Intel CET (IBT + SHSTK) on libnullgate.so
verify_cet_target(nullgate)

# Transparent Interposition Shim Library: libnullgate_shim.so
add_library(nullgate_shim SHARED shim.c)

target_include_directories(nullgate_shim
    PUBLIC
        ${CMAKE_SOURCE_DIR}/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(nullgate_shim PRIVATE
    nullgate
    ${CMAKE_DL_LIBS}
)

# Enforce Intel CET (IBT + SHSTK) on libnullgate_shim.so
verify_cet_target(nullgate_shim)
