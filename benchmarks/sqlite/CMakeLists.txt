# benchmarks/sqlite/CMakeLists.txt - SQLite UDF Compartment Subsystem

add_library(nullgate_sqlite STATIC sqlite_compartment.c)

target_include_directories(nullgate_sqlite
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${PROJECT_SOURCE_DIR}/include
    PRIVATE
        ${PROJECT_SOURCE_DIR}/src/libnullgate
)

target_link_libraries(nullgate_sqlite PRIVATE
    nullgate
    pthread
)

target_compile_options(nullgate_sqlite PRIVATE
    -O3
    -fcf-protection=full
    -Wall
    -Wextra
    -Werror
)

verify_cet_target(nullgate_sqlite)

add_executable(bench_sqlite_runner bench_sqlite_runner.c)

target_include_directories(bench_sqlite_runner PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/src/libnullgate
)

target_link_libraries(bench_sqlite_runner PRIVATE
    nullgate_sqlite
    nullgate
    pthread
    m
)

target_compile_options(bench_sqlite_runner PRIVATE
    -O3
    -fcf-protection=full
    -Wall
    -Wextra
    -Werror
)

verify_cet_target(bench_sqlite_runner)
