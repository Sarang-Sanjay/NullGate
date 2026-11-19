# VerifyCET.cmake - Enforces post-build Intel CET (IBT + SHSTK) ELF note verification

find_program(READELF_EXECUTABLE
    NAMES readelf
    DOC "Path to GNU readelf for inspecting ELF program notes"
)

#
# verify_cet_target(TARGET_NAME):
# Attaches a POST_BUILD command to the specified executable or shared library target.
# Runs 'readelf -n' on the target file and asserts that both 'IBT' and 'SHSTK'
# are present in the GNU_PROPERTY_X86_FEATURE_1_AND note.
# If either feature is missing, the build terminates with a fatal error.
#
function(verify_cet_target TARGET_NAME)
    if(NOT READELF_EXECUTABLE)
        message(FATAL_ERROR "verify_cet_target: GNU readelf executable not found.")
    endif()

    add_custom_command(
        TARGET ${TARGET_NAME} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E echo "[CET-VERIFY] Checking $<TARGET_FILE_NAME:${TARGET_NAME}> for Intel CET (IBT + SHSTK)..."
        COMMAND sh -c "\"$1\" -n \"$2\" | grep -q 'IBT' && \"$1\" -n \"$2\" | grep -q 'SHSTK' && echo '[CET-VERIFY] $<TARGET_FILE_NAME:${TARGET_NAME}>: PASSED (IBT and SHSTK verified)'" _ "${READELF_EXECUTABLE}" "$<TARGET_FILE:${TARGET_NAME}>"
        COMMENT "Auditing ${TARGET_NAME} for Intel CET compliance"
        VERBATIM
    )
endfunction()
