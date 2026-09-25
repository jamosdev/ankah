if(NOT ANKAH_GPERF OR ANKAH_GPERF MATCHES "-NOTFOUND$")
  message(FATAL_ERROR "GNU gperf 3.1 is required; install it and reconfigure the CMake build")
endif()
if(NOT ANKAH_LANGUAGE_MODE STREQUAL "regenerate" AND
   NOT ANKAH_LANGUAGE_MODE STREQUAL "verify")
  message(FATAL_ERROR "ANKAH_LANGUAGE_MODE must be regenerate or verify")
endif()
execute_process(COMMAND "${ANKAH_GPERF}" --version
  OUTPUT_VARIABLE version_output ERROR_VARIABLE version_error RESULT_VARIABLE version_result)
string(REGEX MATCH "^[^\r\n]*" version_line "${version_output}")
if(NOT version_result EQUAL 0 OR NOT version_line STREQUAL "GNU gperf 3.1")
  message(FATAL_ERROR "GNU gperf 3.1 is required, but ${ANKAH_GPERF} reported: ${version_line}${version_error}")
endif()
execute_process(
  COMMAND "${ANKAH_GPERF}" "--initializer-suffix=, ANKAH_LANGUAGE_EN"
          "${ANKAH_LANGUAGE_INPUT}"
  WORKING_DIRECTORY "${ANKAH_SOURCE_DIR}"
  OUTPUT_FILE "${ANKAH_LANGUAGE_TEMP}"
  ERROR_VARIABLE generation_error RESULT_VARIABLE generation_result)
if(NOT generation_result EQUAL 0)
  file(REMOVE "${ANKAH_LANGUAGE_TEMP}")
  message(FATAL_ERROR "gperf failed: ${generation_error}")
endif()
file(READ "${ANKAH_LANGUAGE_TEMP}" generated_source)
string(REGEX REPLACE "/\\* Command-line:[^\n]*\n"
       "/* Generated from src/language_names.gperf. */\n"
       generated_source "${generated_source}")
file(WRITE "${ANKAH_LANGUAGE_TEMP}" "${generated_source}")
if(ANKAH_LANGUAGE_MODE STREQUAL "regenerate")
  execute_process(COMMAND "${CMAKE_COMMAND}" -E copy_if_different
    "${ANKAH_LANGUAGE_TEMP}" "${ANKAH_LANGUAGE_OUTPUT}" RESULT_VARIABLE result)
else()
  execute_process(COMMAND "${CMAKE_COMMAND}" -E compare_files
    "${ANKAH_LANGUAGE_TEMP}" "${ANKAH_LANGUAGE_OUTPUT}" RESULT_VARIABLE result)
endif()
file(REMOVE "${ANKAH_LANGUAGE_TEMP}")
if(NOT result EQUAL 0)
  if(ANKAH_LANGUAGE_MODE STREQUAL "verify")
    message(FATAL_ERROR "src/language_names_gperf.c is stale; run the regenerate-language-names target")
  else()
    message(FATAL_ERROR "could not update ${ANKAH_LANGUAGE_OUTPUT}")
  endif()
endif()
