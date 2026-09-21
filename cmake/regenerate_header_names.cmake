if(NOT ANKAH_GPERF OR ANKAH_GPERF MATCHES "-NOTFOUND$")
  if(NOT EXISTS "${ANKAH_HEADER_OUTPUT}")
    message(FATAL_ERROR "the checked-in generated HTTP header classifier is missing")
  endif()
  if("${ANKAH_HEADER_INPUT}" IS_NEWER_THAN "${ANKAH_HEADER_OUTPUT}" AND
     NOT "${ANKAH_HEADER_OUTPUT}" IS_NEWER_THAN "${ANKAH_HEADER_INPUT}")
    message(FATAL_ERROR
      "src/header_names.gperf is newer than its generated C file; install gperf and rebuild")
  endif()
  execute_process(
    COMMAND "${CMAKE_COMMAND}" -E copy_if_different
            "${ANKAH_HEADER_OUTPUT}" "${ANKAH_HEADER_BUILD_OUTPUT}"
    RESULT_VARIABLE copy_result)
  if(NOT copy_result EQUAL 0)
    message(FATAL_ERROR "could not copy ${ANKAH_HEADER_OUTPUT}")
  endif()
  file(TOUCH "${ANKAH_HEADER_BUILD_OUTPUT}")
  return()
endif()

execute_process(
  COMMAND "${ANKAH_GPERF}" "--initializer-suffix=, ANKAH_HEADER_OTHER"
          "src/header_names.gperf"
  WORKING_DIRECTORY "${ANKAH_SOURCE_DIR}"
  OUTPUT_FILE "${ANKAH_HEADER_TEMP}"
  ERROR_VARIABLE generation_error
  RESULT_VARIABLE generation_result)
if(NOT generation_result EQUAL 0)
  file(REMOVE "${ANKAH_HEADER_TEMP}")
  message(FATAL_ERROR "gperf failed: ${generation_error}")
endif()
file(READ "${ANKAH_HEADER_TEMP}" generated_source)
string(REGEX REPLACE "/\\* Command-line:[^\n]*\n"
       "/* Generated from src/header_names.gperf. */\n"
       generated_source "${generated_source}")
file(WRITE "${ANKAH_HEADER_TEMP}" "${generated_source}")
foreach(output "${ANKAH_HEADER_OUTPUT}" "${ANKAH_HEADER_BUILD_OUTPUT}")
  execute_process(
    COMMAND "${CMAKE_COMMAND}" -E copy_if_different
            "${ANKAH_HEADER_TEMP}" "${output}"
    RESULT_VARIABLE copy_result)
  if(NOT copy_result EQUAL 0)
    file(REMOVE "${ANKAH_HEADER_TEMP}")
    message(FATAL_ERROR "could not update ${output}")
  endif()
endforeach()
file(REMOVE "${ANKAH_HEADER_TEMP}")
file(TOUCH "${ANKAH_HEADER_BUILD_OUTPUT}")
