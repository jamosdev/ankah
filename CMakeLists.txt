cmake_minimum_required(VERSION 3.20)
project(ankah LANGUAGES C)
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
option(ANKAH_WASM_SOLVER "Build the browser WebAssembly solver" ON)
if(ANKAH_WASM_SOLVER)
  find_package(Python3 COMPONENTS Interpreter REQUIRED)
  find_program(ANKAH_WASM_CLANG NAMES clang REQUIRED)
  find_program(ANKAH_WASM_LLD NAMES wasm-ld REQUIRED)
  set(ANKAH_WASM_FILE "${CMAKE_CURRENT_BINARY_DIR}/browser_pow.wasm")
  set(ANKAH_WASM_HEADER "${CMAKE_CURRENT_BINARY_DIR}/browser_pow_data.h")
  add_custom_command(OUTPUT "${ANKAH_WASM_FILE}"
    COMMAND "${ANKAH_WASM_CLANG}" --target=wasm32-unknown-unknown -O3
      -ffreestanding -fno-builtin -nostdlib -Wl,--no-entry
      -Wl,--export=nonce_buffer -Wl,--export=search_batch
      -Wl,--export-memory -Wl,--strip-all
      -o "${ANKAH_WASM_FILE}" "${CMAKE_CURRENT_SOURCE_DIR}/src/browser_pow.c"
    DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/src/browser_pow.c"
    VERBATIM)
  add_custom_command(OUTPUT "${ANKAH_WASM_HEADER}"
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/build_wasm_asset.py"
      "${ANKAH_WASM_FILE}" "${ANKAH_WASM_HEADER}"
    DEPENDS "${ANKAH_WASM_FILE}" "${CMAKE_CURRENT_SOURCE_DIR}/build_wasm_asset.py"
    VERBATIM)
  add_custom_target(ankah-browser-pow DEPENDS "${ANKAH_WASM_HEADER}")
endif()
include(FetchContent)
set(LLHTTP_BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(LLHTTP_BUILD_STATIC_LIBS ON CACHE BOOL "" FORCE)
FetchContent_Declare(llhttp
  URL https://github.com/nodejs/llhttp/archive/refs/tags/release/v9.3.1.tar.gz
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
FetchContent_MakeAvailable(llhttp)
FetchContent_Declare(qrcodegen
  URL https://github.com/nayuki/QR-Code-generator/archive/3c6d0b3cefb4e049dc337e82237c9644399716a8.tar.gz
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
FetchContent_MakeAvailable(qrcodegen)
FetchContent_Declare(stb
  URL https://github.com/nothings/stb/archive/2c980bb59875b0d32144a71867fbdebb2f77cd20.tar.gz
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
FetchContent_MakeAvailable(stb)
add_library(ankah_qr STATIC ${qrcodegen_SOURCE_DIR}/c/qrcodegen.c src/qr.c)
target_include_directories(ankah_qr PRIVATE ${qrcodegen_SOURCE_DIR}/c ${stb_SOURCE_DIR})
target_include_directories(ankah_qr PUBLIC include)
add_library(ankah_pow STATIC src/pow.c)
target_include_directories(ankah_pow PUBLIC include)
find_path(MBEDTLS_INCLUDE_DIR mbedtls/sha256.h REQUIRED)
find_library(MBEDCRYPTO_LIBRARY mbedcrypto REQUIRED)
target_include_directories(ankah_pow PRIVATE ${MBEDTLS_INCLUDE_DIR})
target_link_libraries(ankah_pow PUBLIC ${MBEDCRYPTO_LIBRARY})
add_library(ankah_http STATIC src/http.c)
target_include_directories(ankah_http PUBLIC include)
target_link_libraries(ankah_http PUBLIC llhttp_static)
find_path(LIBUV_INCLUDE_DIR uv.h REQUIRED)
find_library(LIBUV_LIBRARY uv REQUIRED)
add_executable(ankah src/main.c src/static.c src/session.c)
if(ANKAH_WASM_SOLVER)
  add_dependencies(ankah ankah-browser-pow)
  target_include_directories(ankah PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")
  target_compile_definitions(ankah PRIVATE ANKAH_HAS_WASM=1)
else()
  target_compile_definitions(ankah PRIVATE ANKAH_HAS_WASM=0)
endif()
target_include_directories(ankah PRIVATE ${LIBUV_INCLUDE_DIR})
if(UNIX)
  target_compile_definitions(ankah PRIVATE _POSIX_C_SOURCE=200809L)
endif()
target_link_libraries(ankah PRIVATE ankah_http ankah_pow ankah_qr ${LIBUV_LIBRARY})
add_executable(ankah-pow tests/pow_test.c)
target_link_libraries(ankah-pow PRIVATE ankah_pow)
add_executable(ankah-http tests/http_test.c)
target_link_libraries(ankah-http PRIVATE ankah_http)
add_executable(ankah-session tests/session_test.c src/session.c)
target_link_libraries(ankah-session PRIVATE ankah_pow)
enable_testing()
add_test(NAME pow COMMAND ankah-pow)
add_test(NAME http COMMAND ankah-http)
add_test(NAME session COMMAND ankah-session)
if(NOT Python3_Interpreter_FOUND)
  find_package(Python3 COMPONENTS Interpreter)
endif()
if(Python3_Interpreter_FOUND)
  add_test(NAME cache COMMAND ${Python3_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/cache_test.py
    $<TARGET_FILE:ankah> ${CMAKE_CURRENT_SOURCE_DIR})
  add_test(NAME static COMMAND ${Python3_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/static_test.py
    $<TARGET_FILE:ankah> ${CMAKE_CURRENT_SOURCE_DIR}/build_static_bundle.py
    ${CMAKE_CURRENT_SOURCE_DIR})
  add_test(NAME continuation COMMAND ${Python3_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/continuation_test.py
    $<TARGET_FILE:ankah> ${CMAKE_CURRENT_SOURCE_DIR})
endif()
if(ANKAH_WASM_SOLVER)
  find_program(ANKAH_NODE NAMES node nodejs)
  if(ANKAH_NODE)
    add_test(NAME browser_pow COMMAND "${ANKAH_NODE}"
      "${CMAKE_CURRENT_SOURCE_DIR}/tests/browser_pow_test.js" "${ANKAH_WASM_FILE}"
      "${CMAKE_CURRENT_SOURCE_DIR}/pow-worker.js")
  endif()
endif()
