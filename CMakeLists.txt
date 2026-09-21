cmake_minimum_required(VERSION 3.20)
project(ankah LANGUAGES C)
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
option(ANKAH_WASM_SOLVER "Build the browser WebAssembly solver" ON)
option(ANKAH_STRICT_WARNINGS "Treat project compiler warnings as errors" OFF)
if(WIN32)
  set(ANKAH_BUNDLED_DEFAULT ON)
else()
  set(ANKAH_BUNDLED_DEFAULT OFF)
endif()
option(ANKAH_BUNDLED_RUNTIME_DEPS "Build libuv and Mbed TLS from pinned sources"
  ${ANKAH_BUNDLED_DEFAULT})
set(ANKAH_TEST_RUNNER "" CACHE STRING "Runner used for cross compiled integration tests")
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
  URL https://github.com/nodejs/llhttp/archive/refs/tags/release/v9.4.3.tar.gz
  URL_HASH SHA256=1eb813c7437b31a87496a1cd3ed79f00746720f5e7e29c79b42c02cb69f36c39
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
FetchContent_MakeAvailable(llhttp)
if(ANKAH_BUNDLED_RUNTIME_DEPS)
  set(ENABLE_LIB_ONLY ON CACHE BOOL "" FORCE)
  set(ENABLE_FAILMALLOC OFF CACHE BOOL "" FORCE)
  set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
  set(BUILD_STATIC_LIBS ON CACHE BOOL "" FORCE)
  FetchContent_Declare(nghttp2
    URL https://github.com/nghttp2/nghttp2/releases/download/v1.70.0/nghttp2-1.70.0.tar.xz
    URL_HASH SHA256=e05cb1388eaca3830aded4ccf20044b6e1ac1a61411dcca11b0437c4285c8bc2
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
  FetchContent_MakeAvailable(nghttp2)
  set(ANKAH_NGHTTP2 nghttp2_static)
else()
  find_path(NGHTTP2_INCLUDE_DIR nghttp2/nghttp2.h REQUIRED)
  find_library(NGHTTP2_LIBRARY nghttp2 REQUIRED)
  set(ANKAH_NGHTTP2 ${NGHTTP2_LIBRARY})
endif()
FetchContent_Declare(qrcodegen
  URL https://github.com/nayuki/QR-Code-generator/archive/3c6d0b3cefb4e049dc337e82237c9644399716a8.tar.gz
  URL_HASH SHA256=ea6326674b89e3af6d055dac722d5d03ffd3a1d3edb5acd8d691a8b89236907b
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
FetchContent_MakeAvailable(qrcodegen)
FetchContent_Declare(stb
  URL https://github.com/nothings/stb/archive/2c980bb59875b0d32144a71867fbdebb2f77cd20.tar.gz
  URL_HASH SHA256=9a955b1b49a4410088a2e0ee2a9c057c3c907d0c1d75454144cb980aca0ba515
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
FetchContent_MakeAvailable(stb)
add_library(ankah_qr STATIC ${qrcodegen_SOURCE_DIR}/c/qrcodegen.c src/qr.c)
target_include_directories(ankah_qr PRIVATE ${qrcodegen_SOURCE_DIR}/c ${stb_SOURCE_DIR})
target_include_directories(ankah_qr PUBLIC include)
add_library(ankah_pow STATIC src/pow.c)
target_include_directories(ankah_pow PUBLIC include)
if(ANKAH_BUNDLED_RUNTIME_DEPS)
  set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
  set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
  set(USE_SHARED_MBEDTLS_LIBRARY OFF CACHE BOOL "" FORCE)
  set(USE_STATIC_MBEDTLS_LIBRARY ON CACHE BOOL "" FORCE)
  FetchContent_Declare(mbedtls
    URL https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-3.6.7/mbedtls-3.6.7.tar.bz2
    URL_HASH SHA256=a7e8bcbec0e6f761b4af24f25677626b35f762f68eef79c08677a363212d11f6
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
  FetchContent_MakeAvailable(mbedtls)
  set(ANKAH_MBEDCRYPTO mbedcrypto)
  set(ANKAH_MBEDTLS_TLS mbedtls mbedx509)
else()
  find_path(MBEDTLS_INCLUDE_DIR mbedtls/ssl.h REQUIRED)
  find_library(MBEDCRYPTO_LIBRARY mbedcrypto REQUIRED)
  find_library(MBEDTLS_LIBRARY mbedtls REQUIRED)
  find_library(MBEDX509_LIBRARY mbedx509 REQUIRED)
  target_include_directories(ankah_pow PRIVATE ${MBEDTLS_INCLUDE_DIR})
  set(ANKAH_MBEDCRYPTO ${MBEDCRYPTO_LIBRARY})
  set(ANKAH_MBEDTLS_TLS ${MBEDTLS_LIBRARY} ${MBEDX509_LIBRARY})
endif()
target_link_libraries(ankah_pow PUBLIC ${ANKAH_MBEDCRYPTO})
find_program(ANKAH_GPERF NAMES gperf)
set(ANKAH_HEADER_INPUT "${CMAKE_CURRENT_SOURCE_DIR}/src/header_names.gperf")
set(ANKAH_HEADER_OUTPUT "${CMAKE_CURRENT_SOURCE_DIR}/src/header_names_gperf.c")
set(ANKAH_HEADER_BUILD_OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/header_names_gperf.c")
add_custom_command(OUTPUT "${ANKAH_HEADER_BUILD_OUTPUT}"
  COMMAND "${CMAKE_COMMAND}"
    "-DANKAH_GPERF=${ANKAH_GPERF}"
    "-DANKAH_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}"
    "-DANKAH_HEADER_INPUT=${ANKAH_HEADER_INPUT}"
    "-DANKAH_HEADER_OUTPUT=${ANKAH_HEADER_OUTPUT}"
    "-DANKAH_HEADER_BUILD_OUTPUT=${ANKAH_HEADER_BUILD_OUTPUT}"
    "-DANKAH_HEADER_TEMP=${CMAKE_CURRENT_BINARY_DIR}/header_names_gperf.c.tmp"
    -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/regenerate_header_names.cmake"
  DEPENDS "${ANKAH_HEADER_INPUT}" "${ANKAH_HEADER_OUTPUT}"
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/regenerate_header_names.cmake"
  WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
  COMMENT "Generating HTTP header classifier"
  VERBATIM)
add_library(ankah_header_names STATIC "${ANKAH_HEADER_BUILD_OUTPUT}")
target_include_directories(ankah_header_names PUBLIC include)
target_include_directories(ankah_header_names PRIVATE src)
add_library(ankah_http STATIC src/http.c)
target_include_directories(ankah_http PUBLIC include)
target_link_libraries(ankah_http PUBLIC llhttp_static ankah_header_names)
if(ANKAH_BUNDLED_RUNTIME_DEPS)
  set(LIBUV_BUILD_SHARED OFF CACHE BOOL "" FORCE)
  set(LIBUV_BUILD_TESTS OFF CACHE BOOL "" FORCE)
  set(LIBUV_BUILD_BENCH OFF CACHE BOOL "" FORCE)
  FetchContent_Declare(libuv
    URL https://dist.libuv.org/dist/v1.52.1/libuv-v1.52.1.tar.gz
    URL_HASH SHA256=66d511b9e6e334c0e62279eb234fbfb2b3110b1479c09b95b44c7afca8cff9e7
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
  FetchContent_MakeAvailable(libuv)
  set(ANKAH_LIBUV uv_a)
  if(MINGW AND CMAKE_C_COMPILER_ID STREQUAL "GNU")
    target_compile_options(uv_a PRIVATE -Wno-error=incompatible-pointer-types)
  endif()
else()
  find_path(LIBUV_INCLUDE_DIR uv.h REQUIRED)
  find_library(LIBUV_LIBRARY uv REQUIRED)
  set(ANKAH_LIBUV ${LIBUV_LIBRARY})
endif()
add_executable(ankah src/main.c src/static.c src/session.c src/files.c
  src/proxy.c src/frontend.c src/stats.c)
if(ANKAH_WASM_SOLVER)
  add_dependencies(ankah ankah-browser-pow)
  target_include_directories(ankah PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")
  target_compile_definitions(ankah PRIVATE ANKAH_HAS_WASM=1)
else()
  target_compile_definitions(ankah PRIVATE ANKAH_HAS_WASM=0)
endif()
if(NOT ANKAH_BUNDLED_RUNTIME_DEPS)
  target_include_directories(ankah PRIVATE ${LIBUV_INCLUDE_DIR} ${MBEDTLS_INCLUDE_DIR}
    ${NGHTTP2_INCLUDE_DIR})
endif()
if(UNIX)
  target_compile_definitions(ankah PRIVATE _POSIX_C_SOURCE=200809L)
endif()
target_link_libraries(ankah PRIVATE ankah_http ankah_pow ankah_qr ${ANKAH_LIBUV}
  ${ANKAH_MBEDTLS_TLS} ${ANKAH_NGHTTP2})
add_executable(ankah-pow tests/pow_test.c)
target_link_libraries(ankah-pow PRIVATE ankah_pow)
add_executable(ankah-http tests/http_test.c)
target_link_libraries(ankah-http PRIVATE ankah_http)
add_executable(ankah-header-names tests/header_names_test.c)
target_include_directories(ankah-header-names PRIVATE src)
target_link_libraries(ankah-header-names PRIVATE ankah_header_names)
add_executable(ankah-session tests/session_test.c src/session.c)
target_link_libraries(ankah-session PRIVATE ankah_pow)
add_executable(ankah-stats tests/stats_test.c src/stats.c)
target_include_directories(ankah-stats PRIVATE include)
add_executable(ankah-proxy tests/proxy_test.c src/proxy.c)
target_include_directories(ankah-proxy PRIVATE include)
if(UNIX)
  target_compile_definitions(ankah-proxy PRIVATE _POSIX_C_SOURCE=200809L)
endif()
if(NOT ANKAH_BUNDLED_RUNTIME_DEPS)
  target_include_directories(ankah-proxy PRIVATE ${LIBUV_INCLUDE_DIR})
endif()
target_link_libraries(ankah-proxy PRIVATE ${ANKAH_LIBUV} ankah_header_names)
set(ANKAH_PROJECT_TARGETS ankah ankah-pow ankah-http ankah-session ankah-proxy
  ankah-stats ankah-header-names ankah_qr ankah_pow ankah_http ankah_header_names)
if(ANKAH_STRICT_WARNINGS AND CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
  foreach(target IN LISTS ANKAH_PROJECT_TARGETS)
    target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Werror)
  endforeach()
endif()
if(MINGW)
  target_compile_definitions(ankah PRIVATE _WIN32_WINNT=0x0A00)
  foreach(target ankah ankah-pow ankah-http ankah-session ankah-proxy ankah-stats)
    target_link_options(${target} PRIVATE -static -static-libgcc)
  endforeach()
endif()
enable_testing()
add_test(NAME pow COMMAND ankah-pow)
add_test(NAME http COMMAND ankah-http)
add_test(NAME header_names COMMAND ankah-header-names)
add_test(NAME session COMMAND ankah-session)
add_test(NAME proxy COMMAND ankah-proxy)
add_test(NAME stats COMMAND ankah-stats)
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
  add_test(NAME platform COMMAND ${Python3_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/platform_test.py
    $<TARGET_FILE:ankah> ${CMAKE_CURRENT_SOURCE_DIR})
  add_test(NAME tls_http2 COMMAND ${Python3_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/tls_http2_test.py
    $<TARGET_FILE:ankah> ${CMAKE_CURRENT_SOURCE_DIR})
  add_test(NAME dashboard COMMAND ${Python3_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/dashboard_test.py
    $<TARGET_FILE:ankah> ${CMAKE_CURRENT_SOURCE_DIR})
  if(CMAKE_CROSSCOMPILING)
    set_tests_properties(cache static continuation platform tls_http2 dashboard PROPERTIES
      ENVIRONMENT "ANKAH_TEST_RUNNER=${ANKAH_TEST_RUNNER};ANKAH_TEST_WINDOWS_PATHS=1")
  endif()
endif()
if(ANKAH_WASM_SOLVER)
  find_program(ANKAH_NODE NAMES node nodejs)
  if(ANKAH_NODE)
    add_test(NAME browser_pow COMMAND "${ANKAH_NODE}"
      "${CMAKE_CURRENT_SOURCE_DIR}/tests/browser_pow_test.js" "${ANKAH_WASM_FILE}"
      "${CMAKE_CURRENT_SOURCE_DIR}/pow-worker.js")
  endif()
endif()

install(TARGETS ankah RUNTIME DESTINATION . COMPONENT ankah_runtime)
install(FILES
  ankah.png
  particles.min.js
  particlejs.json
  challenge.js
  solver.py
  challenge-polyglot.txt
  phone-scan.png
  pow-worker.js
  DESTINATION assets COMPONENT ankah_runtime)
install(FILES dashboard/index.html dashboard/dashboard.css dashboard/dashboard.js
  dashboard/d3-subset.min.js DESTINATION assets/dashboard COMPONENT ankah_runtime)
install(FILES docs/windows.md DESTINATION . RENAME README-WINDOWS.md
  COMPONENT ankah_runtime)
install(FILES docs/dashboard.md DESTINATION . RENAME DASHBOARD.md
  COMPONENT ankah_runtime)
install(FILES docs/tls-and-proxies.md DESTINATION . RENAME TLS-AND-PROXIES.md
  COMPONENT ankah_runtime)
install(FILES PARTICLES_LICENSE.md DESTINATION notices COMPONENT ankah_runtime)
install(FILES D3_LICENSE.md DESTINATION notices COMPONENT ankah_runtime)
install(FILES
  ${llhttp_SOURCE_DIR}/LICENSE-MIT
  DESTINATION notices RENAME llhttp-LICENSE.txt COMPONENT ankah_runtime)
install(FILES
  ${qrcodegen_SOURCE_DIR}/Readme.markdown
  DESTINATION notices RENAME qrcodegen-NOTICE.md COMPONENT ankah_runtime)
install(FILES
  ${stb_SOURCE_DIR}/LICENSE
  DESTINATION notices RENAME stb-LICENSE.txt COMPONENT ankah_runtime)
if(ANKAH_BUNDLED_RUNTIME_DEPS)
  install(FILES
    ${mbedtls_SOURCE_DIR}/LICENSE
    DESTINATION notices RENAME mbedtls-LICENSE.txt COMPONENT ankah_runtime)
  install(FILES
    ${nghttp2_SOURCE_DIR}/COPYING
    DESTINATION notices RENAME nghttp2-LICENSE.txt COMPONENT ankah_runtime)
  install(FILES
    ${libuv_SOURCE_DIR}/LICENSE
    DESTINATION notices RENAME libuv-LICENSE.txt COMPONENT ankah_runtime)
  install(FILES
    ${libuv_SOURCE_DIR}/LICENSE-extra
    DESTINATION notices RENAME libuv-LICENSE-extra.txt COMPONENT ankah_runtime)
endif()
