#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
  echo "usage: $0 linux-musl-x64|macos-arm64|windows-x64" >&2
  exit 2
fi

platform=$1
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"
mkdir -p dist

case "$platform" in
  linux-musl-x64)
    test "$(uname -s)" = Linux
    test "$(uname -m)" = x86_64
    cmake -E rm -rf build-release-linux dist/ankah-linux-musl-x64
    cmake -S . -B build-release-linux -G Ninja \
      -DANKAH_BUNDLED_RUNTIME_DEPS=ON -DANKAH_STATIC_LINUX=ON \
      -DANKAH_STRICT_WARNINGS=ON
    cmake --build build-release-linux --target verify-header-names verify-language-names
    cmake --build build-release-linux -j 2
    # The admission fixture uses LD_PRELOAD, which a static binary cannot load.
    # The normal source pipeline runs that test against its dynamic executable.
    ctest --test-dir build-release-linux --output-on-failure --timeout 180 \
      --exclude-regex '^admission$'
    if readelf -l build-release-linux/ankah | grep -q INTERP; then
      echo "Linux executable has a dynamic interpreter" >&2
      exit 1
    fi
    if readelf -d build-release-linux/ankah 2>/dev/null | grep -q NEEDED; then
      echo "Linux executable has shared library dependencies" >&2
      exit 1
    fi
    cmake --install build-release-linux --component ankah_runtime \
      --prefix "$root/dist/ankah-linux-musl-x64"
    PYTHONPATH=tests python3 tests/platform_test.py \
      "$root/dist/ankah-linux-musl-x64/ankah" "$root/dist/ankah-linux-musl-x64/assets"
    (cd dist && tar -czf ankah-linux-musl-x64.tar.gz ankah-linux-musl-x64)
    ;;
  macos-arm64)
    test "$(uname -s)" = Darwin
    test "$(uname -m)" = arm64
    cmake -E rm -rf build-release-macos dist/ankah-macos-arm64
    cmake -S . -B build-release-macos -G Ninja \
      -DANKAH_BUNDLED_RUNTIME_DEPS=ON -DANKAH_STRICT_WARNINGS=ON \
      -DCMAKE_OSX_ARCHITECTURES=arm64 -DCMAKE_OSX_DEPLOYMENT_TARGET=13.0 \
      -DPython3_EXECUTABLE="$(command -v python3)" \
      -DANKAH_WASM_CLANG="${ANKAH_WASM_CLANG:?set ANKAH_WASM_CLANG to Homebrew llvm clang}" \
      -DANKAH_WASM_LLD="${ANKAH_WASM_LLD:?set ANKAH_WASM_LLD to Homebrew wasm-ld}"
    cmake --build build-release-macos --target verify-header-names verify-language-names
    cmake --build build-release-macos -j 2
    ctest --test-dir build-release-macos --output-on-failure --timeout 180
    file build-release-macos/ankah | grep -q 'arm64'
    if otool -L build-release-macos/ankah | tail -n +2 | grep -Ev '^[[:space:]]*/usr/lib/|^[[:space:]]*/System/Library/|^[[:space:]]*$'; then
      echo "macOS executable depends on a non-system library" >&2
      exit 1
    fi
    cmake --install build-release-macos --component ankah_runtime \
      --prefix "$root/dist/ankah-macos-arm64"
    PYTHONPATH=tests python3 tests/platform_test.py \
      "$root/dist/ankah-macos-arm64/ankah" "$root/dist/ankah-macos-arm64/assets"
    (cd dist && tar -czf ankah-macos-arm64.tar.gz ankah-macos-arm64)
    ;;
  windows-x64)
    cmake -E rm -rf build-release-windows dist/ankah-windows-x64
    cmake -S . -B build-release-windows -G Ninja \
      -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/mingw-w64-x86_64.cmake \
      -DCMAKE_CROSSCOMPILING_EMULATOR="$(command -v wine)" \
      -DANKAH_TEST_RUNNER="$(command -v wine)" \
      -DANKAH_BUNDLED_RUNTIME_DEPS=ON -DANKAH_STRICT_WARNINGS=ON
    cmake --build build-release-windows -j 2
    if x86_64-w64-mingw32-objdump -p build-release-windows/ankah.exe |
      grep -Eiq 'DLL Name:[[:space:]]+(libgcc|libwinpthread|libstdc)'; then
      echo "Windows executable depends on a compiler runtime DLL" >&2
      exit 1
    fi
    ctest --test-dir build-release-windows --output-on-failure --timeout 180
    cmake --install build-release-windows --component ankah_runtime \
      --prefix "$root/dist/ankah-windows-x64"
    ANKAH_TEST_RUNNER="$(command -v wine)" ANKAH_TEST_WINDOWS_PATHS=1 \
      PYTHONPATH=tests python3 tests/platform_test.py \
      "$root/dist/ankah-windows-x64/ankah.exe" "$root/dist/ankah-windows-x64/assets"
    (cd dist && cmake -E tar cf ankah-windows-x64.zip --format=zip ankah-windows-x64)
    ;;
  *)
    echo "unknown platform: $platform" >&2
    exit 2
    ;;
esac
