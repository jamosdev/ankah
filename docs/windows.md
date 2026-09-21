# Windows x64 builds

Ankah can be cross compiled for 64 bit Windows with MinGW. The Windows build
uses pinned static copies of libuv, Mbed TLS, and nghttp2, so the executable
does not need compiler runtime DLLs. Windows system DLLs are still used.

From a Linux checkout with MinGW, CMake, Clang, LLD, Python, Node, curl, and
OpenSSL installed:

```sh
cmake -S . -B build-windows -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/mingw-w64-x86_64.cmake
cmake --build build-windows
```

Clang and LLD build the browser WebAssembly solver on the build host. Set
`-DANKAH_WASM_SOLVER=OFF` when those tools are unavailable.

## Test with Wine

Set a 64 bit Wine prefix and tell CMake which runner should execute target
programs:

```sh
export WINEARCH=win64
export WINEPREFIX="$PWD/.wine-ankah"
export WINEDEBUG=-all
wineboot --init
cmake -S . -B build-windows -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/mingw-w64-x86_64.cmake \
  -DCMAKE_CROSSCOMPILING_EMULATOR="$(command -v wine)" \
  -DANKAH_TEST_RUNNER="$(command -v wine)"
cmake --build build-windows
ctest --test-dir build-windows --output-on-failure --timeout 180
```

The test launcher translates asset, secret, statistics, static bundle,
certificate, and key paths into the default Wine `Z:` drive. Native Windows
use accepts normal Windows paths.

## Runtime package

Stage the executable and its browser assets with:

```sh
cmake --install build-windows --component ankah_runtime \
  --prefix package/ankah-windows-x64
```

Keep the `assets` directory beside the executable and pass it explicitly:

```bat
ankah.exe --listen 127.0.0.1:8000 --upstream 127.0.0.1:8001 ^
  --public-origin http://localhost:8000 --secret-file ankah.secret ^
  --assets-dir assets -- python -m uvicorn app:app --port 8001
```

The secret format and all other command line options are the same as on Linux.
The continuous integration Windows job retains this package as a zip file for
seven days.
