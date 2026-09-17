# Ankah

Ankah is a native HTTP gateway for Python web applications. The current source
is a prototype; it is not ready to protect a public service.

The HTTP/1.1 gateway issues a proof of work challenge before forwarding a
request to a local application server. It can start that server as a child
process. It serves the browser challenge with the Ankah mascot and a
particles.js background, and offers a Python based terminal solver through a
Bash/CMD script. The gateway supports conditional requests and serves assets
at paths containing their SHA-256 digest with
`Cache-Control: public, max-age=31536000, immutable`. Challenge pages and
scripts use `Cache-Control: no-store`.

## Build and test

Requires a C99 compiler, CMake, libuv, Mbed TLS's crypto library, and Python 3
for the cache integration test. CMake downloads llhttp 9.3.1 during the build.

```sh
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
```

## Local example

Create a private 32-byte secret as 64 lowercase hexadecimal characters:

```sh
python3 -c 'import secrets; print(secrets.token_hex(32))' > ankah.secret
chmod 600 ankah.secret
./build/ankah --listen 127.0.0.1:8000 --upstream 127.0.0.1:8001 \
  --public-origin http://localhost:8000 --secret-file ankah.secret \
  --assets-dir . -- python3 -m daphne mysite.asgi:application -b 127.0.0.1 -p 8001
```

`--allow-prefix /path` exempts a path prefix from the challenge. Use a distinct
secret for each deployment. The upstream address must be reachable only by
trusted local processes.

## Release readiness

TLS/HTTP/2, a WASM browser solver, trusted proxy IP handling, cross-platform
builds, and the GitLab release pipeline are still pending. Do not place this
prototype in front of a public service yet.
