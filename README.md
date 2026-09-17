# Ankah

Ankah is a native HTTP gateway for Python web applications. The current source
is a prototype; it is not ready to protect a public service.

The HTTP/1.1 gateway issues a proof of work challenge before forwarding a
request to a local application server. It can start that server as a child
process. The browser challenge can be solved on the original device or by
scanning a QR code with a phone. A browser without JavaScript shows the QR code
immediately; a browser still solving after ten seconds shows it too. The phone
marks the original browser session as solved, then the original browser uses
its Finished button to continue. A Python based terminal solver is available
through a Bash/CMD script. The gateway supports conditional requests and serves assets
at paths containing their SHA-256 digest with
`Cache-Control: public, max-age=31536000, immutable`. Challenge pages and
scripts use `Cache-Control: no-store`.

For a blocked GET, Finished redirects to the exact original path and query.
For a blocked POST, Ankah holds the original headers and raw body in process
memory and the page carries a one-use continuation token. The token form
submits to the original path; Ankah replaces that form with the saved request
before forwarding it. This preserves multipart boundaries and binary form
parts. The phone never receives the browser session cookie or saved request.

Saved POST bodies are limited to 2 MiB each and 64 MiB in total. An unsolved
session expires after five minutes, a solved session after thirty minutes,
and a saved POST expires five minutes after its challenge is solved. A process
restart clears sessions and saved requests. Chunked and oversized blocked
requests must be retried after unlocking with a small GET request.

Ankah can also serve packaged application static files directly. The build
helper detects common Python web app and frontend directories, then writes a
content addressed bundle for Ankah to load at startup. See
[build time static serving](docs/static-serving.md).

## Build and test

Requires a C99 compiler, CMake, libuv, Mbed TLS's crypto library, and Python 3
for integration tests. CMake downloads llhttp 9.3.1, qrcodegen, and
stb_image_write during the build. qrcodegen is MIT licensed; stb_image_write
is available under the public domain or MIT license.

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

TLS/HTTP/2, a WASM browser solver, trusted proxy IP handling, and cross-platform
builds are still pending. Do not place this
prototype in front of a public service yet.
