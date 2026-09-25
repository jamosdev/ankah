# Protocol matrix

This suite exercises Ankah directly over HTTP/1.1, HTTP/2, and HTTP/3 and
through Caddy over the same three protocols. Native HTTP/3 must negotiate
QUIC with the `h3` ALPN.

Run the complete isolated stack with:

```sh
python3 tests/protocol_matrix/run.py compose
```

After one successful image build, an offline run uses only existing images:

```sh
python3 tests/protocol_matrix/run.py compose --offline
```

Use `--profile edge|native|all` and `--protocol h1|h2|h3|all` to filter the
matrix. Results are written to `protocol-matrix-artifacts` by default. The
Compose network is internal and uses the aliases `edge.ankah.test` and
`native.ankah.test`; it publishes no host ports.

For host debugging, use both Compose files. Build the images, generate the
short-lived certificates in the state volume, start the servers, and export
the generated CA:

```sh
docker compose -f tests/protocol_matrix/compose.yml \
  -f tests/protocol_matrix/compose.debug.yml build
docker compose -f tests/protocol_matrix/compose.yml \
  -f tests/protocol_matrix/compose.debug.yml run --rm --no-deps \
  client certificates.py /run/ankah-protocol
docker compose -f tests/protocol_matrix/compose.yml \
  -f tests/protocol_matrix/compose.debug.yml up -d native edge
docker compose -f tests/protocol_matrix/compose.yml \
  -f tests/protocol_matrix/compose.debug.yml cp \
  native:/run/ankah-protocol/ca.pem protocol-matrix-ca.pem
```

The override maps edge TCP and UDP to loopback port 8443 and native TCP and
UDP to loopback port 9443 on both `127.0.0.1` and `::1`. `ANKAH_EDGE_PORT` and
`ANKAH_NATIVE_PORT` override those ports and must also be reflected in the
external endpoint URLs. The edge advertises its selected port for HTTP/3.

External mode runs in the invoking Python environment. Install the exact lock,
then run the tests against the exported CA:

```sh
python3 -m pip install --require-hashes -r tests/protocol_matrix/requirements.lock
python3 tests/protocol_matrix/run.py external \
  --edge-url https://localhost:8443 \
  --native-url https://localhost:9443 \
  --ca-file protocol-matrix-ca.pem
```

Remove the debug stack and its generated certificate volume when finished:

```sh
docker compose -f tests/protocol_matrix/compose.yml \
  -f tests/protocol_matrix/compose.debug.yml down --volumes --remove-orphans
rm -f protocol-matrix-ca.pem
```

External endpoints must be a dedicated test deployment containing this
fixture and static bundle. The tests create isolated resource names but perform
write, move, lock, and delete operations.

## Test-only Content-Range contract

`PUT /matrix/content-range/{id}` accepts one sequential segment with
`Content-Range: bytes start-end/total`. The first segment starts at zero and
the body length must equal the inclusive range length. Incomplete uploads
return 202, completion returns 201, and both include `Upload-Offset` plus the
SHA-256 digest accumulated so far. Duplicate, overlapping, or out-of-order
segments return 409 with the current offset. `HEAD` returns progress and total
length; `GET` returns the body only after completion.
