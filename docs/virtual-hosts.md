# Isolated virtual hosts

The global configuration remains the primary host. Add `virtual-host=FILE`
for each additional host. Paths in each key/value file resolve relative to that
file. Additional hosts have no static bundle, health/dashboard routes, challenge,
crawler admission or continuation handling. They connect directly to the selected
upstream once; client retries must authenticate with the backend again.

```ini
public-origin=https://submit.example
tls-cert=submit.pem
tls-key=submit.key
upstream=unix:/run/example/submission.sock
route=submission POST /v1/submit
body-limit=25165824
concurrency=2
connect-timeout-ms=5000
upload-timeout-ms=105000
response-timeout-ms=115000
```

All fields are required. `route` may repeat with distinct identifiers and exact
method/path pairs. Route identifiers contain letters, digits, underscores or
hyphens. Limits are positive integer bytes, transactions or milliseconds. Unknown
keys, duplicate fields/hosts/routes and invalid limits fail startup. No route
normalization is performed: queries (including an empty question mark), escaped
paths, dot segments, suffixes and prefixes do not match an exact configured path.
An exact path with the wrong method returns 405, other targets 404, malformed
requests 400, and unknown or mismatched authorities 421.

The primary TLS host and each additional host have their own certificate pair.
Multi-host TLS requires configured SNI and matching HTTP authority. Hostname case
and the implicit HTTPS port 443 are the only authority normalization. An explicit
non-default port must match the configured origin exactly. Duplicate Host and
sensitive submission headers are rejected. HTTP/2 Host must agree with authority.
Internal host identity is authenticated along with the existing private bridge
metadata, and public internal headers cannot override it. HTTP/3 must be `off`
in multi-host mode. Legacy single-host behavior remains available.

On POSIX, SIGHUP loads every certificate pair into a new generation before
publication. A failed replacement retains the complete previous generation.
Existing connections retain their selected generation. Windows directory watchers
cover every certificate/key directory. Unix upstreams require an absolute pathname
and are rejected on Windows; TCP IPv4/IPv6 upstreams retain their existing syntax.
Socket errors and denied permissions return 502 with no fallback or retry. Ankah
does not change socket permissions.

The body limit counts decoded HTTP bytes, including multipart framing. Declared
oversize bodies are rejected before connecting. Chunked HTTP/1 and lengthless
HTTP/2 stream incrementally; an over-limit stream cannot forward its final body
terminator. Trailers and ambiguous framing are rejected. Authorization,
Idempotency-Key, Content-Type, body bytes, backend status/body and Retry-After
pass through. Early backend rejection stops upload forwarding and remains final.
No exact-route request is saved for challenge replay or receipt caching.

Global optional ceilings: `max-connections` (up to 256), `max-h2-streams` (up to
256 total), `upload-queue-bytes` (32768 through 524288 per HTTP/2 upload),
`request-queue-bytes` and `response-queue-bytes` (aggregate queues). Unspecified
ceilings preserve legacy admission defaults. Upload flow credit is returned after
bridge writes complete. Each transport pauses reads when its downstream writes
back up; aggregate budgets provide a final allocation guard. Protocol headers,
TLS state, kernel socket buffers and allocator overhead are additional to these
queue budgets. Exhaustion rejects or closes affected work without retrying it.

TLS handshakes have ten seconds and headers five seconds. Exact-route connect,
upload and response deadlines are absolute. Response time includes upload time,
and response bytes or interim responses do not restart it. Two in-flight requests
means two transactions across all connections and protocols, released on response
completion, cancellation, error or timeout. Excess work receives 503 and
Retry-After. These routes log only configured identifiers, elapsed time and queue
counters; request-derived language logging and persistence are bypassed.

A 105-second upload deadline and 115-second response deadline leave headroom for
a backend's 100-second upload and ten-second processing window. A consumer's
120-second timeout is independent and does not authorize gateway retries.
These limits should be validated against the actual backend before activation.

## Windows verification

Console interrupt handling drains requests and flushes persistence on Windows.
The link tests send an actual Windows console control event through a test-only
launcher; forced process termination remains the separate crash-recovery case.
Generated dashboard credentials are written only after an owner-only protected
ACL has been set and read back. If that protection cannot be verified, the file
is removed before secret bytes are written and the existing temporary-token
fallback is used. Wine currently cannot preserve this ACL in the test filesystem;
the Wine check verifies no credential file, token rotation and rejection of the
old token. Native Windows checks require the persisted file and protected ACL.
Wine results do not establish native Windows permissions or platform acceptance.
