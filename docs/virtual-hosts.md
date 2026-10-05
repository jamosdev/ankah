# Isolated virtual hosts

The global configuration remains the primary host. Add `virtual-host=FILE`
for each additional host. Paths in each key/value file resolve relative to that
file. Each host serves its own challenge endpoints and optional static bundle. The
configured public dashboard route is available on every host and controls the
same gateway process. Health routes and POST continuation remain primary-host
features. Exact upstream routes connect once; client retries must authenticate
with the backend again.

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

Origin and certificate fields are required. A host needs configured upstream routes,
a static bundle, or both. Each upstream route requires a complete policy:
host-level fields for legacy routes, or a named policy as described below. A static-only host does not need an upstream. `route` may repeat with distinct identifiers and exact
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

## Browser pages

Add a build-time bundle to an additional host using paths relative to its file:

```ini
static-bundle=landing-bundle
static-challenge=true
```

Build with `build_static_bundle.py --url-prefix /` to serve `index.html` at `/`.
Additional-host bundles use exact file matching and reject SPA fallback bundles.
`static-challenge` defaults to false. When true, a valid host-bound proof is
required before any representation, range or conditional response is served;
protected files use `Cache-Control: private, no-cache`. Only GET and HEAD serve
files. Other methods return 405 without saving a body for continuation. The
primary host's allow-prefix and download-throttle settings do not apply here.
Unknown targets return 404 without connecting to either upstream.

`/ankah/` and the configured dashboard prefix are reserved on every host. Exact
routes cannot overlap those paths or packaged file URLs. The literal upstream
route always keeps its method/path policy, including rejection of queries.
Browser requests do not consume exact-route concurrency slots or use their
submission deadlines. Gateway-wide connection, stream, queue and admission
bounds still apply.

Visit `/ankah/unlock` on any host to issue fresh proof, even with a solved cookie.
Use `/ankah/unlock?return=/ankah/unlock` for repeated solver testing. Challenge
assets, QR solve pages, command-line instructions and redirects use the selected
host. Cookies omit Domain and proof/session checks reject another host's cookie
even if a client manually copies it. Session snapshots retain host identity;
reordering virtual-host declarations does not change session ownership. Gateway
links synchronize only primary-host sessions; additional-host challenges are local.

The dashboard keeps one token, authenticator, statistics store and set of controls
across hosts. A setting change or runtime disable affects the complete process.
Browser credentials remain in each origin's session storage. Existing public
route, private listener and no-dashboard options apply globally; a private-only
listener does not create a public route. Additional-host dashboard pages follow
normal challenge admission, while their APIs keep existing bearer/TOTP checks.
A primary-host allow-prefix exemption does not exempt another host's pages.

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

## Upstream policies and browser routes

Additional hosts can assign routes to named policies. A policy file contains
only `upstream`, `body-limit`, `concurrency`, `connect-timeout-ms`,
`upload-timeout-ms` and `response-timeout-ms`, with the same required fields,
validation and absolute deadlines as the legacy host-level settings. Unknown,
duplicate or missing fields fail startup. Policy files cannot include other
files. Their filenames resolve relative to the host file; Unix upstream socket
paths remain absolute. Up to 16 named policies are supported per host.

```ini
# In the virtual-host file; definitions may follow their route references.
upstream-policy=browser browser-policy.conf
route=web-get GET /admin/ policy=browser match=prefix query=allow challenge=on
route=web-head HEAD /admin/ policy=browser match=prefix query=allow challenge=on
route=web-post POST /admin/ policy=browser match=prefix query=allow challenge=on
route=login GET /oidc/login policy=browser query=allow challenge=on
route=callback POST /oidc/callback policy=browser
route=logout POST /oidc/backchannel-logout policy=browser
```

Example `browser-policy.conf` for a separate local backend:

```ini
upstream=127.0.0.1:8082
body-limit=65536
concurrency=4
connect-timeout-ms=5000
upload-timeout-ms=10000
response-timeout-ms=15000
```

Every route using a policy shares its transaction capacity across HTTP/1.1 and
HTTP/2 connections. Other policies have independent pools, including when they
use the same address. The gateway-wide resource ceilings still apply. Existing
host-level upstream/limits form the implicit `default` policy and retain their
shared capacity. Omitted `policy` or `policy=default` selects that policy; the
name `default` cannot be declared. All declared policies are validated at
startup, and an implicit policy is required when referenced. Configuration is
loaded at startup; SIGHUP still reloads only certificates.

Route options may appear in any order, once each. The defaults are
`match=exact query=reject challenge=off`, preserving existing three-field routes.
Identifiers and methods retain their existing restrictions. Prefix routes must
end in `/`, match that directory and its descendants, and reject escaped path
bytes, backslashes, repeated slashes and dot segments. No path decoding or
normalization takes place. Exact path ownership wins over prefixes; otherwise
the longest matching prefix owns the request. Wrong methods return 405 and a
rejected query returns 404, without falling through to a broader route.
`query=allow` matches the path before `?` and forwards the complete original
target unchanged, including an empty query. Default routes still reject even
an empty question mark. Prefix routes cannot intersect gateway-reserved paths
or cover packaged static files. Duplicate route identifiers and duplicate
method/path/match definitions fail startup.

`challenge=on` requires host-bound browser proof before connecting. Primary-host
allow prefixes and verified crawlers do not exempt these routes. GET/HEAD can
issue a normal browser gate; its session stores only the GET return target, not
the original headers or body. Unproved writes return 428 with unlock-and-retry
instructions. No routed write is captured or replayed. Challenge responses do
not consume upstream-policy slots. Gateway admission/rate limits still protect
challenge routes; challenge-off routes retain the existing direct admission.

Protocol callback and backchannel POSTs should use exact, challenge-off routes.
Their backend must validate their credentials, state and tokens. A challenge
cookie never substitutes for application authentication or authorization.
Ankah forwards cookies, redirect locations, multiple Set-Cookie fields and
backend cache policy. Routed traffic bypasses request-derived language logging;
its diagnostics use configured route identifiers and queue counters. Browser
GET return targets are subject to normal challenge-session persistence, so do
not place credentials in challenged query URLs. An absolute response deadline may close the affected HTTP/1.1 connection or
reset its HTTP/2 stream rather than deliver a new status after expiry. Forwarding
connects once with no retry, fallback upstream, POST continuation or gateway receipt cache.
