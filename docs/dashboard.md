# Operator dashboard

Ankah can collect traffic statistics and serve them on a private listener or
under an explicit route on its public listener. The feature is off by default.
Without a dashboard listener or public route Ankah starts no timer and keeps no
counters.

## Enabling it

The dashboard token file is required with either listener option. The private
listener remains the most isolated deployment:

```sh
python3 -c 'import secrets; print(secrets.token_hex(32))' > dashboard.token
chmod 600 dashboard.token
./ankah --listen 0.0.0.0:8000 --public-origin https://example.test \
  --secret-file ankah.secret \
  --dashboard-listen 127.0.0.1:9000 --dashboard-token-file dashboard.token \
  -- python3 -m uvicorn app:app --port 8001
```

The token file uses the same format as `--secret-file`: 64 lowercase
hexadecimal characters with an optional trailing newline. Ankah refuses to
start when the token equals the gateway secret, because the token travels in
request headers and the secret must not.

Every `/stats/` request and `GET /metrics` needs
`Authorization: Bearer <token>`. Ankah compares
the token in constant time and answers `401` otherwise. Dashboard sessions
issued after authenticator sign-in also work as bearer credentials.

For a simple same-host setup, mount the dashboard under a distinct public
prefix instead of creating a second listener:

```sh
./ankah --listen 0.0.0.0:8000 --public-origin https://example.test \
  --secret-file ankah.secret \
  --dashboard-public-route=/ankah-admin/ --dashboard-token-file dashboard.token \
  -- python3 -m uvicorn app:app --port 8001
```

The route must be a non-root path with leading and trailing slashes. Ankah
reserves it and rejects startup if it conflicts with a configured health route
or packaged static namespace. The private listener and public route may be
enabled together.

## Where to bind it

The dashboard listener speaks plain HTTP. Keep it off public interfaces.

**Native deployment.** Bind to loopback, as above. For a remote host, reach it
through an SSH tunnel: `ssh -L 9000:127.0.0.1:9000 host`.

**Docker Compose.** Docker publishes ports from the container's own address, so
inside a container the listener must bind `0.0.0.0`. Publish it on the host's
loopback only, and mount both files as Compose secrets, which appear under
`/run/secrets/`:

```yaml
services:
  web:
    image: my-app
    command: ["ankah", "--listen", "0.0.0.0:8000",
              "--public-origin", "https://example.test",
              "--secret-file", "/run/secrets/ankah_secret",
              "--dashboard-listen", "0.0.0.0:9000",
              "--dashboard-token-file", "/run/secrets/ankah_dashboard",
              "--", "python3", "-m", "uvicorn", "app:app", "--port", "8001"]
    ports:
      - "8000:8000"
      - "127.0.0.1:9000:9000"
    secrets: [ankah_secret, ankah_dashboard]
secrets:
  ankah_secret:
    file: ./ankah.secret
  ankah_dashboard:
    file: ./dashboard.token
```

Files are preferred over environment variables because environment values
leak more easily through process inspection, debugging output and logs.

**Kubernetes.** Mount a Secret as a read-only volume and pass the mounted path.
Do not expose the dashboard port through a Service; use
`kubectl port-forward` to reach it.

## The page

Open the listener's root in a browser. The page first asks for a six-digit
authenticator code. To set that up, choose **Use dashboard token**, enter the
token once, then choose **Set up authenticator** and scan the QR code with a
TOTP app. Future visits can use the app's code. Keep the dashboard token as a
recovery credential. Rotating that token also changes the authenticator setup,
so scan the new QR code after rotation.

You can put the token in the address after a
`#`, as in `http://127.0.0.1:9000/#token=<token>`, or paste it into the form
the page shows. The page moves the token into session storage and removes it
from the address bar, so it does not stay in history. Fragments are never sent
to the server.

With `--dashboard-public-route=/ankah-admin/`, open
`https://example.test/ankah-admin/`. The entry page and its assets live under
that prefix, including `/ankah-admin/dashboard/dashboard.js`. They use normal
public Host checks, rate limits, proof-of-work, and traffic accounting. The
page's API calls stay under the prefix, such as
`/ankah-admin/stats/live` and `/ankah-admin/metrics`, require the bearer token,
bypass proof-of-work, and are excluded from the statistics they display.
`/ankah-admin` redirects to the slash-terminated entry URL.

The page keeps the bearer token or temporary session in session storage for
its origin until the browser tab closes. Authenticator sessions expire after
12 hours, are revoked on sign-out, and are lost when Ankah restarts. Each code
can open one session;
there are at most five unsuccessful code attempts per minute for the process.
Authenticator sign-in is an alternative to entering the bearer token, not an
additional factor. Use HTTPS for a public dashboard route and do not serve
untrusted same-origin scripts, because they can access session storage.

The page polls `/stats/live` once a second while its tab is visible. It shows
throughput now, bounded resources against their limits, a summary and charts
for the chosen range, static download throttle activity, bytes sent per hour
as a day by hour grid, and the busiest open connections. Every chart has a
table view. The green spreadsheet button downloads the complete retained
metrics history as CSV. Addresses can be masked on screen. A reset asks for a
second click before it clears the statistics.

The page files load from the `dashboard` directory inside `--assets-dir` when
the dashboard is enabled, and Ankah refuses to start if they are missing. The
public listener does not serve them unless a dashboard public route is
configured, and that route serves only its own prefixed copies. The page is
served with a policy that allows only its own scripts, styles and requests.

Dashboard text follows the request's `Accept-Language` preference and the page
response includes `Content-Language` and `Vary: Accept-Language`. The source
catalog supports English (`en`), Japanese (`ja`), and Spanish (`es`).
Dates and numbers follow the selected language. The source
HTML uses a restricted SSI form, `<!--#echo var="name" -->`, for localized
text. Ankah resolves only names in its compiled language catalog. Any `<!--#`
directive that does not match this form, including includes, commands,
environment variables, and unknown names, makes startup fail. Runtime messages
in `dashboard.js` read the catalog rendered into the page.

## Endpoints

Responses under `/stats/` are JSON except for the CSV export. The metrics
response uses Prometheus text format. On a public route, prepend the configured
prefix to every endpoint below. Every response uses
`Cache-Control: no-store`. Statistics records are arrays of 40 numbers in the
order given by `/stats/schema`. The JSON schema version is 3.

| Request | Returns |
| --- | --- |
| `GET /stats/schema` | field names, `sum` or `max` kinds, ring sizes, limits |
| `GET /stats/live` | gauges, cumulative and current bucket records, recent buckets, busiest connections |
| `GET /stats/history?hours=H&days=D` | up to `H` completed hours and `D` completed days, oldest first |
| `GET /stats/export.csv` | complete retained metrics as a non-overlapping CSV timeline |
| `POST /stats/reset` | clears every counter and moves the statistics epoch to now |
| `GET /metrics` | cumulative counters, current and peak gauges, limits, latency, and the epoch in Prometheus text format |
| `GET /auth/qr` | authenticator setup QR code; requires the dashboard token |
| `POST /auth/login` | exchange a six-digit `X-Ankah-Code` header for a temporary bearer session |
| `POST /auth/logout` | revoke a temporary bearer session |

The metrics response excludes history, request paths, and connection
addresses. Dashboard and metrics requests are not included in the public
traffic statistics. See [external health monitoring](monitoring.md) for a
Prometheus scrape configuration and external monitor deployment.

The CSV starts with any aggregate for days older than the retained daily ring,
continues with daily rows, then switches to hourly rows at a UTC midnight. The
last row is the current partial hour. Its stable columns identify the record
type, UTC period, partial status and bucket count, followed by every raw field
from `/stats/schema`. Exporting reads the current in-memory history without
resetting counters or forcing a snapshot write.

`/stats/live` takes no parameters, so one rendering serves every viewer that
polls within 250 milliseconds. It carries the last two completed hours and the
last completed day, each series tagged with the absolute index of its first
row. A viewer that was away for longer fetches the history again.

`sample_ms` is a monotonic millisecond clock for computing rates between two
live responses. `now` and `epoch` are Unix seconds.

The `top` list holds the 16 open connections that have moved the most bytes,
with their client address, age, byte counts and state. `top_other` sums the
rest. Request paths are never included.

## What is counted

| Fields | Meaning |
| --- | --- |
| `client_bytes_in`, `client_bytes_out` | bytes read from and written to clients |
| `upstream_bytes_in`, `upstream_bytes_out` | bytes read from and written to the application |
| `accepted`, `refused`, `peak_connections` | client connections, including those refused at the limit |
| `requests`, `responses_2xx` to `responses_5xx`, `rate_limited` | request header blocks received, and responses by class |
| `rate_limited_anonymous`, `rate_limited_protected` | request rate rejections in each admission class |
| `anonymous_connection_rejected`, `pending_connection_refused`, `challenge_session_rejected` | admission capacity rejections |
| `challenges_issued`, `challenges_solved`, `challenges_failed`, `passes_issued`, `qr_scans` | proof of work outcomes |
| `posts_saved`, `posts_replayed` | POST bodies held for continuation, and replays |
| `static_requests`, `static_bytes`, `cache_hits`, `cache_misses` | packaged static serving |
| `throttled_static_requests`, `throttled_static_bytes` | packaged static responses admitted through the download throttle |
| `throttle_queue_responses`, `throttle_queued_requests` | 429 queue pages and downloads admitted after waiting |
| `throttle_wait_ms_total`, `throttle_wait_ms_peak` | total and peak wait before throttle admission |
| `peak_throttle_connections`, `peak_throttle_queue` | peak active throttled transfers and queue entries |
| `upstream_requests`, `upstream_failures`, `upstream_responses` | application connections and their outcomes |
| `upstream_latency_ms_total`, `upstream_latency_peak_ms` | time to the first response byte; the mean is the total over `upstream_responses` |
| `peak_sessions`, `peak_pending_bytes` | challenge sessions and saved POST memory |

`client_bytes_out` exceeds `upstream_bytes_in` by the volume Ankah served
itself: challenge pages, its own assets, and packaged static files.

Status classes for proxied responses come from the status line in the first
chunk the application sends. A response whose status line is split across
reads is not classed, and interim `1xx` responses are ignored, so the classes
are close to but not exactly the request count.

With direct TLS, counts cover the plaintext HTTP/1.1 hop between the TLS
frontend and the gateway core, so they measure application bytes rather than
encrypted bytes on the wire. `accepted` counts requests entering the core,
and the live `tls_connections` gauge counts the TLS sockets themselves.

Every request carries `Connection: close`, so an open connection is one
request in progress or one WebSocket tunnel.

## History and memory

Buckets are aligned to UTC hours and UTC days. Each new connection, each
statistics request and a background tick every 60 seconds close finished
buckets. On a server with no new connections, up to a minute of traffic after
a boundary, such as bytes on a long lived tunnel, can be counted in the bucket
before it. A backward clock step never moves a bucket back; a forward step
records empty buckets for the gap.

Ankah keeps 720 hourly records (30 days) and 4096 daily records (about 11
years). Hours older than the hourly ring are dropped because the daily records
still cover them. Days older than the daily ring are merged into a single
`evicted` record, by sum or by maximum per field, and `evicted_days` counts
them, so the average before the ring stays exact. Each record is 320 bytes, so
the whole store is about 1.5 MiB and never grows.

Counters are 64 bit and are never reset automatically. `POST /stats/reset`
starts a new epoch.

## Persistent history

Dashboard statistics are saved every 15 minutes, after a reset, and when the
event loop exits normally. The default snapshot basename is `ankah.stats` in
the process working directory. Use `--stats-file path` to choose another
basename, or `--no-stats-file` to keep statistics only in memory. These
options are valid only when the dashboard is enabled.

Ankah keeps two generations named with `.0` and `.1` suffixes and uses a
`.tmp` file while replacing one. At most three snapshots exist, for a maximum
of about 5 MiB. A crash can lose up to 15 minutes of recent counts. Version
1 snapshots with 32 fields are migrated in memory, preserving their existing
history and starting the eight throttle fields at zero. Version 2 snapshots
with 40 fields also migrate in memory, starting the five admission fields at
zero. A normal restart restores the newest valid generation and retains its
epoch and history.

Missing, unreadable, incompatible, or corrupt snapshots do not prevent Ankah
from starting. It falls back to an older valid generation or an empty store
and writes a warning to standard error. Snapshot write failures also leave the
gateway and dashboard running, so a read-only filesystem is supported with
in-memory statistics. A later successful save reports recovery.

The reset response includes `persistence` with a value of `saved`, `disabled`,
or `failed`. A failed save still resets the running process, but the dashboard
warns that older data could return after a restart.
