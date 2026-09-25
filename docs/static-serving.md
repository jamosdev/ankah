# Build time static serving

Ankah can serve a packaged static directory before a request reaches the app
or the proof of work challenge. Build the package after the app's frontend
build or Django `collectstatic` step. The Python helper is needed only while
building the image. Ankah reads the package at startup and uses an exact URL
lookup table for requests.

```sh
python3 build_static_bundle.py --project-root /app --output /opt/ankah-static
ankah --public-origin https://example.com --secret-file /run/secrets/ankah \
  --static-bundle /opt/ankah-static -- python3 -m uvicorn app:app
```

The helper picks the first available source in this order:

| Source in project root | Default URL prefix |
| --- | --- |
| `staticfiles/` | `/static/` |
| `static/` | `/static/` |
| A single immediate child `*/static/` | `/static/` |
| `public/`, then `dist/`, then `build/` | `/assets/` |

If several app directories contain `static/`, collect them into one directory
first or set `--source`. Django projects should normally run `collectstatic`
and package `STATIC_ROOT`. The helper does not discover every Django app or
reproduce Django's file conflict rules. For a frontend build that expects
paths at `/`, set `--url-prefix /` explicitly:

```sh
python3 build_static_bundle.py --project-root /app --source dist \
  --url-prefix / --output /opt/ankah-static
```

With a root mount, `index.html` is also available at `/`. Other URLs must
match a packaged file exactly; this does not add a catch-all SPA fallback.

## Optional SPA fallback

Ankah treats single-page applications as an explicit deployment choice. To
package an HTML shell for client-side routes, pass its source-relative path:

```sh
python3 build_static_bundle.py --project-root /app --source dist \
  --url-prefix /dashboard/ --spa-fallback index.html \
  --output /opt/ankah-static
```

The bundle records both the shell and its route scope. The scope is the static
URL prefix, so the example can fall back for `/dashboard/settings` without
claiming Django routes elsewhere. Use `--url-prefix /` only when the SPA should
own suitable navigation paths across the site. The shell must be a packaged
HTML file; absolute paths, parent traversal, hidden files, and symbolic links
are rejected. Bundles without `--spa-fallback` retain exact matching only.

Exact packaged URLs remain public, including `/` for a root-mounted
`index.html` and the shell's explicit URL. A missing client-side route does not
share that exemption. It follows the normal proof-of-work policy and receives
the shell only after the request is authorized. An explicit `--allow-prefix`
continues to authorize matching routes normally.

Fallback is deliberately conservative. It accepts only bodyless `GET` and
`HEAD` requests that explicitly accept `text/html`. When browser fetch metadata
is present, it must identify a document navigation. Requests with ranges and
paths whose final non-empty segment contains a literal or percent-encoded dot
do not fall back. This keeps missing JavaScript, stylesheet, image, and similar
asset requests from becoming successful HTML responses. Dotted client-side
route names are therefore unsupported. Query strings do not affect matching.

Configured health routes and `/ankah/` routes retain precedence. Authorized
fallback responses use `Cache-Control: private, no-cache`, navigation-aware
`Vary` fields, and the shell's normal compression and ETag support. Exact
static responses retain their existing public cache policy.

Install the Python `Brotli` package in the build stage. The helper stores
smaller gzip and Brotli versions of text, JavaScript, JSON, XML, SVG, and
WebAssembly files of at least 1 KiB. The output normally contains a version 2
`manifest.tsv`; SPA-enabled bundles use version 3 to record the fallback.
Content addressed files live under `files/`. Ankah also accepts older version
1 bundles. Put the complete directory in the runtime image at the same path
passed to `--static-bundle`. Ankah checks file hashes while loading it. Keep
the package read only at runtime. The helper skips hidden files and rejects
symbolic links. It requires a new or empty output directory.

## Dockerfile segments

Dockerfiles do not have a general `Dockerfile.inc` directive. Add these steps
to the application's Dockerfile. A named build context lets the application
copy the helper without vendoring it:

```sh
docker build --build-context ankah=../ankah -t my-app .
```

```dockerfile
# syntax=docker/dockerfile:1
FROM python:3.12-slim AS app-build
WORKDIR /app
COPY . .
# For Django, run this after dependencies are installed:
# RUN python manage.py collectstatic --noinput
RUN python -m pip install Brotli==1.2.0
COPY --from=ankah /build_static_bundle.py /usr/local/bin/build_static_bundle.py
RUN python /usr/local/bin/build_static_bundle.py \
    --project-root /app --output /opt/ankah-static

FROM your-existing-runtime-image AS runtime
COPY --from=app-build /opt/ankah-static /opt/ankah-static
# Add --static-bundle /opt/ankah-static to the existing Ankah command.
```

By default, static files under the configured prefix are public and bypass the
challenge. The optional throttle configuration described below protects only
its selected subdirectories.
Ankah serves `GET` and `HEAD`, returns 404 for unknown paths in a non-root
static namespace, and sends other URLs through the existing routing. It sends
an ETag and a short cache lifetime by default. Filenames containing a long hex
fingerprint receive an immutable cache lifetime. `Accept-Encoding` selects the
most preferred available representation, with Brotli winning ties; each has its own ETag. Byte
ranges address the selected representation, including its compressed bytes.
Single and multipart ranges are supported, up to 16 ranges per request.
Ankah keeps a 64 MiB LRU cache of compressed files used by full GET responses.
Set `--static-cache-mb N` to change its size, or `0` to disable it. Range
responses use a cached copy if one exists but do not fill the cache.

## Proof-of-work download throttling

Selected directories in a static bundle can require proof of work and share a
bounded download pool. Other packaged files remain public and are served at
full speed. For example, this permits 32 active downloads across two
directories, no more than two per solved client, 50 decimal megabits per
second across the server, and 10 decimal megabits per second per client:

```sh
ankah --public-origin https://example.com --secret-file /run/secrets/ankah \
  --static-bundle /opt/ankah-static \
  --static-throttle-prefix /downloads/ \
  --static-throttle-prefix /archives/ \
  --static-throttle-global-connections 32 \
  --static-throttle-client-connections 2 \
  --static-throttle-global-mbps 50 \
  --static-throttle-client-mbps 10 \
  -- python3 -m uvicorn app:app
```

Prefixes are repeatable directory-style URL paths ending in `/`. They must be
inside the static bundle's URL prefix. All listed prefixes share the same
global and per-client counters and bandwidth buckets. At least one connection
or bandwidth limit is required. Connection limits are positive integers no
larger than 224; the remaining public connection capacity stays available for
challenge and queue requests. An omitted global or client connection limit
uses 224. Bandwidth limits are positive whole decimal megabits per second and
may be omitted independently.

A throttled file requires a solved browser session or a uniquely identified
command-line pass. This requirement takes precedence over `--allow-prefix`.
Passes created by older Ankah versions remain valid for ordinary protected
routes, but a client must solve again before using a throttled prefix. Static
files outside the configured prefixes retain their existing public behavior.

Connection slots apply only to body-producing `GET` responses. `HEAD`, empty
files, conditional 304 responses, and error responses do not occupy a slot.
Bandwidth accounting uses the bytes in the selected representation, so gzip,
Brotli, and range responses are charged by the bytes Ankah actually schedules
for the response body rather than the uncompressed file size. TCP, TLS, and
HTTP header overhead is not included.

When no connection slot is available, Ankah records one bounded queue entry
per solved client and static file. It returns 429 with `Retry-After: 1`, an
HTML page showing the position and queue depth, and a one-second declarative
refresh. Browser tabs therefore retry without JavaScript. Duplicate tabs for
the same client and file can share a position. Queue entries expire after 15
seconds without a retry. The queue holds 4,096 entries globally and 64 per
client; a request retries without a position while either bound is full.

The scheduler shares saturated global bandwidth fairly among solved clients,
then round-robins each client's active transfers. A client's bandwidth limit
is aggregate, so two concurrent downloads share that allowance. The portable
event-loop implementation is available on Linux and Windows.
