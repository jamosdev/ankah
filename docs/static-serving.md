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

Install the Python `Brotli` package in the build stage. The helper stores
smaller gzip and Brotli versions of text, JavaScript, JSON, XML, SVG, and
WebAssembly files of at least 1 KiB. The output contains a version 2
`manifest.tsv` and content addressed files under `files/`. Ankah also accepts
older version 1 bundles. Put the complete directory in the runtime image at the same path
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
RUN python -m pip install Brotli==1.1.0
COPY --from=ankah /build_static_bundle.py /usr/local/bin/build_static_bundle.py
RUN python /usr/local/bin/build_static_bundle.py \
    --project-root /app --output /opt/ankah-static

FROM your-existing-runtime-image AS runtime
COPY --from=app-build /opt/ankah-static /opt/ankah-static
# Add --static-bundle /opt/ankah-static to the existing Ankah command.
```

Static files under the configured prefix are public and bypass the challenge.
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
