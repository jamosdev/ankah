# Release packages

Versioned releases contain three packages:

| Archive | Target |
| --- | --- |
| `ankah-linux-musl-x64.tar.gz` | x86-64 Linux, statically linked with musl |
| `ankah-macos-arm64.tar.gz` | Apple Silicon, macOS 13 or newer |
| `ankah-windows-x64.zip` | 64-bit Windows |

Each archive contains `ankah` (or `ankah.exe`), `assets/`, `LICENSE`, and
third-party notices. Keep the assets together and pass their location with
`--assets-dir`. The macOS CLI is unsigned. The checksum file in each release
covers the archives from that release host; GitLab and GitHub build separately.

## Use a release in a Dockerfile

Choose a version and copy the SHA256 for `ankah-linux-musl-x64.tar.gz` from
that release's `SHA256SUMS`. The Linux package does not require a compiler or
runtime library packages in the final image.

```dockerfile
FROM alpine:3.20 AS ankah-download
RUN apk add --no-cache ca-certificates curl
ARG ANKAH_VERSION
ARG ANKAH_SHA256
RUN test -n "$ANKAH_VERSION" && test -n "$ANKAH_SHA256" \
    && curl -fsSL "https://github.com/jamosdev/ankah/releases/download/${ANKAH_VERSION}/ankah-linux-musl-x64.tar.gz" -o /tmp/ankah.tar.gz \
    && printf '%s  %s\n' "$ANKAH_SHA256" /tmp/ankah.tar.gz | sha256sum -c - \
    && tar -xzf /tmp/ankah.tar.gz -C /opt

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=ankah-download /opt/ankah-linux-musl-x64/ankah /usr/local/bin/ankah
COPY --from=ankah-download /opt/ankah-linux-musl-x64/assets/ /opt/ankah/assets/
COPY --from=ankah-download /opt/ankah-linux-musl-x64/notices/ /usr/share/doc/ankah/notices/
COPY --from=ankah-download /opt/ankah-linux-musl-x64/LICENSE /usr/share/doc/ankah/LICENSE
# Add your application and launch Ankah with --assets-dir /opt/ankah/assets.
```

Pass both values with `docker build --build-arg ANKAH_VERSION=v1.2.3
--build-arg ANKAH_SHA256=YOUR_SHA256 ...`. Pin the base image to a digest for a
fully specified Docker build. Add any utilities your startup script needs,
such as `openssl` if it generates an Ankah secret at startup.

## Publish a version

Development changes pass GitLab checks on `mastah` and are published to
`main`. From a clean local checkout of the latest published `main`, with
`glab` authenticated to the GitLab project, run:

```sh
sh scripts/tag-release.sh v1.2.3
```

The script creates the version tag at `HEAD` and starts a GitLab release
pipeline on `mastah`. That pipeline verifies the tag points into published
`main`, builds and tests the tagged source on all three platforms, and uploads
the packages and checksums to one GitLab release. GitLab mirrors the tag to
GitHub, where a separate workflow builds and releases its own packages. If
starting the pipeline fails after the tag is created, run `glab ci run
--branch mastah --variables-env RELEASE_TAG:v1.2.3` to retry without moving
the tag.

## M1 Max runner setup

The GitLab `macos` runner uses the shell executor. Install Xcode command-line
tools and provision Homebrew with `cmake`, `ninja`, `llvm`, `lld`, `node`, `gperf`,
`python@3.12`, `openssl@3`, and `curl`. Its `llvm` installation must provide
`clang` with a WebAssembly target, and `lld` must provide `wasm-ld`; its `curl`
must support HTTP/2.
The release job checks these tools and creates a temporary Python environment
for Brotli 1.2.0 and hpack 4.2.0. It does not install Homebrew packages on the
runner. The runner needs network access to fetch the pinned CMake sources and
upload its archive as a GitLab job artifact.
