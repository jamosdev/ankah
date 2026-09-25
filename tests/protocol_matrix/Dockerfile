ARG ANKAH_PROTOCOL_SOURCE_HASH=unverified

FROM python:3.12.13-slim-bookworm@sha256:4766d8b510c428e595d74b9cc5bbb2fae8e26316fffb4adc89908d79aacd58a2 AS native-build

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       build-essential ca-certificates cmake git gperf \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /source
COPY . .
RUN cmake -S . -B /build -DANKAH_BUNDLED_RUNTIME_DEPS=ON -DANKAH_WASM_SOLVER=OFF \
    -DANKAH_STRICT_WARNINGS=ON \
    && cmake --build /build -j 2 --target ankah
RUN python3 tests/protocol_matrix/make_static_bundle.py /protocol-static

FROM python:3.12.13-slim-bookworm@sha256:4766d8b510c428e595d74b9cc5bbb2fae8e26316fffb4adc89908d79aacd58a2 AS native
ARG ANKAH_PROTOCOL_SOURCE_HASH
LABEL org.opencontainers.image.revision=$ANKAH_PROTOCOL_SOURCE_HASH
WORKDIR /opt/ankah
COPY --from=native-build /build/ankah ./ankah
COPY --from=native-build /protocol-static ./static
COPY ankah.png particles.min.js particlejs.json challenge.js solver.py challenge-polyglot.txt phone-scan.png pow-worker.js ./assets/
COPY tests/protocol_matrix/fixture_server.py ./fixture_server.py
EXPOSE 8443/tcp 8443/udp

FROM python:3.12.13-slim-bookworm@sha256:4766d8b510c428e595d74b9cc5bbb2fae8e26316fffb4adc89908d79aacd58a2 AS client
ARG ANKAH_PROTOCOL_SOURCE_HASH
LABEL org.opencontainers.image.revision=$ANKAH_PROTOCOL_SOURCE_HASH
WORKDIR /suite
COPY tests/protocol_matrix/requirements.lock ./requirements.lock
RUN python -m pip install --no-cache-dir --require-hashes -r requirements.lock
COPY tests/protocol_matrix/ ./
ENTRYPOINT ["python"]

FROM caddy:2.11.4-alpine@sha256:de23def33b17fb5d1290b0f6c2add1d70780e52341896c00a4c8a2a2fe9d355e AS edge
ARG ANKAH_PROTOCOL_SOURCE_HASH
LABEL org.opencontainers.image.revision=$ANKAH_PROTOCOL_SOURCE_HASH
COPY tests/protocol_matrix/Caddyfile /etc/caddy/Caddyfile
