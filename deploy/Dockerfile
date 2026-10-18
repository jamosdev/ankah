ARG ANKAH_PACKAGE_STAGE=source-build

FROM alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc AS source-build
RUN apk add --no-cache cmake ninja gcc g++ musl-dev linux-headers git clang lld curl openssl python3
WORKDIR /src
COPY . .
RUN cmake -S . -B /build -G Ninja -DCMAKE_BUILD_TYPE=Release \
      -DANKAH_STRICT_WARNINGS=ON -DANKAH_BUNDLED_RUNTIME_DEPS=ON -DANKAH_STATIC_LINUX=ON \
 && cmake --build /build --target ankah -j 2 \
 && cmake --install /build --component ankah_runtime --prefix /opt/ankah

FROM alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc AS release-fetch
RUN apk add --no-cache ca-certificates curl
ARG ANKAH_VERSION
ARG ANKAH_SHA256
RUN test -n "$ANKAH_VERSION" && test -n "$ANKAH_SHA256" \
 && curl -fsSL "https://github.com/jamosdev/ankah/releases/download/${ANKAH_VERSION}/ankah-linux-musl-x64.tar.gz" -o /tmp/ankah.tar.gz \
 && printf '%s  %s\n' "$ANKAH_SHA256" /tmp/ankah.tar.gz | sha256sum -c - \
 && tar -xzf /tmp/ankah.tar.gz -C /opt \
 && mv /opt/ankah-linux-musl-x64 /opt/ankah

FROM ${ANKAH_PACKAGE_STAGE} AS package

FROM alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc
RUN apk add --no-cache ca-certificates
COPY --from=package /opt/ankah /opt/ankah
USER 10001:10001
WORKDIR /var/lib/ankah
STOPSIGNAL SIGTERM
ENTRYPOINT ["/opt/ankah/ankah"]
CMD ["--config", "/etc/ankah/ankah.conf"]
