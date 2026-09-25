# HTTPS HAProxy, Ankah, and Django

This example runs TLS at HAProxy, Ankah on a private proxy network, and Django
on a separate private application network. Only HAProxy publishes port 8443.
HAProxy observes each client's socket IP, removes incoming `Forwarded` and
`X-Forwarded-For`, and sets `X-Forwarded-For` from that socket. Ankah trusts
only HAProxy's fixed `172.30.71.10/32` address. The Django app is a trusted
upstream and does not emit `Ankah-Proxy-Action`.

Run from the repository root:

```sh
ANKAH_PACKAGE_STAGE=source-build python3 examples/haproxy-django/smoke.py
```

For a published release, set `ANKAH_VERSION` to its tag and `ANKAH_SHA256`
to the Linux archive's value in the release `SHA256SUMS`, then run the same
command without `ANKAH_PACKAGE_STAGE`. The Dockerfile downloads and verifies
that binary instead of compiling Ankah. The source-build setting checks the
current checkout during development and CI.

The driver builds the images, validates the HAProxy configuration, and checks
HTTPS Django access, scanning, a connection-only flood, stalled request bodies,
incomplete request headers, source isolation, and access after each 60-second
ban expires. It uses two
long-lived client containers with different source IPs. The self-signed
`localhost` certificate and Ankah secret are generated at startup and are
not persisted. The smoke run takes several minutes because it observes actual
timeouts and stick-table expiry.

For manual exploration:

```sh
ANKAH_VERSION=v1.2.3 ANKAH_SHA256=YOUR_SHA256 \
  docker compose -f examples/haproxy-django/compose.yml up --build -d
curl -k https://localhost:8443/health
docker compose -f examples/haproxy-django/compose.yml down --volumes
```

The `/health` and `/upload` paths bypass the proof challenge so the smoke driver
can exercise Django and body timeouts. Other application paths are challenged.
The policy and response field are described in [the proxy abuse guide](../../docs/proxy-abuse.md).
