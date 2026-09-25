# DOTS benchmark worked example

This example demonstrates one architectural property:

> An application can signal a source and destination filtering decision to a
> cooperating upstream proxy using RFC 8783 DOTS data-channel semantics, and
> later connections matching that rule are then rejected by the proxy before
> any HTTP parsing or protected-service processing.

**This is not SYN-flood protection, kernel-level filtering, reserved
accept-queue capacity, or production DDoS mitigation.** The edge rejects a
matching connection in userspace, after the TCP handshake has completed and
`accept()` has returned. Everything runs on one Docker host, and the load comes
from one container.

The demonstration measures a hypothesis. It does not assume the answer:

> **H1:** after DOTS escalation, repeated malicious connections to the
> Ankah-protected destination consume materially less protected-service and
> backend CPU, because they are rejected by a cheap destination-scoped pre-HTTP
> check at the upstream edge.

The example has done its job if it shows the mechanism and exposes honest
measurements, whatever ordering a particular machine produces.

## Topology

```
                         front 172.30.0.0/24
  attacker 172.30.0.20 ─┐
                        ├──> edge 172.30.0.10:80  (anubis.test) ──> Anubis ──> FastAPI /pi
  legit-probe .21 ──────┘    edge 172.30.0.11:80  (ankah.test)  ──> Ankah  ──> Django  /pi
                                   ^                                  │
                                   │  RFC 8783 data channel, mTLS     │
                                   └── 172.30.1.10:4443 <─────────────┘
                                       (go-dots router, backend network only)

  cAdvisor ──> Prometheus ──> Grafana (127.0.0.1:3000)
```

| Service | Role | Network and address | Limits |
|---|---|---|---|
| `certs` | One-shot: demo CA, DOTS server and client certs, tokens, Anubis key | none | |
| `mysql` | go-dots data channel state | backend `172.30.1.40` | |
| `edge` | Go reverse proxy, ACL check, go-dots data channel server | front `.10` and `.11`, backend `.10` | 2 CPU, 256 MB |
| `anubis` | Anubis v1.27.0 in front of FastAPI | backend `.20` | 1 CPU, 256 MB |
| `ankah` | Released Ankah with DOTS enabled, in front of Django | backend `.21` | 1 CPU, 256 MB |
| `fastapi` | `/pi` on uvicorn, 2 workers | backend `.30` | 1 CPU, 256 MB |
| `django` | `/pi` on gunicorn, 2 sync workers | backend `.31` | 1 CPU, 256 MB |
| `attacker` | Strictly alternating load, new connection per request | front `.20` | 1 CPU, 128 MB |
| `legit-probe` | Low-rate legitimate client for both sites | front `.21` | 0.5 CPU, 128 MB |
| `cadvisor` | Container CPU, memory and network | monitor `172.30.2.30` | |
| `prometheus` | Scrapes everything every 5 s | front, backend, monitor | |
| `grafana` | Provisioned `DOTS Benchmark` dashboard | monitor `172.30.2.20` | |

The backend network is `internal: true`. No application, protection layer or
DOTS port is published to the host. The edge is the only path from the front
network to the applications.

## Quickstart

```sh
cd examples/dots-benchmark
export ANKAH_VERSION=v1.2.3
export ANKAH_SHA256=YOUR_SHA256
docker compose up --build        # or: make up
```

The image downloads the selected package and verifies its SHA256. Set
`ANKAH_PACKAGE_STAGE=source-build` to build the Ankah checkout when testing
changes before a release; no version or hash is needed in that mode.

There is no separate setup step. The `certs` service creates the demo
credentials in the `demo-certs` volume on first start and reuses them after
that.

- Grafana: <http://localhost:3000>, with anonymous read-only access and the
  dashboard as the home page.
- Prometheus: <http://localhost:9090>

If those ports are taken, choose others:

```sh
GRAFANA_PORT=3001 PROMETHEUS_PORT=9091 make up
```

`make down` stops the demo. `make reset` also removes the credentials volume.
`make logs` and `make ps` wrap the matching Compose commands.

The MySQL 5.7.44 image go-dots is built against is published for amd64 only.

## What happens during a run

1. **Startup.** The attacker and probe wait until
   `http://anubis.test/healthz` and `http://ankah.test/healthz` answer through
   the edge. Those routes are allowed by both protection layers and only answer
   once the backends are up. The edge opens its frontends only after the DOTS
   endpoint is serving, so a reachable frontend also means filtering can work.
2. **Pre-escalation.** The attacker alternates `anubis.test`, `ankah.test`,
   `anubis.test`, ... Anubis and Ankah both answer every attacker request with a
   challenge (`428` from both, the Anubis status set by the demo policy).
3. **Escalation.** After `DOTS_THRESHOLD` challenged requests within
   `DOTS_WINDOW_SECONDS` from one client, Ankah registers if needed, then sends
   `PUT .../dots-client=ankah-demo/acls/acl=ankah-172-30-0-20` over mTLS. go-dots
   authenticates the client, validates the ACL, stores it and hands it to the
   edge. The edge then installs a `172.30.0.20/32 -> 172.30.0.11/32 tcp/80 drop`
   rule.
4. **Early rejection.** New attacker connections to `172.30.0.11` are closed
   with a TCP reset straight after `accept()`, before `net/http` reads a byte.
   The same attacker's requests to `anubis.test` are unaffected, and so is the
   probe's traffic to `ankah.test`.
5. **Withdrawal.** After `DOTS_BLOCK_SECONDS`, Ankah sends a `DELETE` for the ACL
   and the edge removes the rule. Attacker requests reach Ankah again, and if they
   keep coming Ankah escalates again. The cycle repeats, which makes the effect
   easy to see on the graphs.

## Reading the dashboard

The `DOTS Benchmark` dashboard marks every ACL install and withdrawal with an
annotation. At an install, expect:

- `Edge Connection Gate`: rejects for the `ankah` frontend jump from zero to the
  attacker's Ankah rate. Accepted connections there drop to the probe's rate.
  The `anubis` frontend is unchanged.
- `Challenge Issue Rate`: Ankah challenges fall to near zero, and Anubis
  challenges continue.
- `Container CPU Cores`: this is the H1 measurement. Compare `ankah` and `edge`
  against `anubis`, both before and during the ACL.
- `Legit Probe Results` and `P50 and P95 Latency`: successes continue on both sites.
- `Backend Pi Requests`: only legit traffic, on both backends.

All graphs show absolute values: requests or bytes per second, cores and
bytes. Nothing is normalised.

**Important for interpreting H1.** The attacker never solves a challenge, so in
this configuration **neither backend receives attacker Pi requests on either
path**. The backend Pi work comes from the probe only. What the demo measures is
protection-layer work: Anubis rendering challenges, compared with Ankah
rendering challenges until escalation and the edge closing sockets afterwards.
Anubis and Ankah also differ in how expensive a challenge is to produce, so
compare each path before and during its own ACL window, not only against the
other path.

## Why the design looks like this

**Two frontend destination addresses.** A DOTS filtering rule names a source
and a destination prefix. Both sites share the edge. If both lived on one
address, a rule protecting Ankah would also cut the attacker off from Anubis,
and the comparison would be lost. So `anubis.test` is `172.30.0.10` and
`ankah.test` is `172.30.0.11`. Docker Compose gives a container one address per
network. The edge therefore gets `cap_add: [NET_ADMIN]`, and `edge/start.sh`
uses it for one thing only: adding the secondary address. It then drops every
capability, switches to an unprivileged user and starts the proxy. Filtering
never uses `NET_ADMIN`.

**Each address serves only its own site.** A request for `ankah.test` sent to
`172.30.0.10` gets `421 Misdirected Request`, and an unknown host gets the same.
Without this, a blocked client could reach Ankah through the Anubis address and
step around a destination-scoped rule.

**Source and destination scope.** The ACL matches source prefix, destination
prefix, protocol and destination port. It is not a global source ban: the same
attacker keeps full access to the other destination. Ankah can only name its
own frontend address (see mTLS identity below).

**A new TCP connection per request.** The reject happens when a connection is
accepted. With keep-alive, a client that connected before the rule was
installed would keep sending requests on its existing connection, and the
rule would have no visible effect. The attacker disables connection reuse
and sends `Connection: close`, so every request shows whether admission was
allowed. The same goes for the probe, and for the edge towards backends
(pooled, since that side is not what is being measured).

**Forwarded identity.** The edge removes `Forwarded`, `X-Forwarded-*` and
`X-Real-Ip` from client requests. It then sets `X-Forwarded-For` and
`X-Real-Ip` from the real socket peer. Ankah trusts only the edge
(`--trusted-proxy 172.30.1.10/32`) and escalates only a client address supplied
by that trusted proxy. A client-supplied header can never pick the address that
gets blocked.

## mTLS identity

The `certs` service creates a demo CA and two certificates from it:
- `edge-dots.crt`, a server certificate for `edge-dots.demo.test` and
  `172.30.1.10`. Ankah requires this name and this CA.
- `ankah-dots-client.crt`, a client certificate with subject CN
  `ankah-demo-client`.

The edge requires a client certificate from the demo CA. go-dots maps the
client certificate's subject CN to its `customer` table. The demo seed
(`mysql/02-seed.sql`) creates that customer with one `ADDRESS_RANGE` prefix,
`172.30.0.11/32`. go-dots rejects any ACL whose destination is outside that
range with `400 bad-attribute`. So even a misbehaving Ankah could not ask the
edge to filter traffic to the Anubis address.

The keys are throwaway demo material in a Docker volume, readable by the
unprivileged service users. They are not copied into any image and nothing
from the developer machine is used.

## go-dots

The edge embeds [go-dots](https://github.com/nttdots/go-dots) at commit
`4e631d1257fd6a5d1f7201c2d06d63c7ace88940` (2025-04-17). It is fetched at build
time by `edge/third_party/fetch-go-dots.sh`, which checks the commit and
applies the patches in `edge/third_party/patches/`.

**Reused unchanged:**
- the data channel HTTP router
- the data channel controllers for client registration and ACLs
- the request types and ACL validators
- the models and database models, with client certificate to customer
  authentication
- the address range check
- the ACL expiry manager

**Not used:** the CoAP signal channel, libcoap, GoBGP and Arista enforcement,
and the `dots_server` command itself. The edge replaces only the command's
`main` and TLS listener setup.

**Transport.** The upstream README still warns that the data channel uses CoAP.
That note dates from 2017. The current source serves the data channel over
HTTPS/RESTCONF (`dots_server/restconf.go`, added in 2018), and that is the path
this demo uses: `application/yang-data+json` under `/v1/restconf`.

**Local patches:**
- `0001`: moves the libcoap-typed code in `dots_common` behind a `dots_nocoap`
  build tag. The data channel then builds with `CGO_ENABLED=0` without libcoap.
  A build without the tag is unchanged.
- `0002`: adds an `External-ACL` blocker type. go-dots hands validated ACLs to
  a registered in-process handler instead of a router, while keeping its normal
  protection bookkeeping. It also makes the protection-row code accept that type
  instead of panicking.

**Schema.** The MySQL schema is the upstream `template.sql`, checked by
SHA-256. The `MySQLNotification` UDF and the triggers that call it are removed,
because they feed the signal channel through a native plugin the demo does not
build. `mysql/02-seed.sql` adds the customer, address range, blocker and blocker
configuration.

**What this claims.** The demo *uses the go-dots RFC 8783 data-channel model
and path*. It does not claim full DOTS interoperability. Deviations observed in
the pinned code:
- `DELETE dots-client` deletes the client's rows but does not stop
  enforcement of its active ACLs. Ankah therefore never uses it.
- Deleting an ACL sets its activation type to `not-type` rather than removing
  the row.
- The ACL lifetime is fixed at 7 days, and `pending-lifetime` cannot be sent.
  Ankah enforces the demo's short block time itself with an explicit `DELETE`.
- The controllers read a `cdid` path parameter that no route defines, so the
  `cdid` check never runs.

The edge accepts only the ACL matches it can enforce exactly: IPv4 or IPv6
source and destination prefixes, protocol, a TCP or UDP destination port or
range, and a `drop` action. Anything else is refused, and go-dots rolls the
request back rather than installing a broader rule than asked for.

## Tuning

Set these in the environment for `make up` or `docker compose up`:

| Variable | Default | Effect |
|---|---:|---|
| `ATTACK_RPS` | `40` | Attacker issue rate, both targets together |
| `ATTACK_CONCURRENCY` | `32` | Attacker requests in flight |
| `PI_N` | `200000` | Pi iterations per request (attacker and probe), capped at 2,000,000 by the backends |
| `PROBE_RPS` | `1` | Legit probe rate, both targets together |
| `DOTS_THRESHOLD` | `10` | Challenged requests before Ankah escalates |
| `DOTS_WINDOW_SECONDS` | `5` | Window for the threshold |
| `DOTS_BLOCK_SECONDS` | `45` | How long an installed ACL stays before Ankah withdraws it |
| `GRAFANA_PORT` | `3000` | Host port for Grafana on 127.0.0.1 |
| `PROMETHEUS_PORT` | `9090` | Host port for Prometheus on 127.0.0.1 |

The attacker issues requests from one scheduler goroutine: request `n` goes to
target `n mod 2`. When all concurrency slots are busy it waits rather than
skipping a target, so a slow site slows both sites equally. It never lowers
the load on one site because the other got slower.

## Inspecting ACLs

What the edge is enforcing now:

```sh
docker compose exec edge curl -s http://172.30.1.10:9100/acls
```

What go-dots holds for the Ankah client, read over mTLS with Ankah's
credentials:

```sh
docker compose exec edge curl -s \
  --resolve edge-dots.demo.test:4443:172.30.1.10 \
  --cacert /run/demo-certs/ca.crt \
  --cert /run/demo-certs/ankah-dots-client.crt \
  --key /run/demo-certs/ankah-dots-client.key \
  https://edge-dots.demo.test:4443/v1/restconf/data/ietf-dots-data-channel:dots-data/dots-client=ankah-demo/acls
```

Other ways to watch:
- Ankah logs each escalation, install and withdrawal
  (`docker compose logs -f ankah`).
- The edge logs every DOTS request with its status.
- `edge_dots_acls` and `ankah_dots_active_acls` show the current count.

Attacker addresses appear only in these logs and the `/acls` output, never as
Prometheus labels.

## Smoke test

```sh
make test          # or: python3 smoke.py
```

A clean run replaces any running copy of this demo: it runs
`docker compose down -v` first and again at the end, which also deletes the
credentials volume. Use `--keep` to leave the stack up after a pass, or
`--use-running` to check a stack that is already up without restarting it.

The smoke test uses `DOTS_BLOCK_SECONDS=20` and binds Grafana and Prometheus to
3001 and 9091 so it does not collide with a demo on the default ports. Override
them with `SMOKE_GRAFANA_PORT` and `SMOKE_PROMETHEUS_PORT`.

It checks:
- both sites answer and both backends receive legit traffic
- the attacker alternates strictly
- Ankah registers and installs a real go-dots ACL, which the edge then enforces
- attacker connections to the Ankah address are rejected without ever reaching
  the HTTP handler, while the Anubis address keeps challenging
- the probe keeps succeeding
- no attacker request reaches a backend
- after withdrawal the attacker reaches Ankah again
- every Prometheus target is up and Grafana has the dashboard

The Ankah side of the DOTS client also has its own tests in the main tree:
`tests/dots_policy_test.c` and `tests/dots_integration_test.py`.

## Exposure

This is a local demo:
- Grafana is anonymous and read-only, and bound to 127.0.0.1.
- Prometheus is bound to 127.0.0.1, and also sits on the front network so it
  can scrape the load generators. It has no authentication.
- The DOTS endpoint and the edge's `/acls` and `/metrics` listener are on the
  internal backend network only.
- cAdvisor runs privileged with read access to host paths, as it needs to read
  container statistics.

## Versions

Every image is pinned by digest in the Dockerfiles and `compose.yaml`.

| Component | Version |
|---|---|
| go-dots | `4e631d1257fd6a5d1f7201c2d06d63c7ace88940` plus local patches |
| Anubis | `ghcr.io/techarohq/anubis:v1.27.0` |
| cAdvisor | `ghcr.io/google/cadvisor:v0.60.6` |
| Prometheus | `prom/prometheus:v3.14.0` |
| Grafana | `grafana/grafana:13.2.2` |
| MySQL | `mysql:5.7.44` |
| Go toolchain | `golang:1.27.1-trixie` |
| Edge and loadgen runtime | `debian:trixie-slim` |
| Python | `python:3.13.15-slim-trixie` |
| Ankah build and runtime | `alpine:3.20` |
| Python packages | fastapi 0.141.1, uvicorn 0.53.0, Django 6.1.1, gunicorn 26.2.0, prometheus-client 0.26.0 |
| Go modules | pinned in `edge/go.sum` and `loadgen/go.sum` |

## Licensing

go-dots is licensed under the Apache License 2.0. This repository does not
contain go-dots source; it contains only the fetch script and the two patch
files, which modify go-dots and are therefore Apache 2.0 derived work. An edge
image built from this example contains modified go-dots code. If you
distribute such an image, Apache 2.0 section 4 applies:
- include the go-dots `LICENSE`
- state that files were changed; the patch files list them.

The root [README](../../README.md#licenses) carries the license text.
