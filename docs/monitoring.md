# External health monitoring

Ankah can expose local gateway health routes and Prometheus metrics. Both are
off by default. The health switches affect the public listener. Metrics are
available through the configured dashboard listener or dashboard public route.

Run monitors outside the application host when possible. A separate host or
failure domain can detect machine, network, and process failures that a monitor
beside the gateway cannot see.

## Gateway health routes

Each switch enables one exact public path at its conventional location:

```sh
./ankah ... --ankah-healthz --ankah-livez --ankah-readyz
```

Use an equals sign to choose a different location:

```sh
./ankah ... --ankah-livez=/ankah/livez
```

The routes answer `GET` and `HEAD` with status 200 and `ok`. Query parameters
do not affect matching. They use the normal public Host checks, trusted proxy
processing, rate limit, and traffic statistics, but they bypass the challenge
and never contact the application. A configured path takes precedence over an
Ankah internal route, a packaged static file, or an application route.

Use these checks for different scopes:

| Check | Example | What it proves |
| --- | --- | --- |
| Gateway only | Enable `--ankah-livez` and request `/livez` | The network path and Ankah event loop can answer a request |
| Application | Leave `/healthz` unclaimed by Ankah, allow that prefix, and implement it in the application | Ankah can connect to the application and the application reports healthy |
| Real static asset | Request a known file such as `/static/app.abcdef1234.js` | The public route, static manifest, stored file, and response path work |

Relocate an Ankah route when both gateway and application checks use the same
conventional name. For example, use `--ankah-livez=/ankah/livez` and leave the
application's `/livez` route untouched.

An application health route still follows normal challenge policy. Add a
narrow exemption such as `--allow-prefix /healthz`, or use whatever solved
session or pass the monitor normally uses.

Public requests use separate anonymous, protected, and crawler rate buckets. A valid
solved session or pass selects the protected bucket, except on `/ankah/`
endpoints, which always use the anonymous bucket. A public `--allow-prefix`
path without proof also uses the anonymous bucket. The protected global limit
is 1,000 requests burst and 500 per second, with 200 burst and 100 per second
per resolved client address. Anonymous limits are 200 burst and 100 per second
globally, with 40 burst and 20 per second per address. Each class has its own
client table, so anonymous scans do not spend protected tokens.

Published [Google common-crawler ranges](https://developers.google.com/crawling/ipranges/common-crawlers.json)
bypass the challenge and use the
crawler bucket, which permits a burst of 10 requests and refills at 2 requests
per second. Bingbot claims reserve the single crawler slot while an asynchronous
reverse lookup and matching forward lookup verify a `search.msn.com` or
`bing.com` name. Only one crawler request or Bing lookup may be active across
the process. A second crawler request receives `429 Too Many Requests` with a
one-second retry hint. Crawler matching uses the resolved client address, so a
proxy must be listed with `--trusted-proxy` before its forwarding headers can
identify a crawler.

At most 192 anonymous and 32 header-pending sockets can occupy each public
connection layer, out of its 256-socket limit. Unsolved challenges issued
without proof are limited to 3,072 globally and 64 per resolved address, out
of 4,096 total session slots. These limits leave room for established clients
when an admission slot is available. A continuous connection flood can still
prevent a new client from connecting before it can present proof.
Incomplete direct request headers expire after five seconds. Direct TLS uses
an absolute ten-second handshake deadline and a five-second header deadline
after the handshake.

Prefer a real, versioned static asset over a synthetic static health file. It
detects missing or stale deployment content. Treat a 200 response with the
expected body or digest as success.

## Prometheus metrics

Enable the dashboard as described in [the operator dashboard](dashboard.md),
then scrape `GET /metrics` on its private listener with its bearer token:

```yaml
scrape_configs:
  - job_name: ankah
    authorization:
      type: Bearer
      credentials_file: /run/secrets/ankah_dashboard
    static_configs:
      - targets: ["127.0.0.1:9000"]
```

The response uses Prometheus text format. It contains cumulative traffic and
gateway event counters, response class counters, upstream response latency,
current and peak resource gauges, configured limits, and the statistics epoch.
It does not contain request paths, client addresses, or hourly and daily
history. Scrapes on the dashboard listener are excluded from the statistics
they expose. When using `--dashboard-public-route=/ankah-admin/`, scrape
`GET /ankah-admin/metrics` on the public origin instead. The route still
requires the bearer token and is excluded from the reported statistics.

Keep the dashboard listener private. If Prometheus runs on another machine,
use a private network, tunnel, or authenticated proxy instead of publishing
the plain HTTP listener on an Internet-facing interface.

## Uptime Kuma example

This standalone Compose deployment uses the Uptime Kuma 2 image tag from the
[official Compose example](https://github.com/louislam/uptime-kuma/blob/master/compose.yaml),
stores its state in a local directory, and exposes its management page only on
the host loopback interface:

```yaml
services:
  uptime-kuma:
    image: louislam/uptime-kuma:2
    container_name: uptime-kuma
    volumes:
      - ./uptime-kuma-data:/app/data
    ports:
      - "127.0.0.1:3001:3001"
    restart: always
```

Start it with `docker compose up -d`, then reach the management page locally at
`http://127.0.0.1:3001`. For remote administration, forward that loopback port
over SSH. Configure HTTP monitors for the gateway-only, application, and real
static asset URLs described above. Place this deployment on a separate host or
failure domain from Ankah for useful external failure detection.
