# DOTS data-channel filtering

Ankah can act as an RFC 8783 DOTS data-channel client. The feature is off by
default. When enabled, Ankah watches challenged traffic from trusted proxies and
asks an upstream filtering point to drop repeat flood traffic before it reaches
Ankah again.

This is a fail-open integration. Request handling never waits for DOTS, and a
DOTS error only logs and increments metrics.

## Configuration

Set `--dots-server` to enable the client. Once it is set, the full connection
and protected-service configuration is required:

```sh
ankah \
  --trusted-proxy 172.30.1.10/32 \
  --dots-server 172.30.1.10:4443 \
  --dots-server-name edge-dots.demo.test \
  --dots-ca-file ca.crt \
  --dots-cert-file ankah-dots-client.crt \
  --dots-key-file ankah-dots-client.key \
  --dots-cuid ankah-demo \
  --dots-protected-network 172.30.0.11/32 \
  --dots-protected-port 80
```

All DOTS options can also be provided through environment variables using the
`ANKAH_DOTS_` prefix, or through the config file using the same kebab-case names
as the command line.

| Option | Default | Meaning |
|---|---:|---|
| `--dots-server` | unset | DOTS HTTPS data-channel address as `ip:port` or `[ipv6]:port`. Host names are not resolved and are rejected. Setting it enables DOTS. |
| `--dots-server-name` | unset | TLS server name and SNI value. |
| `--dots-path` | `/v1/restconf` | RESTCONF base path: starts with `/`, no trailing `/`, letters, digits, `/ - _ .` only. |
| `--dots-ca-file` | unset | CA bundle used to verify the DOTS server. |
| `--dots-cert-file` | unset | Client certificate for mTLS. |
| `--dots-key-file` | unset | Client private key for mTLS. |
| `--dots-cuid` | unset | DOTS client identifier, 1 to 63 characters from `A-Z a-z 0-9 - _`. |
| `--dots-protected-network` | unset | Destination prefix Ankah may protect. |
| `--dots-protected-port` | `80` | Destination TCP port in the installed ACL. |
| `--dots-threshold` | `10` | Challenged requests from one client before escalation, 1 to 64. |
| `--dots-window-seconds` | `5` | Sliding window for the threshold, 1 to 3600. |
| `--dots-block-seconds` | `45` | Time before Ankah withdraws an installed ACL, 1 to 86400. |

DOTS also requires at least one `--trusted-proxy`. Setting a connection or
identity option (`--dots-server-name`, `--dots-ca-file`, `--dots-cert-file`,
`--dots-key-file`, `--dots-cuid`, `--dots-protected-network`) without
`--dots-server`, leaving one of them out, or enabling DOTS without a trusted
proxy is a configuration error and Ankah exits at startup. The client
certificate, key and CA are loaded at startup, so an unreadable or mismatched
file also stops Ankah from starting.

## Trigger model

DOTS escalation only uses Ankah's resolved client address after trusted-proxy
processing. A direct peer that is not in `--trusted-proxy` can be challenged, but
it cannot trigger DOTS. A resolved address that is the proxy itself, or that
falls inside a trusted proxy network, is never escalated. This keeps upstream
filtering tied to a deployment where the edge proxy is explicitly trusted.

Each escalation installs one ACL named `ankah-<address>` that drops TCP from
the client's `/32` (or `/128`) to `--dots-protected-network` on
`--dots-protected-port`. The client address and the protected network must be
the same address family; otherwise no request is sent, and the escalation is
counted as a failed install
(`ankah_dots_operations_total{operation="install",result="error"}`). Ankah withdraws the ACL with a `DELETE` after
`--dots-block-seconds`, because the ACL body carries no lifetime of its own.

Ankah keeps the ACLs it installed in memory only, so a restart forgets them.
After registration succeeds it therefore lists the client's ACLs and withdraws
every `ankah-*` ACL left by a previous process. It does not delete and recreate
its `dots-client` registration for this, because the go-dots server used in the
worked example removes those rows without stopping the rules already enforced.

## Limits and retries

- Operations run one at a time from a queue of 64. Each has a 5 second
  timeout.
- At most 256 ACLs are tracked. Escalations beyond that, or while the client is
  not registered, are not sent and are counted as dropped.
- Registration is retried with backoff from 1 second up to 30 seconds. An
  install answered with 404 marks the client unregistered, which triggers a new
  registration.
- A failed withdrawal is retried every 5 seconds. A 404 on withdrawal counts as
  success, since the server no longer holds the ACL.
- The per-address threshold table holds 1,024 addresses and evicts the least
  recently seen one.

## Metrics

When DOTS is enabled, Ankah exposes these metrics through the configured
dashboard listener or dashboard public route:

```text
ankah_dots_escalations_total
ankah_dots_dropped_total
ankah_dots_operations_total{operation="register|list|install|withdraw",result="ok|error"}
ankah_dots_active_acls
ankah_dots_registered
```

Keep a dashboard listener private when using one, and require the bearer token
in every setup, as described in [monitoring](monitoring.md) and [the operator
dashboard](dashboard.md).

## Worked example

The worked example in `examples/dots-benchmark` runs Ankah, Anubis, two Python
backends, Prometheus, Grafana, cAdvisor and a small edge proxy. The edge embeds
the pinned go-dots RFC 8783 data-channel router and maps validated ACLs to a
source and destination scoped pre-HTTP connection reject.

The example is intentionally limited:

- Filtering happens in userspace after the TCP connection is accepted.
- It is not SYN filtering, kernel filtering, accept-queue protection, or a
  production DDoS mitigation service.
- The attacker in the demo never solves a challenge, so neither backend receives
  attacker Pi requests. The visible difference is in the protection layer:
  Anubis keeps issuing challenges, while Ankah escalates to an edge reject for
  the active block window.
