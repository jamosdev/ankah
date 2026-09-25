# Trusted proxy abuse actions

Ankah can ask a configured trusted reverse proxy to block the client associated
with an Ankah-generated response. Set `--trusted-proxy` to the direct proxy
address or CIDR and select `--proxy-abuse-profile=off|conservative|strict`.
The default profile is `conservative`. Without a trusted direct peer, Ankah
never emits an action. The response field is private to this deployment:

```http
Ankah-Proxy-Action: block
```

The field contains an action, never a client address. The proxy chooses the
source address, ban duration, and enforcement method. The example uses
[HAProxy and Django](../examples/haproxy-django/README.md) and rejects marked
sources when they next connect. HAProxy strips the field before delivering the
response. Ankah sends at most one action per resolved client IP in 60 seconds. Clients
sharing that IP share the same counters and proxy ban.

For standards-based upstream filtering, Ankah also has an optional
[RFC 8783 DOTS data-channel client](dots.md). That path installs and withdraws
filtering ACLs over mTLS instead of returning the private
`Ankah-Proxy-Action` response field.

| Trigger | Conservative | Strict |
| --- | --- | --- |
| Invalid proof answers | 8 in 60 seconds | 4 in 60 seconds |
| Rejections by the client's rate bucket | 8 in 60 seconds | 4 in 60 seconds |
| Unproved challenged path scanning | 40 requests and 32 paths in 30 seconds | 20 requests and 16 paths in 30 seconds |
| Incomplete bodies after complete headers | 3 in 10 minutes | 2 in 10 minutes |

Path scanning uses the path without its query string. Ankah routes, health
routes, and packaged static files are excluded. The bounded policy stores
4,096 exact client IPs with oldest-entry eviction and a 256-bit path sketch
per entry; it does not retain raw paths. Distributed traffic that exhausts the
global rate bucket does not contribute to the per-client rate trigger.

For a trusted proxy peer, a stalled body after complete request headers can
receive `408 Request Timeout`, including a block action when the threshold is
reached. A connection without complete headers, or one whose final response
has started, closes without a new response. The proxy's client and server
timeouts should exceed Ankah's 30-second idle timeout.

`ankah_proxy_abuse_actions_total{reason="invalid_proof|client_rate|path_scan|body_stall"}`
is a process-lifetime Prometheus counter. These values are not part of the
persisted statistics snapshots.

Only deploy this contract with a proxy that directly observes the client IP
it will block. Ankah resolves a client IP from trusted forwarding fields, while
the proxy acts on its own socket source. All responses pass through Ankah, so a
trusted upstream application could also emit this field. The example Django
app does not emit it.
