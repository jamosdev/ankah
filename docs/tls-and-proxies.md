# TLS, HTTP/2, HTTP/3, and proxy addresses

## Direct TLS

Pass an unencrypted PEM private key and a PEM certificate chain together:

```sh
./ankah --listen 0.0.0.0:8443 \
  --public-origin https://example.test:8443 \
  --tls-cert /run/secrets/example-chain.pem \
  --tls-key /run/secrets/example-key.pem \
  --secret-file /run/secrets/ankah.secret \
  --upstream 127.0.0.1:8001
```

Both TLS options are required when either is present, and the public origin
must use `https`. Without these options the listener continues to accept plain
HTTP/1.1, including deployments behind a separate TLS terminator.

The TCP TLS listener accepts TLS 1.2 and newer. It advertises `h2` and
`http/1.1` with ALPN. A TLS deployment also starts a UDP listener on the
configured `--listen` address and port, enables QUIC with the `h3` ALPN, and
advertises `Alt-Svc` on HTTP/1.1 and HTTP/2 responses. The advertised port
comes from `--public-origin`, including its implicit HTTPS port 443. Ankah
exits during startup if the UDP bind fails. Open the corresponding UDP port
when upgrading an existing direct TLS deployment. Use `--http3 off`,
`ANKAH_HTTP3=off`, or `http3 = off` in the configuration file to disable
native HTTP/3 and its advertisement.

HTTP/2 and HTTP/3 terminate at Ankah. Each stream uses a private HTTP/1.1
connection to the application core. Cleartext HTTP/2 and HTTP/2 or HTTP/3
connections to the application server are not enabled.

Ankah streams HTTP/2 request bodies with a valid `Content-Length` to the
application as they arrive. Allowed routes and clients that have solved the
challenge use the limit configured by `--max-upload-mb`; blocked and locally
handled routes retain the 16 MiB limit. HTTP/2 bodies without a declared
length are held in memory until the stream ends and remain limited to 16 MiB
per stream and 64 MiB per connection. An unknown-length stream that exceeds
16 MiB receives a 413 response immediately. If the connection's 64 MiB
buffer is full, the affected stream receives 503. In either case, Ankah
stops that upload after sending the complete response and keeps other streams
on the connection available. Until the stream ends, an unknown-length body has
no core upload deadline. The frontend normally closes its connection after
120 seconds without traffic, but defers that timer while another large
declared-length stream is governed by the core's deadlines.

Declared-length streams use separate connection and stream flow control. Data
admitted to a bounded per-stream queue immediately releases connection credit,
while stream credit waits until the application write succeeds. A stalled
application therefore closes only its request stream window and does not stop
other streams or HTTP/2 control frames on the same connection. The initial
stream window and per-stream queue limit are 512 KiB, and the connection
window is 16 MiB. Declared-length request queues are limited to 128 MiB across
all frontend connections. A stream that reaches this shared limit receives
503. The core's upload and five-minute first-final-reply deadlines govern
streams larger than 16 MiB; the frontend's 120-second idle timer resumes when
their final response starts or the stream closes. Interim 1xx responses do not
extend the first-final-reply deadline.

HTTP/3 accepts at most 256 QUIC connections, 32 request streams per
connection, and 256 request streams in total. Declared-length request streams
use a 512 KiB stream window and queue, a 16 MiB connection window, and a
128 MiB shared queue. Stream credit is returned after the private core write
completes. Requests without a declared length are buffered until the stream
ends, with limits of 16 MiB per stream and 64 MiB per connection and across
all connections. The core applies the configured upload limit. Request
trailers receive a 400 response if no final response has started; otherwise
the stream is reset. Response trailers are forwarded. Response
data waits in queues of at most 2 MiB per stream, 8 MiB per connection, and
64 MiB overall; Ankah pauses core reads until the client acknowledges data.
Cancelled streams close their private core connection.

QUIC requires a valid Retry token before allocating connection state. Tokens
expire after 10 seconds, and Retry packets are constrained by the
amplification limit. Handshakes have a 10-second deadline and established
connections have a 120-second idle timeout. Connection IDs route packets to
their existing connection. Packets from a changed peer address are dropped,
so connection migration is disabled. Session tickets and 0-RTT are disabled.
During drain, Ankah stops accepting new QUIC connections and streams, sends
an HTTP/3 shutdown notice, and lets accepted streams finish before closing
the UDP listener.

HTTP/1.1 chunked uploads are counted by decoded body bytes. An upload that
crosses its configured limit receives 413 if a final response has not already
started, then the connection closes.

On POSIX systems, send `SIGHUP` after replacing the certificate and key files.
On Windows, Ankah watches their parent directories and reloads the pair after
a short delay. A replacement is checked before it is used. Existing
connections continue with the credentials selected during their handshake.

## Trusted proxy addresses

Forwarding headers are ignored unless the direct peer belongs to a configured
network. Add each permitted proxy network separately:

```sh
./ankah ... \
  --trusted-proxy 127.0.0.0/8 \
  --trusted-proxy 10.0.0.0/8 \
  --trusted-proxy 2001:db8:1234::/48
```

For a configured peer, Ankah prefers the RFC `Forwarded` header when present
and otherwise reads `X-Forwarded-For`. It walks the chain from right to left
through configured proxy networks. The first address outside those networks
becomes the client address used for request limits, saved requests, and the
upstream `X-Forwarded-For` header.

Scheme and host always come from `--public-origin`. Incoming `Forwarded`,
`X-Real-IP`, and `X-Forwarded-*` values are removed before the request is sent
to the application. Ankah writes fresh `X-Forwarded-For`,
`X-Forwarded-Proto`, and `X-Forwarded-Host` values.

See [trusted proxy abuse actions](proxy-abuse.md) and the
[HAProxy and Django example](../examples/haproxy-django/README.md) for a proxy
that applies Ankah response signals and rejects connection floods.

## IPv6 endpoints

Use brackets around IPv6 listener and upstream addresses:

```sh
./ankah --listen '[::]:8443' --upstream '[::1]:8001' ...
```
