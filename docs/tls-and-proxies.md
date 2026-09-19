# TLS, HTTP/2, and proxy addresses

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

The TLS listener accepts TLS 1.2 and newer. It advertises `h2` and `http/1.1`
with ALPN. HTTP/2 terminates at Ankah; application requests remain HTTP/1.1.
Cleartext HTTP/2 and HTTP/2 connections to the application server are not
enabled.

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

## IPv6 endpoints

Use brackets around IPv6 listener and upstream addresses:

```sh
./ankah --listen '[::]:8443' --upstream '[::1]:8001' ...
```
