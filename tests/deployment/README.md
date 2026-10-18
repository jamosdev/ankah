# Deployment acceptance checks

From the checkout, with Docker Engine, Compose, Python 3 and OpenSSL:

```sh
python3 tests/deployment/smoke.py --artifacts /tmp/ankah-deployment-evidence
```

This builds the actual deployment Dockerfile, an Ubuntu 24.04 source build
using the native instructions, and a pinned Chromium client. It runs the
Compose template with HAProxy and the native configuration with Nginx,
each against a fresh synthetic application and isolated state. It selects
unused loopback host ports and requires unused template subnets plus
`172.30.83.0/24` for an isolated browser network. The
application is never published on a public interface. It does not touch
existing services or `/etc` on the host.

Checks cover startup, public Host, browser proof and original-URL continuation,
repeat visits, dashboard authorization, forwarding header sanitization,
unavailable upstream with live gateway, graceful drain, container replacement,
stable credentials, solved-session/statistics restoration, version selection
and rollback, and both proxy configuration syntaxes. Images and executable
hashes, exact Docker commands, logs and response diagnostics are retained.
The native service unit is verified inside Ubuntu with its installed binary;
process execution uses the native configuration and service account. Actual
systemd lifecycle checks and a remote GitLab pipeline remain separate checks.

Each independent deployment has fresh gateway state. Restart, replacement,
and rollback intentionally reuse that deployment's state. Startup probes use
TCP only. Each deployment performs one browser challenge and a bounded number
of admitted requests, within the initial budgets; no rate refill is assumed.
Browser response artifacts contain cookies and the saved browser state is a
credential. Keep the artifact directory private and remove it after review.
No application admission policy or shared test fixture is changed.
