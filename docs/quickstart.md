# Protect an existing site

Keep your existing HTTPS proxy, certificates, and application. Insert Ankah
between the proxy and the application's private HTTP listener:

```text
visitor -> existing HTTPS proxy -> Ankah :8000 -> private application :8001
```

Choose [Docker Compose](#docker-compose) or [native Linux with systemd](#native-linux-with-systemd),
then complete [verification and cutover](#verification-and-cutover). Neither
path starts the application as an Ankah child process. Your application's
existing supervisor continues to manage it.

## Before starting

Write down these substitutions before running commands:

| Setting | Example | What to supply |
| --- | --- | --- |
| Public origin | `https://example.com` | Your exact public scheme, hostname and optional port, without a path |
| Application endpoint | `127.0.0.1:8001` native, `172.30.82.10:8001` Compose | A numeric private HTTP address and actual listening port |
| Immediate proxy peer | `127.0.0.1/32` native, `172.30.81.1/32` host proxy into Docker | Only the source address Ankah sees from your HTTPS proxy |
| Application image | `registry.example.com/site:version` | Compose only: your existing image, with its command and other settings |

These templates assume the HTTPS proxy runs on the same host. For a
containerized or remote proxy, read [other proxy layouts](#other-proxy-layouts)
before starting. Port `8000` must be free. Keep the application's old proxy
backend and a copy of its proxy configuration for immediate routing rollback.
Keep the application listener private; remove public port publication or
bind it to loopback as appropriate. If the application currently uses port
`8000`, move its private listener and update the old proxy backend first.

Use a checkout of the version you intend to deploy. Source builds download
pinned dependencies and need internet access. Release downloads need a
published version and its archive SHA256 from that same host's `SHA256SUMS`;
do not mix GitLab and GitHub checksums. If the selected package has not been
published, use the source build. See [release packages](release-packages.md).

## Docker Compose

This path needs an x86-64 Linux Docker host, Docker Engine with the Compose
plugin, Python 3, and sudo. Run `docker info`, `docker compose version`, and
`python3 --version` first. Run commands from the checkout unless noted.

1. Prepare the configuration and credentials:

   ```sh
   cp deploy/compose/.env.example deploy/compose/.env
   cp deploy/compose/ankah.conf.example deploy/compose/ankah.conf
   sudo sh deploy/compose/setup.sh
   ```

   Edit `deploy/compose/.env`: set `APP_IMAGE` to the existing application
   image and give `ANKAH_IMAGE` a distinct local version tag. Edit
   `deploy/compose/ankah.conf`: set `public-origin` and the application's
   numeric `upstream` address/port. The application must listen on
   `0.0.0.0:8001` inside its container for the supplied port to work.

   The setup script creates missing credentials only; rerunning it preserves
   them. Credentials are root-owned, group `10001`, mode `0640`, in a `0750`
   directory. The state directory is owned by `10001:10001`, mode `0700`.
   Ankah runs as that numeric unprivileged account. Rootless Docker or user
   namespace remapping needs equivalent ownership in the daemon's mapped
   UID/GID range. Configuration must be readable by UID `10001`.

2. Adapt [compose.yml](../deploy/compose/compose.yml) to the existing application.
   Copy its current `command`/`entrypoint`, environment, volumes, health
   checks, database connections, dependencies, and required networks into
   `application`. Omitting `command` preserves the image's default command;
   it does not preserve a command overridden in your previous Compose file.
   Remove the application's public `ports` mapping. Do not launch a second
   copy against the same writable application data during migration: either
   move the service into this project during a maintenance window, or merge
   the Ankah service and both network definitions into the existing project.
   When merging, keep relative bind paths relative to that Compose file and
   set `ANKAH_SOURCE` to the absolute checkout path.

   Before replacing the old application container, preserve a private route
   from the existing HTTPS proxy to it for staging and rollback. With a host
   proxy, temporarily add this loopback-only mapping to `application` (choose
   a free host port and use it in the previous proxy backend):

   ```yaml
   ports:
     - "127.0.0.1:8001:8001"
   ```

   Replace any old `8001:8001` mapping with this restricted one. With a
   containerized proxy, retain its original shared application network
   instead. Confirm the old route still serves the application before
   staging Ankah. Keep this private route until you no longer need immediate
   routing rollback.

   The frontend network is `172.30.81.0/24`, with gateway `172.30.81.1` and
   Ankah `172.30.81.10`. The private application network is `172.30.82.0/24`,
   with application `172.30.82.10` and Ankah `172.30.82.11`. Check
   `ip route` and `docker network ls`/`docker network inspect` for conflicts.
   If either subnet conflicts with your host, VPN or other containers,
   change it and all corresponding addresses in Compose and `ankah.conf`.
   Keep the subnets distinct. The application network is internal; retain
   another existing network if the application needs outbound internet or
   database access. Containers on these networks are trusted infrastructure.

3. Build from the checkout, with Release selected explicitly by the Dockerfile:

   ```sh
   cd deploy/compose
   docker compose config --quiet
   docker compose build ankah
   docker compose up -d
   docker compose logs --tail=100 ankah
   ```

   Ankah's exec-form entrypoint receives stop signals directly. It restarts
   automatically unless stopped, has a read-only root filesystem, and gets
   two minutes to drain on shutdown. Its only published port is
   `127.0.0.1:8000`. Configuration and credentials are mounted read-only;
   `./state` remains writable and survives container replacement. Do not
   remove it when recreating the container.

   Alternatively, set these values in `.env` before building. Replace both
   placeholders with a published version and its matching GitHub checksum:

   ```dotenv
   ANKAH_PACKAGE_STAGE=release-fetch
   ANKAH_VERSION=vX.Y.Z
   ANKAH_SHA256=REPLACE_WITH_64_HEX_ARCHIVE_SHA256
   ```

   Run the same build and startup commands. Both arguments are mandatory;
   the Dockerfile verifies the checksum before extracting. The runtime
   image, credentials, network layout and state paths are identical.

4. Continue with [verification and cutover](#verification-and-cutover).
   Retrieve the dashboard recovery credential when needed:

   ```sh
   sudo cat credentials/dashboard.token
   ```

## Native Linux with systemd

This walkthrough targets Ubuntu 24.04 on x86-64. Run from the checkout.
The existing application service remains independently managed and listens
on loopback, for example `127.0.0.1:8001`.

1. Install prerequisites and create the account and directories:

   ```sh
   sudo apt-get update
   sudo apt-get install -y build-essential cmake ninja-build git clang lld \
     python3 curl ca-certificates
   sudo useradd --system --user-group --home-dir /var/lib/ankah \
     --no-create-home --shell /usr/sbin/nologin ankah
   sudo install -d -m 755 /opt/ankah
   sudo install -d -m 750 -o root -g ankah /etc/ankah /etc/ankah/credentials
   sudo install -d -m 700 -o ankah -g ankah /var/lib/ankah
   ```

   Create the account once. On a repeat installation, use the existing
   `ankah` account and keep its state and credentials.

2. Choose one installation method. For a source build, use a fresh build
   directory and an unused version directory:

   ```sh
   ANKAH_INSTALL_VERSION="source-$(git rev-parse --short=12 HEAD)"
   cmake -S . -B build-release-first-deployment -G Ninja -DCMAKE_BUILD_TYPE=Release \
     -DANKAH_STRICT_WARNINGS=ON -DANKAH_BUNDLED_RUNTIME_DEPS=ON
   cmake --build build-release-first-deployment --target ankah --parallel 2
   sudo test ! -e "/opt/ankah/$ANKAH_INSTALL_VERSION" && \
   sudo cmake --install build-release-first-deployment --component ankah_runtime \
     --prefix "/opt/ankah/$ANKAH_INSTALL_VERSION"
   ```

   Bundled runtime dependencies avoid dependence on the distribution's TLS
   library version. Compilers, Clang's WebAssembly target and LLD are required;
   installing only a C compiler is insufficient. Keep the executable and
   installed `assets` together. Do not reuse this version directory for a
   different build; use a new suffix for builds with local changes.

   Alternatively, install a checksum-verified Linux release without building:

   ```sh
   ANKAH_INSTALL_VERSION=vX.Y.Z
   ANKAH_SHA256=REPLACE_WITH_64_HEX_ARCHIVE_SHA256
   sudo sh deploy/native/install-release.sh "$ANKAH_INSTALL_VERSION" "$ANKAH_SHA256"
   ```

   This downloads the selected GitHub archive, verifies it and installs it
   under `/opt/ankah/$ANKAH_INSTALL_VERSION`. It refuses to overwrite a
   version. Only `curl`, CA certificates, tar and standard system utilities
   are needed for this method; the other prerequisites are for source builds.

3. Select the installation and configure Ankah:

   ```sh
   sudo ln -s "/opt/ankah/$ANKAH_INSTALL_VERSION" /opt/ankah/current
   sudo install -m 640 -o root -g ankah deploy/native/ankah.conf /etc/ankah/ankah.conf
   sudo python3 deploy/credentials.py /etc/ankah/credentials
   sudo chown root:ankah /etc/ankah/credentials/gateway.secret /etc/ankah/credentials/dashboard.token
   sudo chmod 640 /etc/ankah/credentials/gateway.secret /etc/ankah/credentials/dashboard.token
   sudoedit /etc/ankah/ankah.conf
   ```

   Set `public-origin`, the numeric loopback `upstream` and its port before
   starting. Keep `listen=127.0.0.1:8000` and trust only your actual proxy
   peer. Credentials are created once and are readable by the service group;
   the service cannot overwrite them. Do not copy the example configuration
   over an existing deployment when upgrading.

4. Install and start the service:

   ```sh
   sudo install -m 644 deploy/native/ankah.service /etc/systemd/system/ankah.service
   sudo systemd-analyze verify /etc/systemd/system/ankah.service
   sudo systemctl daemon-reload
   sudo systemctl enable --now ankah
   sudo systemctl status ankah --no-pager
   sudo journalctl -u ankah -n 100 --no-pager
   ```

   The unit explicitly selects `/etc/ankah/ankah.conf`, restricts writable
   paths to state, restarts failures after five seconds, limits restart
   bursts, and allows two minutes for graceful shutdown. It does not start
   or stop the application. Continue with verification below. To retrieve
   the dashboard recovery credential:

   ```sh
   sudo cat /etc/ankah/credentials/dashboard.token
   ```

## Verification and cutover

1. Check Ankah directly before changing public routing. Replace the Host with
   the authority from your public origin, including a non-default port:

   ```sh
   curl --fail-with-body -i -H 'Host: example.com' http://127.0.0.1:8000/ankah/livez
   curl -i -H 'Host: example.com' 'http://127.0.0.1:8000/?ankah-check=first'
   ```

   Liveness must return `200` and `ok`. It checks Ankah without contacting
   the application; it does not prove application readiness. An unverified
   browser request normally returns `428` with a challenge page. A Host
   mismatch returns `421`, including on health routes. Curl cannot complete
   this browser check by simply following redirects. Do not send dashboard
   credentials across a public plain HTTP connection.

2. Stage the HTTPS proxy change for your testing source IP only, preserving
   the previous backend for everyone else. Keep the existing TLS listener,
   certificate configuration and public hostname. Forward the public Host
   unchanged and replace incoming client-address headers. Copy either the
   [Nginx location](../deploy/proxy/nginx.conf) into the existing HTTPS server
   or the [HAProxy backend](../deploy/proxy/haproxy.cfg) into its configuration.

   For Nginx staging, put this map in the `http` context, replacing the
   documentation IP with your testing client's public source IP and the
   default endpoint with the previous application backend:

   ```nginx
   map $remote_addr $site_backend {
       default       127.0.0.1:8001;
       192.0.2.20    127.0.0.1:8000;
   }
   ```

   During staging, replace the template's `proxy_pass` with
   `proxy_pass http://$site_backend;`. Keep the template's header directives.
   For HAProxy, add `use_backend ankah if { src 192.0.2.20/32 }` to the
   HTTPS frontend before its existing `default_backend`. Preserve all
   earlier routing rules that your site needs. Operators behind a shared
   NAT should use a dedicated test source so other clients are not included.

   Test and reload the applicable proxy:

   ```sh
   sudo nginx -t && sudo systemctl reload nginx
   # Or:
   sudo haproxy -c -f /etc/haproxy/haproxy.cfg && sudo systemctl reload haproxy
   ```

   Ankah removes incoming `Forwarded`, `X-Real-IP`, and `X-Forwarded-*`
   before forwarding. It writes canonical `X-Forwarded-For`,
   `X-Forwarded-Host`, and `X-Forwarded-Proto`. Never use Nginx's
   `$proxy_add_x_forwarded_for` here or append an untrusted incoming chain.
   With a host proxy into Docker, Ankah normally sees `172.30.81.1`, the
   bridge gateway, rather than `127.0.0.1`. Confirm the peer using a packet
   capture or your container networking diagnostics before trusting it.
   A different Docker networking mode can produce a different peer.

3. From the staged source, open a fresh private browser window at a real
   application URL with a query, for example
   `https://example.com/?ankah-check=browser`. Observe the challenge, successful
   proof, continuation to the exact original path and query, and the expected
   application content. Revisit it in the same window: it should reach the
   application with the solved session. Check that application logs report
   the real test client's IP and public HTTPS origin, not a supplied spoofed
   header or Docker bridge address. A protected WebSocket first needs an
   ordinary solved GET; application-specific streaming and proxy timeouts
   still need the existing site's configuration.

4. Open `https://example.com/ankah-admin/` in that window, choose **Use dashboard
   token**, and paste the token retrieved above. Confirm traffic and challenge
   counters. Optionally set up an authenticator and upload a mascot through
   the [dashboard](dashboard.md). Keep the token as a recovery credential.

5. Only after these checks, route all intended traffic to Ankah: set Nginx's
   `proxy_pass` to `http://127.0.0.1:8000` and remove the preview map, or replace
   HAProxy's previous default backend with `ankah` and remove the preview
   source rule. Validate and reload, repeat the browser check, and watch
   application responses and [admission/crawler monitoring](monitoring.md).
   For immediate routing rollback, restore the saved proxy configuration
   pointing to the previous private application backend, validate and reload.
   Keep that backend reachable by the proxy throughout staging. For Docker,
   a rollback may need a host-loopback application port or the proxy's original
   shared application network; never reopen it on a public host interface.

### Other proxy layouts

For another HTTPS proxy, change only its HTTP backend to Ankah and preserve
Host. Delete incoming `Forwarded` and `X-Real-IP`; overwrite
`X-Forwarded-For` with the actual client source address. Do not trust a
visitor-supplied chain. Ankah derives scheme/host from `public-origin`, so
the edge does not need to supply those headers. Trust only the immediate
peer, preferably a single `/32` or IPv6 `/128`, not an entire LAN or every
container network. If a CDN precedes the proxy, establish that proxy's own
trusted-client-IP handling first using the CDN's authenticated/network
boundaries; then forward the resolved address.

A containerized proxy cannot use its own `127.0.0.1` to reach a different
container. Attach it to the Compose frontend network, give it a fixed address
such as `172.30.81.20`, route to `172.30.81.10:8000`, and replace
`trusted-proxy=172.30.81.1/32` with `trusted-proxy=172.30.81.20/32`.
The host-loopback mapping can remain for operator probes. Keep the proxy's
original application network available for routing rollback. A remote proxy
needs a private reachable listener, firewall restriction to that peer and
the matching trust entry; the supplied native loopback listener is for a
same-host proxy. See [TLS and proxy addresses](tls-and-proxies.md).

## Persistent files

| Purpose | Compose host path | Native path |
| --- | --- | --- |
| Configuration | `deploy/compose/ankah.conf` | `/etc/ankah/ankah.conf` |
| Gateway signing secret | `deploy/compose/credentials/gateway.secret` | `/etc/ankah/credentials/gateway.secret` |
| Dashboard recovery token | `deploy/compose/credentials/dashboard.token` | `/etc/ankah/credentials/dashboard.token` |
| Session snapshots and consumption journal | `deploy/compose/state/ankah.sessions.*` | `/var/lib/ankah/ankah.sessions.*` |
| Statistics snapshots | `deploy/compose/state/ankah.stats.*` | `/var/lib/ankah/ankah.stats.*` |
| Optional mascot override | `deploy/compose/state/ankah.mascot.png` | `/var/lib/ankah/ankah.mascot.png` |

Snapshot generations use `.0` and `.1`; temporary replacements use `.tmp`.
Keep `ankah.sessions.journal` with both session generations; it is created when
consumption needs recording. State can include saved POST bodies: restrict and
protect backups like application data. Do
not share state between concurrently running gateways. Sessions are saved
on clean shutdown and scheduled every 30 seconds; statistics on clean
shutdown and every 15 minutes. Abrupt termination can lose recent data.
Dashboard authenticator sign-in sessions end on restart; the recovery token
and its authenticator setup stay stable. See [session storage](gateway-links.md#session-files)
and [persistent history](dashboard.md#persistent-history).

## Upgrades, backups and rollback

1. Retain the current image tag/image ID or `/opt/ankah` version directory,
   configuration and credentials. Build/download a new version before
   stopping the running gateway. Read its release notes for persistence
   compatibility; do not assume an older binary can read a newer format.
   For Compose, give the new image a distinct tag in `.env` and run
   `docker compose build ankah` while the old container continues serving.
   For native source builds, repeat installation into a new version directory;
   for packages run the verified installer with the new version and checksum.

2. Schedule a maintenance window or route temporarily to the previous backend.
   Stop Ankah gracefully with `docker compose stop ankah` or
   `sudo systemctl stop ankah`. Wait for completion; confirm the logs do not
   report snapshot failures or forced termination. Do not use `docker kill`
   or `kill -9`. Long requests can outlast the two-minute supervisor deadline;
   extend it before maintenance if needed.

3. With Ankah stopped, take a consistent backup of the whole configuration,
   both credentials, and entire state directory, retaining ownership/modes.
   Store it privately, outside the checkout. For example, from `deploy/compose`:

   ```sh
   sudo tar -czpf /root/ankah-backup-before-upgrade.tar.gz ankah.conf .env credentials state
   ```

   Or for native:

   ```sh
   sudo tar -czpf /root/ankah-backup-before-upgrade.tar.gz /etc/ankah /var/lib/ankah
   ```

   Use a unique backup filename for each upgrade. Copying live snapshot
   generations independently is not a consistent backup.

4. For Compose, run `docker compose up -d --no-deps ankah` using the new tag.
   For native, replace the symlink atomically while stopped:

   ```sh
   sudo ln -s "/opt/ankah/$ANKAH_INSTALL_VERSION" /opt/ankah/current.next
   sudo mv -Tf /opt/ankah/current.next /opt/ankah/current
   sudo systemctl start ankah
   ```

   Keep credentials stable. Repeat liveness, fresh-browser continuation,
   returning-browser access, dashboard sign-in and counters before full
   cutover. The previously solved browser should stay admitted after restart.
   An uploaded mascot should also remain. Check logs for restoration errors.

5. For a compatible binary rollback, stop gracefully, select the retained
   image tag in `.env` and run `docker compose up -d --no-deps --no-build ankah`,
   or switch `current` back to the retained native version and start. Keep the
   current state. Repeat verification before routing traffic back.

   Never blindly restore an older session-consumption journal after accepting
   new traffic: it can make a consumed POST usable again. For incompatible
   persistence formats, require release-specific migration/rollback guidance.
   Keep the current snapshots and journal intact; an older binary may need a
   fresh session basename and clients to unlock again, as described in
   [session storage](gateway-links.md#session-files). Do not pair old snapshots
   with an unrelated journal. A full stopped backup may be restored only when
   no later traffic has consumed state, or under the release's recovery guidance.

## Startup and access problems

| Symptom | Check |
| --- | --- |
| `421` or incorrect redirects | Exact `public-origin`, public Host including port, and proxy Host preservation; health probes need that Host too |
| Missing challenge/dashboard assets or startup exit | Keep executable and complete installed assets from the same version; verify `assets-dir`, directory traversal permissions and mount source |
| Secret/token cannot be read | Exactly 64 hex characters, optionally a newline; check owner/group, file mode and parent directory access as UID `10001` or account `ankah` |
| State warnings, lost counters or continuation `503` | State directory ownership, writable mount, free space; check logs and retain journal plus both snapshots |
| Challenge succeeds but application fails | Application listening address/port, numeric `upstream`, private network membership, application service logs and database connectivity |
| Every client appears as the proxy or bridge | Confirm actual immediate peer and matching `trusted-proxy`; overwrite incoming address headers at the edge |
| Trusted forwarded header gives `400` | Malformed `Forwarded`/`X-Forwarded-For`; remove visitor values and set one resolved client IP at the proxy |
| Compose bind mount fails | Run setup, create `ankah.conf`, and resolve paths relative to the Compose file; missing files must not turn into directories |
| Restart loop | Inspect `docker compose logs --tail=100 ankah` or `journalctl -u ankah`; fix configuration, then `systemctl reset-failed ankah` if the start limit was reached |

For failures, retain status, response headers, a bounded body, gateway logs,
the deployed version and executable/image hash. A passing liveness probe does
not explain an application or browser failure. No admission limits are changed
by these deployment templates.
