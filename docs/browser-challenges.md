# Browser challenge background

Normal challenges, `/ankah/unlock`, and active phone/QR solve pages use the
bundled original particle preset. The animation runs behind the content with
137 particles before density adjustment, speed 6, white particles/lines and
hover repulsion. Pointer movement is observed on the window so the canvas
does not intercept form controls. The dashboard retains its own quieter style.

Decorative scripts and configuration load asynchronously through same-origin,
content-hashed `/ankah/assets/` URLs on the selected host. They are available
when the dashboard is disabled. Loading or initialization failures never block
proof submission or continuation. Reduced motion suppresses decorative loading;
its preference is checked again before initialization. No delay is added to
proof completion, so a fast challenge can finish before the background appears.

## Browser regression check

The normal Node and host-browser tests cover loading failure isolation and
asset delivery. A separate Chromium smoke test checks real painted pixels,
particle movement, pointer/control interaction, mobile layout, reduced motion,
phone challenges and navigation with failed or stalled decoration. It can test
a source build or an installed package. Its isolated TLS fixture uses synthetic
hosts and credentials; certificate exceptions apply only to that fixture.

Install the existing Python test dependencies (Brotli 1.2.0 and hpack 4.2.0),
Node, and Playwright 1.62.1 with Chromium. Keep optional browser tooling outside
the checkout:

```sh
npm install --prefix /tmp/ankah-browser-tools playwright@1.62.1
/tmp/ankah-browser-tools/node_modules/.bin/playwright install chromium
```

Run the check; it starts and stops a fresh gateway for every independent scenario:

```sh
NODE_PATH=/tmp/ankah-browser-tools/node_modules \
  node tests/challenge_background_test.cjs "$PWD/build/ankah" "$PWD" /tmp/ankah-browser-results
```

Use a new output path for each run. For an
installed package, replace the executable and asset arguments with its `ankah`
and `assets` paths; optional `--bundle PATH` selects its landing bundle.
`--no-dashboard` verifies the same challenge backgrounds without a dashboard.
When the fixture runs in a separate local container, set `ANKAH_FIXTURE_ADDRESS`
to its reachable private address and `ANKAH_FIXTURE_RUNNER` to a JSON argument
array such as `["docker","exec","-i","test-container","python3","/source/tests/browser_fixture.py"]`.
Executable, asset and bundle paths then refer to that container. The helper
exchanges fixture metadata over stdout and closes each fixture through stdin;
there is no network administration endpoint. `BROWSER` can select an existing
Chromium executable. No production address or credential belongs in these checks.

The browser writes screenshots, its version, the fixture executable hash and
scenario results. Visual checks hold the Finished form navigation only long
enough to inspect the challenge; separate cases exercise unmodified navigation.
Phone checks solve a fresh session without sharing the original page's cookie.

Pass `--routes` to the same check to exercise administration-prefix and login
query navigation through an isolated policy backend. These two fresh-browser
cases require an initial challenge, real browser proof completion and a return
to the unchanged query-bearing target. The fixture uses only synthetic backends;
it does not test an OIDC provider or application authorization.
