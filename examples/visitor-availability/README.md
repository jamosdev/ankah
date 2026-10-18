# Visitor availability benchmark

This benchmark asks whether real visitors can obtain the correct application
response during a specified workload. A reproducible result in which Ankah
performs poorly is useful evidence too. There is no assertion that a gateway
must outperform the direct application.

The same Django image, two synchronous Gunicorn workers, CPU-bound `/pi`
implementation, work factor, application limits, and offered arrival schedules
are used for three deployments:

| Deployment | Serving components | CPU / memory limits |
|---|---|---|
| `direct` | Django application | 1 CPU / 256 MiB |
| `ankah` | Application and Ankah | Each 1 CPU / 256 MiB |
| `dots` | Application, Ankah, upstream edge, go-dots database | App and Ankah as above; edge 2 CPU / 256 MiB; database 1 CPU / 512 MiB |

Application resources stay fixed. Extra protection components add resources;
the report includes their costs. Both protected deployments use normal Ankah
admission and conservative abuse defaults. The DOTS deployment adds a trusted
edge and the default DOTS threshold/window/block duration. It does not disable
local bans to make escalation more visible. The database uses a 64 MiB buffer
pool. Container limits are ceilings, not dedicated host capacity.

The [older DOTS demo](../dots-benchmark/README.md) supplies the application and
filtering components. Its competitor comparison remains separate.

## Run and regenerate

Requires a Linux Docker Engine, Docker Compose, Python 3, network access during
image construction, and an amd64 host (the pinned MySQL image is amd64-only).
Playwright 1.62.1, Chromium, and their dependencies are installed inside client
images. Application and DOTS dependencies reuse the pinned versions in the
worked example. Ankah is built from this checkout in Release mode with strict
warnings and its WebAssembly solver enabled.

Keep artifacts outside the checkout. Each output directory must be new. The
runner creates a unique Compose project for every independent scenario and
removes only that project's containers, networks, and credential volume.
Networks `172.30.0.0/24` and `172.30.1.0/24` must be free; stop the older DOTS
demo first if it occupies them. Compose reports an address-pool conflict rather
than stopping another deployment. No service port is published to the host.

```sh
# Harness correctness, all deployments, attack behaviours, and visitor cohorts.
python3 examples/visitor-availability/run.py --profile smoke \
  --output /tmp/visitor-smoke

# Published reference protocol: 15 cells, five 300-second repeats per cell.
python3 examples/visitor-availability/run.py --profile reference \
  --output /tmp/visitor-reference

# Recalculate without Docker, browsers, or another traffic run.
python3 examples/visitor-availability/report.py /tmp/visitor-reference
```

The reference run requires about 6.25 measured hours plus image construction,
preparation, and draining. Its 75 independent runs each have 300 offered visits
per visitor cohort, giving 1,500 offered visits per cohort per cell. It tests
no attack and both 40 and 200 attacker work requests/second for each of two
attack behaviours. The smoke profile uses eight seconds, one repeat per cell,
and 0.25 visits/second per cohort (two offers each). Its percentiles have very
small samples and are not reference evidence. Its no-attack correctness check
counts all visitor wire requests, including preparation and assets, against
the initial 40-request client burst without assuming refill. The current page
uses 12 requests per fresh visit, so preparation plus two new visits and two
returning visits uses 38 requests. The check fails if that budget grows.

For exploration, select `--arms direct ankah`, `--attacks unsolved solved`,
`--rates 40 200`, `--duration 180`, `--repeats 3`, `--work-factor 200000`, or
`--visitor-rps 1`. These change the recorded protocol; a filtered or shortened
run must not be described as the complete reference profile. Duration is
restricted to 3..900 seconds so the pre-earned returning session remains
within its normal lifetime. Work factor is 1..2,000,000 Pi iterations.

## Clients and timing

In the reference profile, the visitor container offers one new visit and one
returning visit per second.
Chromium executes the shipped challenge page, worker, proof submission, and
continuation without bypassing or replacing the solver. A new visit receives
a fresh browser context and cookie/cache state. Returning visits receive
independent contexts initialized with the cookies and storage earned by one
real visit before the attack. Each visit has its own page and connection pool;
the returning cohort does not share a browser's per-origin connection limit.
HTTP cache is not transferred to these contexts. The distinction measured here
is retained proof state, not a warm HTTP cache. Browser launch is preparation;
context and page creation are included in both cohorts' visit latency. Normal
browser connection pooling remains enabled within each context.

The attacker has a different real source address from visitors. Both visitor
cohorts share one address. In `unsolved`, requests never submit proof. In
`solved`, Chromium earns proof before measurement and an HTTP client reuses
its cookies and User-Agent from the same container/address. This models a
client that pays for access once and floods afterwards, not a fresh proof for
each request. Both behaviours open a new TCP connection per work request;
DOTS admission therefore applies to those connections. For the direct app,
the same work requests are sent without a challenge prelude.

The attack timeout is five seconds, with at most 2,048 requests in flight.
Each visitor cohort has at most 64 visits in flight and a 30-second deadline.
Fixed schedules do not wait for completion. An arrival that misses its slot
by more than 250 ms or cannot obtain a generator slot is retained as a
`generator_miss`; that run is invalid for a matched-load comparison. Failures
are never retried into successes. HTTP readiness, proof setup, assets, answer
submissions, and continuation requests appear in raw observations. TCP
readiness probes are recorded separately and do not send HTTP requests.
Compose also waits for the gateway's zero-I/O TCP health check before starting
the clients; its probe configuration and recent results are in container metadata.
Preparation does not assume rate-token refill, and state is never shared
between independent runs. Deployment order rotates across repeats.

## Reading the evidence

`summary.md`, `summary.csv`, and `summary.json` are derived from raw files.
`metadata.json` records source identity, dirty state, exact command, Docker
versions, host hardware/load, protocol, and source-address counts. Each trial
retains its resolved Compose configuration, container/image IDs and limits,
gateway executable hash, worker browser version, logs, gateway metrics, and
DOTS metrics/ACLs where present. Registry image digests and the package lock
identify inputs; retain the built images as well when repeating a historic run,
since distribution package repositories can change.
The runner gives built images run-specific tags, disables rebuilding/pulling
during scenarios, and verifies each container's image ID against the original
build. All repeats therefore use the same images even if other local tags change.
`source.patch` preserves tracked changes from the recorded commit and new
benchmark source files for development runs. Apply it to that commit before
rebuilding; a clean published revision is preferable for reference results.

Interpret these measures together:

- **Correct application responses / offered visits:** validate JSON, backend,
  requested work factor, and Pi value. A challenge, unrelated `200`, rejection,
  missed arrival, or timeout is not success. Failure categories and absent
  observations remain visible; they never disappear from the denominator.
- **p95:** nearest-rank latency of successful visits, from scheduled arrival
  until receipt and validation of the application payload. It includes challenge
  and continuation time. It is conditional on success: always read it beside
  success rates and sample counts. Reports preserve each repeat and pool raw
  samples instead of averaging percentiles. Fewer than 100 successful samples
  is flagged; zero successes has no latency percentile.
- **Challenge time:** from receipt of the challenge response headers until
  accepted proof response headers, including assets, solver startup, computation,
  and submission. This is not isolated hashing time. Challenged visits with no
  accepted answer retain observed wait time and failure/timeout state.
  Unchallenged visits have no challenge time.
- **Backend work:** Gunicorn completion logs carry the same identifiers as
  client observations. Solving preparation must show proof acceptance and a
  correct backend response. Measured attacker completions, challenges, bans,
  rate rejections, resets, and timeouts are retained. A policy-blocked attacker
  is an observed outcome, not grounds to weaken policy or discard a run.
- **Serving resources:** Docker Engine cumulative CPU counters and memory
  usage minus inactive file cache, sampled in batches approximately once a
  second. Serving totals include the app, gateway, edge, and database that are
  actually running. Aggregate memory is the peak of sampled sums, not the sum
  of each component's independent peak. Coverage duration is retained. Client
  CPU/memory are reported separately. Observer records give host harness CPU,
  Docker CLI CPU, and the harness process's lifetime peak RSS. Docker daemon
  usage is not isolated from other host workloads. These costs are outside
  serving-container totals; same-host contention is unavoidable
  in this example and is not attributed to a particular cause without evidence.
  Separate container-lifetime CPU counters include startup, preparation, and
  draining; the main table measures the configured traffic window. Memory
  sampling begins before browser preparation, after service readiness.

Example interpretation criteria default to at least 99% correct visits within
30 seconds, with successful-visit p95 no greater than five seconds for new
visitors and one second for returning visitors. Override the latency criteria
using `--new-slo-ms` and `--returning-slo-ms`. These are examples, not acceptance
gates for benchmark correctness or assurances for another application.

## Limits and publication

This is one CPU-bound Django endpoint, HTTP/1.1 without TLS, one attacker
address, and one visitor address on a single Docker host. It does not measure
database-heavy pages, static asset mixes, mobile devices, other browsers,
distributed attackers, a shared attacker/visitor address, or existing attacker
keep-alive connections. The upstream edge filters in userspace after TCP
`accept()`, not before the handshake. It is not SYN-flood or network-capacity
protection. Low gateway memory does not establish visitor availability.

Publish the entire reference output, including unsuccessful and invalid rows,
alongside its configuration and exact command. Check `valid_load_comparison`
before comparing deployments. Never turn smoke numbers into a capacity claim.
Until a complete reference artifact is published, the README makes no measured
visitor-availability or resource advantage claim.

Run harness unit checks independently of Docker:

```sh
python3 -m unittest discover -s examples/visitor-availability -p 'test_*.py'
node --test examples/visitor-availability/client_test.cjs
```

The Linux CI smoke job retains all observations even on failure. Full reference
measurements are deliberately separate from its small correctness sample.
The manual `visitor_availability_reference` CI job publishes the full output
as a job artifact retained for one year. It requests a nine-hour timeout;
the project's runner timeout must permit that window. Its result does not
require a performance win and does not block the ordinary publish pipeline.
