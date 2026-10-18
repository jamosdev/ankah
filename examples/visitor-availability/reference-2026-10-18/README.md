# Local reference result, 18 October 2026

All 75 independent trials completed with valid offered load and resource
coverage. Each cell has five 300-second repeats, with 1,500 offered new visits
and 1,500 offered returning visits. The workload is the same CPU-bound Django
`/pi?n=200000` endpoint in every deployment. Both visitor cohorts offer one
visit per second, share one source address, and have a 30-second deadline.
The attacker uses a separate address. See the [protocol](../README.md) for
the application limits, challenge behaviour, schedules, and measurement definitions.

During unsolved floods at both 40 and 200 requests/second, both protected
deployments delivered every offered legitimate visit correctly. Direct
application access delivered 10.8% at 40 requests/second and 1.3% at 200.
Solving and reusing proof changed the outcome: at 200 requests/second, Ankah
delivered 0.4% of new visits and 6.2% of returning visits; adding DOTS delivered
0.3% and 3.2%. This run demonstrates protection against the specified unsolved
floods and poor availability against the specified proof-reusing floods.
It does not establish capacity for another workload or a cause for each failure.

The [generated report](summary.md) includes all 30 cohort rows with correct
response counts, successful-visit p95, and challenge p95, plus all 75 serving
resource measurements. [Detailed JSON](summary.json) retains failure categories,
challenge failures/timeouts, setup charges, backend correlations, per-component
costs, client costs, container-lifetime counters, and observer overhead.
[CSV](summary.csv) contains the pooled cohort rows. P95 is conditional on
success; the very small successful samples in some solved-flood rows are
flagged in JSON and must not be read as evidence of good availability.

## Serving deployment resources

CPU seconds are means across the five measured windows in each cell. Memory
is the range of each repeat's sampled peak sum across all serving containers.
These totals include the application, gateway, and, for DOTS, edge and database.
They exclude the load clients, host observer, and shared Docker daemon; client
and observer counters appear in the detailed JSON. Container-lifetime CPU,
including startup, preparation, and draining, is reported there separately.

| Deployment | Attack | Offered attack RPS | Mean serving CPU seconds / 300 s | Sampled peak serving MiB, repeat range |
|---|---|---:|---:|---:|
| direct | none | 0 | 130.3 | 119.3 to 120.9 |
| direct | unsolved | 40 | 299.0 | 117.2 to 118.6 |
| direct | unsolved | 200 | 299.0 | 117.1 to 118.7 |
| direct | solved | 40 | 299.0 | 117.8 to 119.0 |
| direct | solved | 200 | 299.0 | 117.2 to 118.4 |
| ankah | none | 0 | 141.3 | 127.5 to 129.9 |
| ankah | unsolved | 40 | 149.1 | 127.9 to 129.3 |
| ankah | unsolved | 200 | 170.5 | 128.7 to 130.2 |
| ankah | solved | 40 | 319.4 | 200.4 to 202.2 |
| ankah | solved | 200 | 321.5 | 200.4 to 202.1 |
| dots | none | 0 | 175.7 | 533.3 to 537.7 |
| dots | unsolved | 40 | 179.1 | 531.9 to 538.3 |
| dots | unsolved | 200 | 185.2 | 533.1 to 538.5 |
| dots | solved | 40 | 367.9 | 619.8 to 624.0 |
| dots | solved | 200 | 421.5 | 621.9 to 623.4 |

## Provenance and publication status

The run finished at 2026-10-18 05:52 UTC after approximately 7 hours 39 minutes.
It used a Linux amd64 host with an Intel Xeon E5-2696 v4 and approximately
252 GiB RAM. Application and client containers ran on that same host; limits
are ceilings rather than dedicated capacity. Unrelated host activity is not
isolated. HTTP/1.1 without TLS, Chromium, two source addresses, and this single
CPU-bound endpoint limit what can be inferred.

[Provenance](provenance.json) records the exact command, source fingerprint,
base commit and dirty-tree state, Release configuration, host information,
Docker versions, frozen image identities, report hashes, and raw archive hash.
This was a development-tree run based on commit
`da7caeda0891d108ddd25ea67898415ffa155d8e`, with the source changes preserved
as `source.patch` in the raw archive. The base commit alone does not reproduce
the measured checkout. Images were frozen and verified for every repeat.

The 105,564,918-byte raw `reference.tar.gz` is retained locally. Its SHA-256 is:

```text
4d78736957cfd94bb886fabbfbd1843b138f8b70cb95daac5d4278a73944c8f1
```

This checked-in snapshot contains derived results and provenance. The full raw
observations, source patch, container manifests, executable hashes, metrics,
and logs are in the archive. Public hosting of that archive and execution in
remote GitLab CI remain pending. No independent reproduction is claimed.
The manual reference CI job can produce a complete downloadable job artifact.
