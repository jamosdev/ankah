# Visitor availability results

Profile: reference. Complete: True. Full reference protocol: True.

Successful-visit p95 is conditional on success. Read failure counts and sample sizes alongside it.
Example SLOs are configurable interpretation aids, not suitability guarantees. Resource peaks are sampled.

| Deployment | Attack | RPS | Visitor | Repeats | Valid load | Correct / offered | p95 ms | Challenge p95 ms |
|---|---|---:|---|---:|---|---:|---:|---:|
| ankah | none | 0 | new | 5 | True | 1500 / 1500 | 1189.6 | 922.6 |
| ankah | none | 0 | returning | 5 | True | 1500 / 1500 | 260.0 | n/a |
| ankah | solved | 200 | new | 5 | True | 6 / 1500 | 11241.7 | 987.0 |
| ankah | solved | 200 | returning | 5 | True | 93 / 1500 | 14426.9 | n/a |
| ankah | solved | 40 | new | 5 | True | 56 / 1500 | 14667.6 | 2201.6 |
| ankah | solved | 40 | returning | 5 | True | 552 / 1500 | 14909.0 | n/a |
| ankah | unsolved | 200 | new | 5 | True | 1500 / 1500 | 1087.3 | 886.0 |
| ankah | unsolved | 200 | returning | 5 | True | 1500 / 1500 | 222.8 | n/a |
| ankah | unsolved | 40 | new | 5 | True | 1500 / 1500 | 1089.7 | 900.0 |
| ankah | unsolved | 40 | returning | 5 | True | 1500 / 1500 | 260.8 | n/a |
| direct | none | 0 | new | 5 | True | 1500 / 1500 | 279.0 | n/a |
| direct | none | 0 | returning | 5 | True | 1500 / 1500 | 287.7 | n/a |
| direct | solved | 200 | new | 5 | True | 20 / 1500 | 25549.2 | n/a |
| direct | solved | 200 | returning | 5 | True | 20 / 1500 | 25593.2 | n/a |
| direct | solved | 40 | new | 5 | True | 160 / 1500 | 28043.8 | n/a |
| direct | solved | 40 | returning | 5 | True | 161 / 1500 | 28540.0 | n/a |
| direct | unsolved | 200 | new | 5 | True | 20 / 1500 | 25082.2 | n/a |
| direct | unsolved | 200 | returning | 5 | True | 20 / 1500 | 25185.8 | n/a |
| direct | unsolved | 40 | new | 5 | True | 162 / 1500 | 28348.8 | n/a |
| direct | unsolved | 40 | returning | 5 | True | 162 / 1500 | 28443.0 | n/a |
| dots | none | 0 | new | 5 | True | 1500 / 1500 | 1036.5 | 837.5 |
| dots | none | 0 | returning | 5 | True | 1500 / 1500 | 233.2 | n/a |
| dots | solved | 200 | new | 5 | True | 5 / 1500 | 12174.8 | 1119.6 |
| dots | solved | 200 | returning | 5 | True | 48 / 1500 | 12213.7 | n/a |
| dots | solved | 40 | new | 5 | True | 58 / 1500 | 14702.2 | 1988.8 |
| dots | solved | 40 | returning | 5 | True | 490 / 1500 | 16218.0 | n/a |
| dots | unsolved | 200 | new | 5 | True | 1500 / 1500 | 964.7 | 809.8 |
| dots | unsolved | 200 | returning | 5 | True | 1500 / 1500 | 215.5 | n/a |
| dots | unsolved | 40 | new | 5 | True | 1500 / 1500 | 1183.0 | 927.4 |
| dots | unsolved | 40 | returning | 5 | True | 1500 / 1500 | 258.6 | n/a |

## Each repeat and serving resources

| Trial | Valid load | Serving CPU seconds | Mean CPU cores | Sampled peak MiB |
|---|---|---:|---:|---:|
| ankah-none-0-r1 | True | 140.2 | 0.5 | 128.1 |
| ankah-none-0-r2 | True | 141.5 | 0.5 | 127.5 |
| ankah-none-0-r3 | True | 141.9 | 0.5 | 129.7 |
| ankah-none-0-r4 | True | 142.0 | 0.5 | 129.9 |
| ankah-none-0-r5 | True | 141.1 | 0.5 | 128.9 |
| ankah-solved-200-r1 | True | 321.6 | 1.1 | 201.1 |
| ankah-solved-200-r2 | True | 321.8 | 1.1 | 202.1 |
| ankah-solved-200-r3 | True | 321.5 | 1.1 | 201.3 |
| ankah-solved-200-r4 | True | 321.5 | 1.1 | 200.4 |
| ankah-solved-200-r5 | True | 321.3 | 1.1 | 201.0 |
| ankah-solved-40-r1 | True | 318.9 | 1.1 | 200.5 |
| ankah-solved-40-r2 | True | 319.2 | 1.1 | 202.2 |
| ankah-solved-40-r3 | True | 319.5 | 1.1 | 201.2 |
| ankah-solved-40-r4 | True | 319.9 | 1.1 | 200.4 |
| ankah-solved-40-r5 | True | 319.6 | 1.1 | 201.2 |
| ankah-unsolved-200-r1 | True | 165.4 | 0.6 | 128.7 |
| ankah-unsolved-200-r2 | True | 186.1 | 0.6 | 130.2 |
| ankah-unsolved-200-r3 | True | 168.8 | 0.6 | 129.1 |
| ankah-unsolved-200-r4 | True | 167.1 | 0.6 | 129.9 |
| ankah-unsolved-200-r5 | True | 165.2 | 0.6 | 130.0 |
| ankah-unsolved-40-r1 | True | 147.7 | 0.5 | 127.9 |
| ankah-unsolved-40-r2 | True | 156.6 | 0.5 | 129.3 |
| ankah-unsolved-40-r3 | True | 147.7 | 0.5 | 128.3 |
| ankah-unsolved-40-r4 | True | 146.6 | 0.5 | 129.0 |
| ankah-unsolved-40-r5 | True | 146.8 | 0.5 | 128.6 |
| direct-none-0-r1 | True | 132.5 | 0.4 | 120.9 |
| direct-none-0-r2 | True | 136.2 | 0.5 | 120.7 |
| direct-none-0-r3 | True | 127.0 | 0.4 | 119.3 |
| direct-none-0-r4 | True | 129.0 | 0.4 | 119.6 |
| direct-none-0-r5 | True | 126.7 | 0.4 | 119.6 |
| direct-solved-200-r1 | True | 299.0 | 1.0 | 117.2 |
| direct-solved-200-r2 | True | 299.0 | 1.0 | 118.4 |
| direct-solved-200-r3 | True | 299.0 | 1.0 | 117.8 |
| direct-solved-200-r4 | True | 299.0 | 1.0 | 117.3 |
| direct-solved-200-r5 | True | 299.0 | 1.0 | 117.6 |
| direct-solved-40-r1 | True | 299.1 | 1.0 | 118.3 |
| direct-solved-40-r2 | True | 298.9 | 1.0 | 119.0 |
| direct-solved-40-r3 | True | 299.1 | 1.0 | 117.9 |
| direct-solved-40-r4 | True | 299.1 | 1.0 | 117.8 |
| direct-solved-40-r5 | True | 299.0 | 1.0 | 118.4 |
| direct-unsolved-200-r1 | True | 299.0 | 1.0 | 117.2 |
| direct-unsolved-200-r2 | True | 299.0 | 1.0 | 117.1 |
| direct-unsolved-200-r3 | True | 299.0 | 1.0 | 118.7 |
| direct-unsolved-200-r4 | True | 299.0 | 1.0 | 118.4 |
| direct-unsolved-200-r5 | True | 299.0 | 1.0 | 118.0 |
| direct-unsolved-40-r1 | True | 299.1 | 1.0 | 117.6 |
| direct-unsolved-40-r2 | True | 299.0 | 1.0 | 117.2 |
| direct-unsolved-40-r3 | True | 299.0 | 1.0 | 118.6 |
| direct-unsolved-40-r4 | True | 299.0 | 1.0 | 118.5 |
| direct-unsolved-40-r5 | True | 299.1 | 1.0 | 118.5 |
| dots-none-0-r1 | True | 176.8 | 0.6 | 537.0 |
| dots-none-0-r2 | True | 174.4 | 0.6 | 533.3 |
| dots-none-0-r3 | True | 176.4 | 0.6 | 537.7 |
| dots-none-0-r4 | True | 177.5 | 0.6 | 536.9 |
| dots-none-0-r5 | True | 173.1 | 0.6 | 533.5 |
| dots-solved-200-r1 | True | 422.1 | 1.4 | 622.6 |
| dots-solved-200-r2 | True | 421.0 | 1.4 | 623.4 |
| dots-solved-200-r3 | True | 421.1 | 1.4 | 623.3 |
| dots-solved-200-r4 | True | 422.0 | 1.4 | 621.9 |
| dots-solved-200-r5 | True | 421.2 | 1.4 | 623.3 |
| dots-solved-40-r1 | True | 367.2 | 1.2 | 621.7 |
| dots-solved-40-r2 | True | 370.1 | 1.2 | 619.8 |
| dots-solved-40-r3 | True | 367.6 | 1.2 | 621.0 |
| dots-solved-40-r4 | True | 367.1 | 1.2 | 624.0 |
| dots-solved-40-r5 | True | 367.2 | 1.2 | 620.9 |
| dots-unsolved-200-r1 | True | 184.0 | 0.6 | 538.5 |
| dots-unsolved-200-r2 | True | 192.8 | 0.6 | 534.7 |
| dots-unsolved-200-r3 | True | 183.6 | 0.6 | 536.0 |
| dots-unsolved-200-r4 | True | 182.6 | 0.6 | 533.1 |
| dots-unsolved-200-r5 | True | 183.1 | 0.6 | 536.9 |
| dots-unsolved-40-r1 | True | 177.7 | 0.6 | 531.9 |
| dots-unsolved-40-r2 | True | 181.1 | 0.6 | 537.9 |
| dots-unsolved-40-r3 | True | 176.1 | 0.6 | 538.3 |
| dots-unsolved-40-r4 | True | 179.9 | 0.6 | 533.5 |
| dots-unsolved-40-r5 | True | 180.7 | 0.6 | 535.0 |

See summary.json for each repeat's cohort results, failures, setup charges, backend correlation, client costs, and per-container resources.
Container lifetime CPU counters include startup, preparation, and draining; the table above uses the measured window only.
Host-side sampling and Docker daemon overhead are outside container totals.
Raw observations, manifests, logs, and metadata are retained beside this report.
