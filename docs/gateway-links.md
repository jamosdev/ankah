# Linked gateways and session storage

Use links when several Ankah gateways serve the same public host. Every node
must use the same `--public-origin` host and `--secret-file` content, and each
node must list every other node. Links authenticate and encrypt traffic with
TLS PSK keys derived from that secret and public host. Keep the link listener
reachable only from the other gateways.

For two nodes with private addresses `10.0.0.11` and `10.0.0.12`:

```sh
# On 10.0.0.11
ankah --public-origin https://example.test --secret-file /run/secrets/ankah \
  --ankah-link 10.0.0.12:41113 --ankah-link-listen 10.0.0.11:41113 ...

# On 10.0.0.12
ankah --public-origin https://example.test --secret-file /run/secrets/ankah \
  --ankah-link 10.0.0.11:41113 --ankah-link-listen 10.0.0.12:41113 ...
```

Repeat `--ankah-link host[:port]` for each peer. The default peer and listener
port is `41113`. IPv6 peers use `[address]:port`, and the listen option accepts
a numeric `address:port` or `[IPv6]:port`. If a peer is configured without
`--ankah-link-listen`, Ankah listens on `0.0.0.0:41113`. Peer names are resolved
asynchronously at startup and on reconnect, so address changes are picked up
when a link reconnects. Use a full mesh; the gateways do not relay messages
between peers.

Challenge creation sends no link message. A phone can open the QR or solve page
and submit a valid answer to any node. The answer is checked from the shared
secret and then the solved state is sent to peers. Each node checks
`ankah_sid` from its own state; the original browser receives a signed
`ankah_pass` cookie when it finishes. Rate buckets stay local. An abuse decision
also installs a ten-minute local client IP block and sends capped batches of
blocks to peers. Trusted proxy block actions remain available.

An unsolved POST and its body stay on the node that received them. Once proof
has been solved, the browser can submit its one-use continuation on any node.
That node asks the original node for the saved request. The original node
records consumption durably before releasing the request, so concurrent
continuations cannot use the token twice. If the original node or its link is
unavailable, the continuation returns `503` with `Retry-After: 1`; the token
remains available for retry. The nodes do not replicate unsolved POST bodies.

## Session files

Session persistence is on by default. The default basename is
`ankah.sessions` in the process working directory. Use
`--session-state-file path` to choose another basename, or
`--no-session-state-file` to use memory only. Each node needs its own basename
and a writable private directory. Two rotating snapshots use `.0` and `.1`
suffixes; a `.tmp` file is used during replacement. A `.journal` file records
one-use POST consumption and must be kept with the snapshots. File access is
restricted to the gateway account. Do not share these files between nodes.

Dirty sessions are scheduled for a snapshot at most once every 30 seconds and
again during clean shutdown. Journal maintenance can schedule additional
snapshots, including when sessions have not changed, until both snapshot slots
no longer contain consumed POSTs. These attempts are spaced at least five
seconds apart after success and 30 seconds after failure. The main request loop
copies a bounded amount of saved body data at a time and hands the completed
snapshot to a dedicated disk writer. The writer also handles dashboard
snapshots and consumption records. It runs at background CPU and disk priority
where supported. Snapshot failures and lag over 90 seconds are reported on
standard error.

The 30-second interval is a schedule, not a maximum loss window if disk writes
fall behind. A sudden stop can lose sessions and unproved POSTs that were not
in a durable snapshot. The consumption journal prevents an older snapshot from
making an already consumed POST usable again. Keep it during backup and
restore. The writer compacts records no longer needed by either snapshot slot.
The active journal has a 1 MiB limit for new writes. If snapshots cannot make
room, new continuations return `503` with `Retry-After: 1` until storage
recovers. An existing larger journal is validated and compacted before new
records are accepted. A temporary file can briefly require additional space.

If a journal is malformed, saved POSTs are discarded and continuations pause
while both snapshot slots are durably refreshed and the journal is reset. If a
snapshot slot cannot be read or validated, compaction waits until a durable
replacement of that slot succeeds. Persistent storage failures continue to
return retryable `503` responses.
