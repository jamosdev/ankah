# Limitations

This page records features that are out of scope and will not be implemented.

## Contents

- [Connection admission](#connection-admission)
  - [Preferential TCP admission for previously proved clients](#preferential-tcp-admission-for-previously-proved-clients)

## Connection admission

### Preferential TCP admission for previously proved clients

This feature would reserve some TCP connection slots for source IP addresses
associated with a recently passed proof of work challenge. During a flood,
connections from those addresses could reach HTTP parsing before other clients.
Each request would still need its normal session cookie or pass.

This feature is out of scope and will not be implemented. When Ankah runs behind
a TLS terminating reverse proxy, every TCP connection may have the proxy's IP
address. Ankah resolves the client's IP from trusted forwarding headers only
after admitting the connection and parsing its HTTP headers, so TCP admission
cannot distinguish those clients. A trusted proxy can separately block a source
after receiving an [abuse action](proxy-abuse.md), and can reject connection
floods from its own socket observations. That early denial does not reserve
capacity for previously proved clients.
