# File Tunnel public library core

Frontend-safe runtime policy and configuration primitives for File Tunnel clients.

The crate is side-effect free and is suitable for browsers, Flutter hosts,
native desktop applications, CLIs, and external SDKs. It models three access
modes without confusing authentication with File Tunnel authorization:

- `one_time` uses short-lived tunnel capabilities for one exact tunnel and does
  not require an account.
- `individual` requires Shared Auth for the exact `file-tunnel-api` audience;
  File Tunnel still verifies account ownership, billing, quotas, and access.
- `organization` requires the same exact audience; File Tunnel independently
  verifies the selected organization membership and role.

An organization identifier is client-selected routing context, never evidence
of membership. Administrator and internal-service modes are deliberately
unrepresentable.

## Transport boundary

- Remote API origins require HTTPS.
- Remote event origins require WSS.
- HTTP and WS are accepted only for loopback development.
- URL credentials, paths, queries, and fragments are rejected.
- Raw TCP, NATS, database, and admin transports remain internal and cannot be
  configured through this package.

Bearer tokens, refresh tokens, pairing capabilities, event tickets, service
credentials, delegation grants, database URLs, provider keys, presigned URLs,
and object-store credentials are not configuration fields. Credential
acquisition and storage remain in Shared Auth clients and platform-secure
credential providers.

Wire contracts are owned by
[`file-tunnel/ftnl-interfaces`](https://github.com/file-tunnel/ftnl-interfaces).
This repository does not fork TypeSpec, JSON Schema, OpenAPI, AsyncAPI,
Protobuf, or generated bindings.

## Development

Run:

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
cargo build --locked --release
```

The crate contains no React, JSX, TSX, environment reader, CLI parser, network
client, database client, global logger, or telemetry provider.
