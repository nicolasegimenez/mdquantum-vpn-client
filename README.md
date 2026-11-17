# MDQuantum VPN client

Rust client under development for a VPN using hybrid post-quantum TLS.

## Implemented

- Command-line configuration and PEM trust roots (custom roots replace public roots).
- Actual TCP/TLS connection with a 10-second deadline covering DNS, TCP and TLS.
- TLS 1.3 only, with X25519MLKEM768 as the only allowed key exchange group.
- Certificate chain and hostname verification through rustls.
- Negotiated TLS version and key exchange logged after connection.
- Local development echo server and tests of encrypted data exchange and rejection cases.

The CLI currently establishes the connection, reports it, and exits. It does not
forward application traffic yet. `--port` is reserved for the future SOCKS5
listener and does not open a listening socket. There is no TUN interface,
production VPN server, client authentication, routing, or DNS management yet.
Hybrid key exchange does not imply post-quantum certificate signatures.

## Try locally

Requires a Rust toolchain supporting edition 2024 and the native build tools
needed by aws-lc-rs (including a C compiler and CMake).

From this repository root, start the loopback-only test server:

```sh
cargo run --locked --example echo-server
```

It listens on `127.0.0.1:8443` and prints the path of an ephemeral public
certificate. Use that path in another terminal:

```sh
cargo run --locked --bin vpn-client -- \
  --server-domain localhost --server-port 8443 \
  --server-cert /tmp/mdquantum-dev-PID.pem
```

Replace `PID` with the value printed by the server. The private key remains in
memory. Stop the example with Ctrl+C; its public PEM can then be deleted.
The example handles connections sequentially with a 10-second deadline and is
only a local fixture. The integration test verifies actual echo traffic.

## Verify

```sh
cargo fmt --check
cargo test --locked --all-targets
cargo clippy --locked --all-targets -- -D warnings
```

Tests cover hybrid TLS 1.3 data exchange, rejection of classical-only key
exchange, TLS 1.2, untrusted certificates and hostname mismatch, plus certificate
loading and configured key exchange preference.

## Next milestones

1. Agree on server authentication, destination permissions and a bounded message format.
2. Implement SOCKS5 CONNECT with client/server TCP forwarding and integration tests.
3. Add TUN, routing, DNS, IPv6 and recovery according to product requirements.
4. Validate the server endpoint with the separate `mdq` scanner.

TLS encryption and integrity are delegated to rustls and aws-lc-rs.

## License

See [LICENSE](LICENSE) for the project's license terms.
