# SEMP

SEMP is an Erlang application implementing TRUST (Trusted, Rapid, Unmodifiable, Secure Topology) as a custom, DNS-based, **non-EPMD** distribution overlay. Each RPC uses connect→(token path)→call→close.

- TLS 1.3 mTLS with client certs
- Whitelist via SHA-512 of TBSCertificate
- Token-accelerated reconnect (short TTL)
- Per-node permissions (modules/functions) + suspicion levels
- No errors are sent to clients; server logs + adjusts suspicion and closes

## Layout

- `src/` modules (incl. `trust_dist.erl` carrier)
- `include/semp.hrl`
- `priv/certs/` (dev-only)
- `rebar.config`, `.gitignore`, `LICENSE.md`, `README.md`

## Build

```bash
rebar3 compile
rebar3 shell
