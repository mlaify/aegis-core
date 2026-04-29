# aegis-core

Shared Rust crates for the Aegis ecosystem.

## Workspace Crates

- `aegis-proto` - protocol object model
- `aegis-crypto` - crypto traits and demo implementation
- `aegis-identity` - identity helpers and resolver interfaces
- `aegis-api-types` - relay request/response/error types
- `aegis-testkit` - sample fixtures

## Protocol References

- `../aegis-spec/docs/protocol-index.md`
- `../aegis-spec/docs/implementation-conformance-v0.1.md`
- `../aegis-docs/docs/architecture-overview.md` (human-oriented overview)

## Current v0.1.0-alpha Status

This repo implements draft/prototype core behavior for Aegis `v0.1.0-alpha`.

- demo crypto/signing is non-production
- no production PQ suite implementation
- no production network resolver implementation

## Development Workflow

```sh
cargo fmt
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## CI Expectations

GitHub Actions runs `fmt`, `clippy`, and tests for this repo.

## Protocol Change Policy

- Protocol field changes MUST update RFC/schema/fixture artifacts.
- Relay behavior changes MUST update `RFC-0004` and conformance docs.
- Identity behavior changes MUST update `RFC-0002` and conformance docs.

## Contributing

See `CONTRIBUTING.md`.
