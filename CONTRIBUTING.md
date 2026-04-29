# Contributing to aegis-core

## Scope

`aegis-core` contains shared protocol, crypto, identity, and API type crates.

Protocol semantics are defined in:

- `../aegis-spec/docs/protocol-index.md`
- `../aegis-spec/docs/implementation-conformance-v0.1.md`

## Development Workflow

```sh
cargo fmt
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## CI Expectations

This repo runs Rust CI for `fmt`, `clippy`, and tests.

## Protocol Change Policy

- Protocol field changes MUST update RFC/schema/fixture artifacts in `aegis-spec` and proto fixtures.
- Relay behavior changes belong in relay repos and MUST update `RFC-0004` + conformance docs.
- Identity behavior changes MUST update `RFC-0002` + conformance docs.

## Current v0.1 Status

Core crates support local-development demo crypto and signing only.

- no production PQ cryptography yet
- no production resolver service yet
