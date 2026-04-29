# v0.1 Serialization Fixtures

These fixtures define the expected v0.1 wire-shape for core protocol objects.

- `envelope.v0.1.json`
- `private_payload.v0.1.json`
- `identity_document.v0.1.json`
- `prekey_bundle.v0.1.json`

## Stability Rules

- Treat these fixtures as protocol stability guards, not sample throwaway data.
- Changes to fixture field names or shape MUST be reviewed against RFC-0002 and/or RFC-0003.
- Fixture updates SHOULD NOT be made casually; they imply wire-contract impact.
