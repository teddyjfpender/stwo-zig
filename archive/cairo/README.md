# Legacy Cairo Evidence

This directory preserves source identities used by historical SN2 comparison
artifacts. Nothing here is part of the production Cairo frontend or a release
oracle.

`legacy_claim_registry.zig` is the generated registry for the historical
`teddyjfpender/stwo-cairo` pin recorded in `conformance/upstream.md`. Active
claim generation imports
`src/frontends/cairo/air/official_claim_registry.zig` exclusively.
