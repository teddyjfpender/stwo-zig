# Upstream Pin

This repository is porting StarkWare `stwo` to Zig with strict parity checkpoints.

- Upstream repository: `https://github.com/starkware-libs/stwo`
- Pinned commit: `a8fcf4bdde3778ae72f1e6cfe61a38e2911648d2`
- Pin date: `2026-02-07`

## Current Parity Slice

This increment targets:

- `core/fields/*`
- `core/fri`
- `core/pcs/quotients`
- `core/pcs/verifier`
- `core/proof`
- `core/verifier`
- `core/vcs/verifier`
- `core/vcs/hash`
- `core/vcs/merkle_hasher`
- `core/vcs/utils`
- `core/vcs/test_utils`
- `core/vcs_lifted/merkle_hasher`
- `core/vcs_lifted/verifier`
- `core/vcs_lifted/test_utils`
- `prover/vcs/prover`
- `prover/vcs/ops`
- `prover/vcs_lifted/prover`
- `prover/vcs_lifted/ops`
- `prover/line`
- `prover/fri` (decommit helper + layer decommit slices)
- `prover/secure_column`
- `tracing/mod`

## Upgrade Policy

1. Bump the pin in this file to a specific upstream commit.
2. Re-run vector generation for all committed parity fixtures.
3. Require Zig parity tests to pass before merging.
4. Document any intentional divergence in `handoff.md`.
