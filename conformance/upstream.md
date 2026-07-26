# Upstream Pin Ledger

This file is the single source-pin ledger for the repository's independent Rust correctness
oracles. A revision applies only to the compatibility lane that names it. Native Stwo acceptance
does not establish Cairo acceptance, and Cairo acceptance does not establish Native Stwo parity.
`python3 scripts/check_upstream_pins.py` rejects drift in manifests, lockfiles, source constants,
generated registries, persistent sessions, prover boundaries, and hosted CI checkout metadata.

## Native Stwo Lane

This lane governs the backend-neutral Native Stwo API, protocol, proof, and verifier surface.
The field names below are retained for compatibility with the Native parity and upstream-surface
checkers.

- Upstream repository: `https://github.com/starkware-libs/stwo`
- Pinned commit: `a8fcf4bdde3778ae72f1e6cfe61a38e2911648d2`
- Pin date: `2026-02-07`

## RISC-V (Stark-V) Lane

This lane governs the RV32IM frontend's executor semantics, trace format, and AIR parity target.
Stark-V is a work in progress upstream; pinning a commit turns parity into a concrete, testable
contract instead of a moving reference. Native Stwo or Cairo acceptance does not establish
Stark-V parity, and Stark-V acceptance establishes neither of the other lanes.

- Stark-V repository: `https://github.com/ClementWalter/stark-v`
- Pinned Stark-V commit: `d478f783055aa0d73a93768a433a3c6c31c91d1c`
- Stark-V pin date: `2026-06-12`

## Cairo Lane

This lane governs Cairo AIR, witness generation, statement, proof, and canonical `verify_cairo`
acceptance. The production port targets the current official StarkWare source pair:

- Official Stwo-Cairo repository: `https://github.com/starkware-libs/stwo-cairo`
- Pinned official Stwo-Cairo commit: `82f21252a68ec006d73e299f5bf1ce6d4db0ee78`
- Official Cairo Stwo repository: `https://github.com/starkware-libs/stwo`
- Pinned official Cairo Stwo commit: `7b211edde786775016ef3eecb837a6240d8fe792`

These revisions govern the production AIR registry and will govern the final
Rust `verify_cairo` adapter. The completion requirements are recorded in
`conformance/2026-07-26-stwo-cairo-production-port-goal.md`.

### Legacy SN2 evidence

Historical SN2 tooling was built from Stwo-Cairo commit `dcd58345`, which has
two deliberately distinct Stwo authorities: the verifier-compatible revision
declared by the source tree, and the clean companion revision needed to compile
its complete prover and witness surface. This evidence remains bound to the
following fork revisions and is not eligible to release the official Cairo
products:

- Stwo-Cairo repository: `https://github.com/teddyjfpender/stwo-cairo`
- Pinned Stwo-Cairo commit: `dcd5834565b7a26a27a614e353c9c60109ebc1d9`
- Stwo repository: `https://github.com/teddyjfpender/stwo`
- Pinned Cairo verifier Stwo commit: `9d7e3d6fa0fc64a0d143a8b2fcb8ee952f4de8f2`
- Pinned Cairo prover Stwo commit: `3fe684648ff31e55b71525ad689fab7dfbd88880`

The official Cairo lane is accepted only by the canonical Rust `verify_cairo`
implementation built from the official Stwo-Cairo and Stwo pair. Zig scalar,
SIMD, Metal, trace-oracle, legacy-fork, or Zig-verifier agreement cannot
override its rejection. Legacy base-trace and witness receipts are
authoritative only for their explicitly labelled legacy comparison and only
when generated from the fork Stwo-Cairo and prover-Stwo pair, without path
dependencies or dirty source.

The corresponding historical generated claim registry is retained at
`archive/cairo/legacy_claim_registry.zig`. Production code must not import it;
the active registry is the official generated registry under
`src/frontends/cairo/air/`.

The pinned Stwo-Cairo manifest itself contains a `LOCAL-ONLY` absolute-path patch and does not
compile its full prover against its declared verifier Stwo revision. Repository-owned Rust prover
tools must therefore isolate the crate in their own workspace and replace every affected Stwo
package with the exact prover revision above. The pin checker validates that complete replacement
graph and its lockfile; inheriting the upstream absolute path is forbidden.

## Native Stwo Parity Slice

The current Native Stwo increment targets:

- `core/fields/*`
- `core/fri`
- `core/pcs/quotients`
- `core/pcs/verifier`
- `core/pcs/utils`
- `core/proof`
- `core/verifier`
- `core/vcs/verifier`
- `core/test_utils`
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
- `prover/air` (accumulation + component-prover slices)
- `prover/prove` (prepared-samples + sampled-points + component-driven prove_ex slices)
- `prover/fri` (full fri prover commit/decommit flow + layer decommit slices)
- `prover/pcs` (quotient-ops + commitment tree/decommit + prove-values + prove-values-from-samples slices)
- `prover/channel` (logging channel slice)
- `prover/lookups` (utils + mle + sumcheck + gkr verifier + gkr prover prove-batch slice)
- `prover/poly` (module + twiddles + circle evaluation/poly/secure_poly/ops slices)
- `prover/secure_column`
- `tracing/mod`

## Upgrade Policy

1. Name the compatibility lane being upgraded; never reuse evidence from another lane.
2. Bump every exact revision that composes that lane's Rust oracle in this ledger. For Cairo,
   state whether the official production pair, a legacy SN2 evidence pair, or both change.
3. Update manifests, lockfiles, constants, proof envelopes, receipts, and generated artifacts that
   carry those revisions.
4. Re-run vector generation for all committed fixtures in the affected lane.
5. Require the affected Zig parity, bidirectional interoperability, and exact Rust-oracle tests to
   pass before merging.
6. Document any intentional divergence in `conformance/divergence-log.md`.
