# Handoff (Current)

## Scope Anchor
- Upstream: `https://github.com/starkware-libs/stwo`
- Pin: `a8fcf4bdde3778ae72f1e6cfe61a38e2911648d2`
- Contract: `CONFORMANCE.md` (strict parity + gated delivery)

## Newly Landed Parity Slices

### Prover Lookups
- `src/prover/lookups/gkr_prover.zig`
  - Full `proveBatch` flow ported.
  - Added full layer model, multivariate oracle, mask extraction, challenge progression, and artifact/proof assembly.
  - Added prove+verify tests for:
    - grand product
    - logup generic
    - logup singles
    - logup multiplicities

### Prover PCS
- `src/prover/pcs/quotient_ops.zig`
  - Ported quotient computation flow over lifted domain.
  - Added mixed-log-size handling and failure checks (shape/log-size/length invariants).

- `src/prover/pcs/mod.zig`
  - Ported commitment tree prover/decommit path.
  - Ported commitment scheme prover slices:
    - commit roots + log-size tracking
    - tree builder
    - per-tree query-position handling (including preprocessed tree mapping)
    - per-tree decommit extraction
  - Added `proveValuesFromSamples` wiring:
    - sampled-values channel mixing
    - quotient computation
    - FRI commitment/decommit
    - PoW nonce grind + transcript mixing
    - final `ExtendedCommitmentSchemeProof` assembly
  - Added roundtrip test against `core/pcs/verifier.zig`.
  - Added negative tests for shape mismatch and inconsistent sampled-value rejection.

### Prover FRI
- `src/prover/fri.zig`
  - Ported full `FriProver` commit/decommit flow (in addition to earlier layer decommit helpers).
  - Includes:
    - first layer commit/decommit
    - inner layer commit/decommit loop
    - last layer interpolation + degree enforcement
    - query sampling + decommit on sampled queries
  - Added roundtrip prover->verifier test with `core/fri.zig` verifier.
  - Added failure tests for non-canonic domain and high-degree rejection.

### Prover AIR
- `src/prover/air/accumulation.zig`
  - Ported domain accumulation slice with:
    - deterministic secure-power generation
    - per-log-size accumulation buckets
    - lifted accumulation finalize path
    - `ColumnAccumulator`/`columns` API parity slice
  - Added mixed-log-size and coefficient-accounting tests.

- `src/prover/air/component_prover.zig`
  - Ported prover-side component interface slice:
    - `Poly` and lifted-position access
    - `Trace`
    - `ComponentProver` vtable
    - `ComponentProvers` composition accumulation wiring
  - Added deterministic tests for poly lifting and composition accumulation.

### Prover Entrypoint
- `src/prover/prove.zig`
  - Added prepared-samples proving entrypoint (`provePrepared`) that wraps PCS proving into `ExtendedStarkProof`.
  - Added roundtrip test against core PCS verifier.

## Current Quality Gates (Passing)
- `zig build fmt`
- `zig build test`
- `python3 scripts/parity_fields.py`
- `cargo check --manifest-path tools/stwo-vector-gen/Cargo.toml`

## Current Known Gaps
1. `CommitmentSchemeProver.proveValues` parity is currently implemented as `proveValuesFromSamples`.
   - It requires sampled values as input instead of computing them directly from committed polynomials.
2. Missing upstream `prover/poly/circle/*` parity (evaluation/poly/secure_poly/ops), which blocks native sampled-value computation path parity.
3. Top-level `prover::prove/prove_ex` full parity is still incomplete.
   - Current entrypoint is `provePrepared` (prepared sampled-values path).
   - Full upstream-style `prove/prove_ex` still depends on `prover/poly/circle/*` and deeper `prover/air` parity.

## Next Highest-Impact Targets
1. Port `prover/poly/circle/*` minimal parity slice needed for in-prover sampled-value evaluation.
2. Upgrade `CommitmentSchemeProver` from `proveValuesFromSamples` to full upstream-style `proveValues` path.
3. Extend `prover/air` to full upstream constraint-domain evaluation flow and stitch `prover::prove_ex` end-to-end.
4. Expand differential vectors to cover newly landed prover FRI/PCS/GKR flows.

## Divergence Record (Active)
- Temporary API divergence:
  - `CommitmentSchemeProver` currently exposes `proveValuesFromSamples` as the executable parity path.
  - Closure plan: remove this as primary path once `prover/poly/circle` parity lands and full `proveValues` is wired.
