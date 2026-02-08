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
    - in-prover sampled-value computation (`proveValues`) from committed columns via barycentric circle evaluation
  - Added `proveValuesFromSamples` wiring:
    - sampled-values channel mixing
    - quotient computation
    - FRI commitment/decommit
    - PoW nonce grind + transcript mixing
    - final `ExtendedCommitmentSchemeProof` assembly
  - Added roundtrip test against `core/pcs/verifier.zig`.
  - Added negative tests for shape mismatch, inconsistent sampled-value rejection, and sampled-point-on-domain rejection.

### Prover Poly (Circle)
- `src/prover/poly/circle/evaluation.zig`
  - Ported circle evaluation slice for base-field columns in bit-reversed order.
  - Added barycentric weights/evaluation path matching upstream canonic-coset semantics.
  - Added deterministic tests for:
    - constant-column out-of-domain evaluation
    - x-coordinate polynomial evaluation
    - point-on-domain rejection.
- `src/prover/poly/circle/poly.zig`
  - Ported circle coefficient polynomial slice with:
    - `CircleCoefficients` ownership + invariants
    - `evalAtPoint`
    - `extend`
    - `evaluate` (naive domain evaluation path)
    - `interpolateFromEvaluation` (deterministic Gaussian-elimination reference path)
    - `splitAtMid`
  - Added split-identity, domain-evaluation, and interpolation roundtrip tests.
- `src/prover/poly/circle/secure_poly.zig`
  - Ported secure-coordinate polynomial wrapper slice:
    - `SecureCirclePoly.evalAtPoint`
    - `splitAtMid`
    - `interpolateFromEvaluation`
  - Added secure split-identity, shape-failure, and interpolation roundtrip tests.
- `src/prover/poly/circle/ops.zig`
  - Added circle-poly operation helpers (`evaluateOnCanonicDomain`, split helpers) to stabilize call sites.

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
    - bridge adapter to `core/air/components` (`componentsView`) for mask/point-eval orchestration
  - Added deterministic tests for poly lifting and composition accumulation.

### Prover Entrypoint
- `src/prover/prove.zig`
  - Added sampled-points proving entrypoints (`prove`, `proveEx`) backed by in-prover PCS `proveValues`.
  - Added component-driven proving slice (`proveExComponents` / `proveComponents`) with:
    - AIR mask-point derivation via `ComponentProvers.componentsView`
    - composition OODS sanity check against sampled values
    - in-prover composition polynomial generation + commit (reference interpolation path)
  - Retained prepared-samples proving entrypoint (`provePrepared`) as compatibility path.
  - Added roundtrip tests against core verifier for prepared, sampled-points, and component-driven slices.

## Current Quality Gates (Passing)
- `zig build fmt`
- `zig build test`
- `python3 scripts/parity_fields.py`
- `cargo check --manifest-path tools/stwo-vector-gen/Cargo.toml`

## Current Known Gaps
1. `CommitmentSchemeProver.proveValues` now computes sampled values in-prover, but does not yet use/store circle coefficients + shared weights hash-map optimization path from upstream.
2. `prover/poly/circle` is now executable but still missing full upstream FFT/twiddle-backed interpolation/evaluation parity.
3. Top-level `prover::prove/prove_ex` full parity is still incomplete.
   - Current executable entrypoints are sampled-points (`prove`/`proveEx`), component-driven (`proveExComponents`/`proveComponents`), and prepared sampled-values (`provePrepared`) paths.
   - Component-driven slice currently enforces zero PCS blowup (`log_blowup_factor == 0`) while composition commit uses reference evaluation/interpolation.

## Next Highest-Impact Targets
1. Complete FFT/twiddle-backed circle interpolation/evaluation parity and wire `store_polynomials_coefficients` fast path.
2. Generalize component-driven proving to non-zero blowup (align `ColumnEvaluation`/commit semantics with upstream extended-domain handling).
3. Implement full upstream `prover::prove` / `prover::prove_ex` pipeline parity on top of in-prover PCS `proveValues`.
4. Expand differential vectors to cover prover-side circle poly slices and full `proveValues`.

## Divergence Record (Active)
- Temporary implementation divergence:
  - `CommitmentSchemeProver.proveValues` currently evaluates from committed column evaluations only (no stored-coefficients fast path and no weights cache map).
  - Component-driven `proveExComponents` currently supports only `log_blowup_factor == 0`.
  - Closure plan: complete `prover/poly/circle` coefficient stack and route `setStorePolynomialsCoefficients` through upstream-equivalent branching.
