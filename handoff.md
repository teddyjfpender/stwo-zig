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
  - Ported non-zero blowup commit semantics:
    - columns are now committed on the extended domain (`log_size + log_blowup_factor`) via interpolation + canonic-domain evaluation.
    - `proveValues` / `proveValuesFromSamples` no longer reject non-zero blowup.
    - added non-zero blowup roundtrip coverage for both sampled-values and in-prover sampled-point paths.
  - Wired `setStorePolynomialsCoefficients` slice:
    - committed trees can now retain base polynomial coefficients.
    - `proveValues` evaluates sampled points from stored coefficients when present (fallback remains barycentric on committed evaluations).
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
    - `evaluate` (FFT-layer path with upstream small-domain special cases)
    - `interpolateFromEvaluation` (FFT inverse-layer path with upstream small-domain special cases)
    - `splitAtMid`
  - Added split-identity, domain-evaluation, and interpolation roundtrip tests.
  - Added deterministic twiddle generation + FFT layer helpers (`slowPrecomputeTwiddles`, line/circle twiddle slicing, butterfly/ibutterfly loops).
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
1. `CommitmentSchemeProver.proveValues` now computes sampled values in-prover and supports stored coefficients, but still lacks shared weights hash-map caching and full upstream TwiddleTree-backed coefficient plumbing.
2. `prover/poly/circle` now has FFT-layer interpolation/evaluation, but still lacks full upstream TwiddleTree backend parity (precompute/caching and backend-specific SIMD/CPU paths).
3. Top-level `prover::prove/prove_ex` full parity is still incomplete.
   - Current executable entrypoints are sampled-points (`prove`/`proveEx`), component-driven (`proveExComponents`/`proveComponents`), and prepared sampled-values (`provePrepared`) paths.
   - Component-driven slice now allows non-zero PCS blowup, but still uses reference interpolation/evaluation in composition commit path.

## Next Highest-Impact Targets
1. Complete FFT/twiddle-backed circle interpolation/evaluation parity and wire `store_polynomials_coefficients` fast path.
2. Implement full upstream `prover::prove` / `prover::prove_ex` pipeline parity on top of in-prover PCS `proveValues`.
3. Expand differential vectors to cover prover-side circle poly slices and full `proveValues` (including non-zero blowup cases).
4. Strengthen component-driven `proveEx` parity coverage with non-zero blowup fixtures.

## Divergence Record (Active)
- Temporary implementation divergence:
  - `CommitmentSchemeProver.proveValues` now has a stored-coefficients fast path, but still lacks upstream-equivalent shared weights cache map and backend-integrated coefficient flow.
  - `prover/poly/circle` currently uses local twiddle generation per operation (no shared TwiddleTree cache wiring yet).
  - Closure plan: complete `prover/poly/circle` coefficient stack and route `setStorePolynomialsCoefficients` through upstream-equivalent branching.
