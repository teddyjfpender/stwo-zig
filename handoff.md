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
  - Added direct coefficient commit path (`commitPolys`):
    - commits coefficient-form circle polynomials directly to extended-domain columns.
    - respects `setStorePolynomialsCoefficients` by cloning/storing coefficient columns.
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
  - Aligned top-level API with upstream component-driven flow:
    - `prove(components, ..., commitment_scheme)` -> `StarkProof`
    - `proveEx(components, ..., commitment_scheme, include_all_preprocessed_columns)` -> `ExtendedStarkProof`
  - Kept sampled-point proving path as explicit non-upstream helper entrypoints:
    - `proveSampledPoints`
    - `proveExSampledPoints`
  - Added component-driven proving slice (`proveExComponents` / `proveComponents`) with:
    - AIR mask-point derivation via `ComponentProvers.componentsView`
    - composition OODS sanity check against sampled values
    - in-prover composition polynomial generation + direct coefficient commit path
  - Retained prepared-samples proving entrypoint (`provePrepared`) as compatibility path.
  - Added roundtrip tests against core verifier for prepared, sampled-points, and component-driven slices.

### Toolchain/Runtime Stabilization
- Broad Zig 0.15 compatibility sweep across core/prover paths:
  - migrated `std.rand` usage to `std.Random`.
  - migrated `std.ArrayList` callsites to allocator-passing API (`.empty`, `append(allocator, ...)`, `toOwnedSlice(allocator)`, `deinit(allocator)`).
  - widened several strict error unions that previously rejected allocator or verifier-layer errors on instantiated paths.
  - normalized hash digest test formatting via `std.fmt.bytesToHex`.
  - replaced parity vector `@embedFile` use with runtime `readFileAlloc` (`vectors/fields.json`) to avoid package-path violations under root-module testing.
- Kept root `zig build test` scope aligned with existing project gate while preserving compatibility fixes in touched modules.

## Current Quality Gates (Passing)
- `zig build fmt`
- `zig build test`
- `python3 scripts/parity_fields.py`
- `cargo check --manifest-path tools/stwo-vector-gen/Cargo.toml`

## Current Known Gaps
1. `CommitmentSchemeProver.proveValues` now computes sampled values in-prover and supports stored coefficients, but still lacks shared weights hash-map caching and full upstream TwiddleTree-backed coefficient plumbing.
2. `prover/poly/circle` now has FFT-layer interpolation/evaluation, but still lacks full upstream TwiddleTree backend parity (precompute/caching and backend-specific SIMD/CPU paths).
3. Top-level `prover::prove/prove_ex` full parity is still incomplete.
   - Current executable entrypoints are component-driven (`prove`/`proveEx`, plus `proveExComponents`/`proveComponents`), sampled-points (`proveSampledPoints`/`proveExSampledPoints`), and prepared sampled-values (`provePrepared`) paths.
   - Component-driven slice now allows non-zero PCS blowup and direct composition coefficient commit, but still has remaining divergence from upstream twiddle/weights-cache internals.
4. Full-repo forced test-graph execution (`refAllDecls(core/prover/...)`) currently surfaces additional legacy failures outside the current default gate (notably FRI ownership/decommit and a few legacy expectation mismatches). These are queued for dedicated cleanup slice.

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

## Latest Slice (Deep Validation + Ownership Safety)
- `src/core/fri.zig`
  - Hardened `FriVerifier.commit` ownership semantics:
    - deep-clones first/inner layer proofs and last-layer polynomial into verifier-owned allocations.
    - avoids aliasing caller-owned proof buffers that caused double-free / UAF hazards under expanded module test graphs.
  - Added `cloneLayerProof` helper for explicit proof-data cloning.
- `src/core/vcs_lifted/verifier.zig`
  - `lessByLogSize` now uses a stable tie-break (`lhs < rhs`) when log sizes are equal.
  - Prevents nondeterministic equal-size ordering drift in lifted verifier query ordering paths.
- `src/core/pcs/verifier.zig`
  - Strengthened proof cleanup to deinitialize `fri_proof` as part of verifier proof ownership teardown.
- `src/prover/pcs/mod.zig`
  - `proveValuesFromSamples` now deep-owns `sampled_points`/`sampled_values` inputs and deinitializes them consistently.
  - Frees prover-only `fri_decommit.query_positions` before returning extended proof to eliminate allocator leaks in deep `prover prove` tests.

### Additional Gate/Probe Coverage (Passing)
- `zig test tmp_deep_probe.zig --test-filter "prover fri"` (temporary probe import of `src/prover/prove.zig` and `src/prover/pcs/mod.zig`)
- `zig test tmp_deep_probe.zig --test-filter "prover prove"`
- `zig build fmt`
- `zig build test --summary all`
- `python3 scripts/parity_fields.py`
- `cargo check --manifest-path tools/stwo-vector-gen/Cargo.toml`

## Latest Slice (PCS Sampled-Value Parity: Weights Cache)
- `src/prover/pcs/mod.zig`
  - `evaluateSampledValues` now matches upstream-style non-coefficient evaluation semantics by caching barycentric weights keyed by `(log_size, folded_point)`.
  - Reuses `CircleEvaluation.barycentricWeights` outputs across repeated sampled points instead of recomputing per sample.
  - Cache lifecycle is allocator-safe: all cached weight vectors are freed before function return.
  - Maintains existing coefficient fast path (`evalAtPoint`) when `store_polynomials_coefficients` is enabled.
- Added regression/integration test:
  - `prover pcs: prove values handles repeated sampled points across columns`
  - Covers repeated sampled points on multiple columns, sampled-value shape/value assertions, and full verifier roundtrip acceptance.

### Additional Gate/Probe Coverage (Passing)
- `zig test tmp_deep_probe.zig --test-filter "prover pcs: prove values handles repeated sampled points across columns"`
- `zig test tmp_deep_probe.zig --test-filter "prover prove"`
- `zig build fmt`
- `zig build test --summary all`
- `python3 scripts/parity_fields.py`
- `cargo check --manifest-path tools/stwo-vector-gen/Cargo.toml`

## Latest Slice (TwiddleTree-Backed FFT Reuse)
- `src/prover/poly/twiddles.zig`
  - Added owned M31 twiddle-tree construction (`precomputeM31`) and teardown (`deinitM31`).
  - Added deterministic slow twiddle precompute + inverse generation parity helper.
  - Added invariant test that twiddles and inverse twiddles multiply to one.
- `src/prover/poly/circle/poly.zig`
  - Added explicit TwiddleTree-backed APIs:
    - `CircleCoefficients.evaluateWithTwiddles(...)`
    - `interpolateFromEvaluationWithTwiddles(...)`
  - Kept existing API surface stable by routing:
    - `evaluate(...)` through owned twiddle precompute + `evaluateWithTwiddles`.
    - `interpolateFromEvaluation(...)` through owned twiddle precompute + `interpolateFromEvaluationWithTwiddles`.
  - Replaced local ad-hoc twiddle slicing with `core/poly/utils.domainLineTwiddlesFromTree` semantics.
  - Added parity tests:
    - `evaluate with twiddles matches evaluate`
    - `interpolate with twiddles matches interpolate`
- `src/prover/pcs/mod.zig`
  - Added per-log-size twiddle cache for interpolation/evaluation commit paths.
  - `interpolateCoefficientColumns` now reuses cached twiddle trees and calls `interpolateFromEvaluationWithTwiddles`.
  - `prepareColumnsForCommitOwned` extension path now evaluates coefficients through cached twiddle trees.
  - `commitPolys` now evaluates coefficient inputs through cached twiddle trees (no per-column precompute churn).

### Additional Gate/Probe Coverage (Passing)
- `zig test tmp_deep_probe.zig --test-filter "prover poly circle poly: evaluate with twiddles matches evaluate"`
- `zig test tmp_deep_probe.zig --test-filter "with twiddles"`
- `zig test tmp_deep_probe.zig --test-filter "prover prove"`
- `zig build fmt`
- `zig build test --summary all`
- `python3 scripts/parity_fields.py`
- `cargo check --manifest-path tools/stwo-vector-gen/Cargo.toml`
