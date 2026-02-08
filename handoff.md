# Handoff (Current)

## Scope Anchor
- Upstream: `https://github.com/starkware-libs/stwo`
- Pin: `a8fcf4bdde3778ae72f1e6cfe61a38e2911648d2`
- Contract: `CONFORMANCE.md` (strict parity + gated delivery)

## Latest Slice (True Proof Exchange Interop)

### Rust<->Zig Artifact Exchange
- Replaced fixture-bridge interop path with true bidirectional proof exchange:
  - Rust-generated proof artifacts verify in Zig.
  - Zig-generated proof artifacts verify in Rust.
  - Tampered artifacts are rejected in both directions.
  - Tamper coverage now includes both:
    - semantic statement mutation rejection
    - proof-byte corruption rejection.
- New exchange mode:
  - `proof_exchange_json_wire_v1`
- New interop artifact directory:
  - `vectors/reports/interop_artifacts/`

### Harness + Tooling
- `scripts/e2e_interop.py`
  - Rewritten to run proof-exchange matrix for:
    - `xor`
    - `state_machine`
  - Emits machine-readable report:
    - `vectors/reports/e2e_interop_report.json`
    - `vectors/reports/latest_e2e_interop_report.json`
  - Hard-validates artifact metadata:
    - schema version
    - exchange mode
    - pinned upstream commit
    - generator/runtime ownership.
- `tools/stwo-interop-rs/src/main.rs`
  - Fixed compile path to use public `stwo::prover` exports.
  - Requires upstream-pinned nightly toolchain (`nightly-2025-07-14`).
- `build.zig`
  - `interop` step now points to proof-exchange harness semantics.
  - Added deterministic `release-gate` sequence:
    - `fmt -> test -> vectors -> interop -> bench-smoke -> profile-smoke`
- `README.md`
  - Updated conformance gate docs with true exchange behavior and new `release-gate`.

### Additional Gate Coverage (Passing)
- `cargo +nightly-2025-07-14 check --manifest-path tools/stwo-interop-rs/Cargo.toml`
- `python3 scripts/e2e_interop.py`
- `zig build interop`
- `zig build release-gate`

## Latest Slice (Benchmark/Profile Protocol Upgrade)

### Benchmark Harness
- `scripts/benchmark_smoke.py`
  - Upgraded from fixture smoke timing to matched Rust-vs-Zig proving protocol on
    release interop binaries.
  - Benchmarks deterministic workload matrix (`xor` + `state_machine`) on shared
    config inputs and records:
    - prove latency samples
    - verify latency samples
    - per-sample peak RSS (`time -l`)
    - proof wire size
    - commitments/decommitments shape metrics
  - Enforces default Zig/Rust latency gate:
    - `zig_over_rust <= 1.50` (per `CONFORMANCE.md` section 9.2).
  - Supports stricter optional matrix:
    - `--include-medium`

### Profiling Harness
- `scripts/profile_smoke.py`
  - Upgraded from coarse smoke to hotspot-attribution profiling:
    - deep proving workloads (`state_machine_deep`, `xor_deep`)
    - repeated `time -l` metrics (wall, RSS, instructions, cycles)
    - `sample`-based hotspot extraction (`Sort by top of stack`)
  - Emits actionable mitigation hints keyed by hotspot classes
    (quotient/FRI, hash/Merkle, allocator churn, field/circle mul).

### Additional Gate Coverage (Passing)
- `zig build bench-smoke`
- `zig build profile-smoke`
- `zig build release-gate`

## Latest Slice (Canonical Release Evidence Manifest)

- Added `scripts/release_evidence.py`:
  - emits deterministic machine-readable manifest:
    - `vectors/reports/release_evidence.json`
    - `vectors/reports/latest_release_evidence.json`
  - records:
    - git SHA / branch / dirty flag
    - pinned upstream commit (from interop report)
    - gate command matrix (`release-gate` or `release-gate-strict`)
    - interop/benchmark/profile report paths + SHA-256 hashes + statuses
    - overall pass/fail summary.
- `build.zig`:
  - added `release-evidence` step.
  - extended `release-gate-strict` chain with final `release-evidence` stage.

### Additional Gate Coverage (Current)
- `python3 scripts/release_evidence.py --gate-mode strict`
  - emits manifest and returns non-zero when strict reports are not all green.

## Latest Slice (Prover API Surface Tightening)

- `src/prover/prove.zig`
  - Tightened public API surface to upstream-equivalent entrypoints only:
    - public: `prove`, `proveEx`
    - internal-only helpers: sampled-point/prepared/component helper paths used for internal testing and staged parity closure.
  - This removes non-upstream helper functions from exported contracts while preserving current deterministic test coverage.

### Additional Gate Coverage (Passing)
- `zig build test --summary all`
- `zig build release-gate`

## Latest Slice (Examples Wrappers + Gate Harnesses)

### Example Proof Wrappers
- `src/examples/state_machine.zig`
  - Added end-to-end `prove(...)` / `verify(...)` wrappers over real component-driven pipeline:
    - `prover/prove.zig::prove`
    - `core/verifier.zig::verify`
    - `prover/pcs::CommitmentSchemeProver`
    - `core/pcs/verifier::CommitmentSchemeVerifier`
  - Added transcript wiring for config/statement/public-input/claim mixing.
  - Added wrapper-specific component adapter implementing both prover and verifier component vtables.
  - Added wrapper tests:
    - roundtrip prove+verify
    - statement tamper rejection.

- `src/examples/xor.zig`
  - Added end-to-end `prove(...)` / `verify(...)` wrappers over the same real proving/verifying path.
  - Added deterministic preprocessed/main commitment wiring and statement mixing.
  - Added wrapper-specific prover/verifier component adapter.
  - Added wrapper tests:
    - roundtrip prove+verify
    - statement mismatch rejection.

### Build Gates + Harness Scripts
- `build.zig`
  - Added explicit conformance-smoke steps:
    - `zig build interop`
    - `zig build bench-smoke`
    - `zig build profile-smoke`
- Added new harnesses:
  - `scripts/e2e_interop.py`
    - fixture-bridge interop gate (Rust vectors + Zig wrapper proof-path checks + optional upstream examples check).
  - `scripts/benchmark_smoke.py`
    - deterministic short benchmark runs with JSON report output.
  - `scripts/profile_smoke.py`
    - coarse profiling smoke (`/usr/bin/time -l` peak RSS + wall-clock) with JSON report output.
- `README.md`
  - Added smoke-gate command documentation for vectors/interop/bench/profile steps.

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
  - Added sampled-point proving helper paths for staged parity closure:
    - `proveSampledPoints`
    - `proveExSampledPoints`
  - Added component-driven proving slice (`proveExComponents` / `proveComponents`) with:
    - AIR mask-point derivation via `ComponentProvers.componentsView`
    - composition OODS sanity check against sampled values
    - in-prover composition polynomial generation + direct coefficient commit path
  - Retained prepared-samples helper entrypoint (`provePrepared`) as compatibility path.
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
- `zig build test --summary all`
- `python3 scripts/parity_fields.py`
- `zig build interop`
- `zig build bench-smoke`
- `zig build profile-smoke`
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

## Latest Slice (Secure-Poly Twiddle Reuse)
- `src/prover/poly/circle/secure_poly.zig`
  - Added `interpolateFromEvaluationWithTwiddles(...)` so secure interpolation can reuse one precomputed twiddle tree across all secure coordinates.
  - Routed existing `interpolateFromEvaluation(...)` through owned twiddle precompute + with-twiddles path, preserving API while aligning behavior with upstream twiddle reuse structure.
  - Added parity regression test:
    - `prover poly circle secure poly: interpolate with twiddles matches interpolate`

### Additional Gate/Probe Coverage (Passing)
- `zig test tmp_deep_probe.zig --test-filter "secure poly: interpolate with twiddles matches interpolate"`
- `zig test tmp_deep_probe.zig --test-filter "prover prove"`
- `zig build fmt`
- `zig build test --summary all`
- `python3 scripts/parity_fields.py`
- `cargo check --manifest-path tools/stwo-vector-gen/Cargo.toml`

## Latest Slice (PCS Mixed-Log Twiddle Cache Coverage)
- `src/prover/pcs/mod.zig`
  - Added edge regression test:
    - `prover pcs: commit polys supports mixed log sizes with twiddle cache`
  - Validates `commitPolys` twiddle-cache behavior when committing multiple coefficient polynomials with different log sizes in one call.
  - Asserts extended-domain log-size/length expectations and constant-value preservation across both committed columns.

### Additional Gate/Probe Coverage (Passing)
- `zig test tmp_deep_probe.zig --test-filter "prover pcs: commit polys supports mixed log sizes with twiddle cache"`
- `zig test tmp_deep_probe.zig --test-filter "secure poly: interpolate with twiddles matches interpolate"`
- `zig test tmp_deep_probe.zig --test-filter "prover prove"`
- `zig build fmt`
- `zig build test --summary all`
- `python3 scripts/parity_fields.py`
- `cargo check --manifest-path tools/stwo-vector-gen/Cargo.toml`

## Latest Slice (Twiddle Inversion Parity: Chunked Path)
- `src/prover/poly/twiddles.zig`
  - `precomputeM31` now mirrors upstream inversion strategy:
    - small domains: direct per-element inversion.
    - large domains: chunked `batchInverseChunked` inversion path.
  - Added large-domain regression:
    - `twiddle tree: precompute m31 uses chunked inverse path for large domains`
  - Keeps existing twiddle/inverse product invariants and deterministic behavior.

### Additional Gate/Probe Coverage (Passing)
- `zig test tmp_deep_probe.zig --test-filter "twiddle tree: precompute m31 uses chunked inverse path for large domains"`
- `zig test tmp_deep_probe.zig --test-filter "prover prove"`
- `zig build fmt`
- `zig build test --summary all`
- `python3 scripts/parity_fields.py`
- `cargo check --manifest-path tools/stwo-vector-gen/Cargo.toml`

## Latest Slice (Examples Parity Vectors: state_machine + xor)
- `src/examples/mod.zig`
  - Added exported examples module surface:
    - `state_machine`
    - `xor`
- `src/examples/state_machine.zig`
  - Added deterministic trace generation parity slice:
    - `genTrace(allocator, log_size, initial_state, inc_index)` using bit-reversed circle-domain indexing.
    - `deinitTrace(...)` ownership helper.
  - Added public-state transition parity helper:
    - `transitionStates(log_n_rows, initial_state)` with upstream-equivalent intermediate/final formulas.
  - Added tests for success and failure paths (`InvalidIncIndex`, `InvalidLogSize`).
- `src/examples/xor.zig`
  - Added deterministic preprocessed-column generators:
    - `genIsFirstColumn(...)`
    - `genIsStepWithOffsetColumn(...)` using bit-reversed circle-domain indexing.
  - Added tests for success and failure paths (`InvalidStep`).
- `tools/stwo-vector-gen/src/main.rs`
  - Extended field-vector schema and generation with:
    - `example_state_machine_trace`
    - `example_state_machine_transitions`
    - `example_xor_is_first`
    - `example_xor_is_step_with_offset`
  - Added deterministic generators for each section and state encoding helper.
- `src/core/fields/parity_vectors.zig`
  - Extended JSON parser schema for all new example sections.
  - Added parity tests that compare Rust-generated vectors against Zig example implementations.
  - Added explicit negative differential checks in each new parity slice:
    - state-machine trace (`inc_index` perturbation)
    - state-machine transitions (mutated initial state)
    - xor `is_first` (different `log_size`)
    - xor `is_step_with_offset` (step/offset perturbation)
- `vectors/fields.json`
  - Regenerated deterministically with new example vector sections.

### Additional Gate/Probe Coverage (Passing)
- `zig build fmt`
- `cargo check --manifest-path tools/stwo-vector-gen/Cargo.toml`
- `python3 scripts/parity_fields.py --regenerate --skip-zig`
- `python3 scripts/parity_fields.py`
- `zig build test --summary all`

## Latest Slice (State-Machine Lookup Claimed-Sum Parity)
- `src/examples/state_machine.zig`
  - Added `Elements` lookup combiner:
    - `combine(state) = state[0] + alpha * state[1] - z`
  - Added interaction claimed-sum helpers:
    - `claimedSumFromInitial(...)` (direct row accumulation)
    - `claimedSumTelescoping(...)` (first/last inverse form)
  - Added deterministic parity test:
    - direct accumulation equals telescoping form.
  - Added explicit failure mode:
    - `DegenerateDenominator` when lookup denominator is zero.
- `tools/stwo-vector-gen/src/main.rs`
  - Extended vector schema with:
    - `example_state_machine_claimed_sum`
  - Added deterministic generator covering:
    - `log_size`, `initial_state`, `inc_index`
    - lookup elements (`z`, `alpha`)
    - `claimed_sum`
    - `telescoping_claim`
  - Skips degenerate denominator samples deterministically.
- `src/core/fields/parity_vectors.zig`
  - Added parser schema for `example_state_machine_claimed_sum`.
  - Added parity test that validates:
    - direct claimed-sum output
    - telescoping output
    - direct == telescoping identity
  - Added negative differential case:
    - perturbed `alpha` must alter behavior (or trigger expected degeneracy).
- `vectors/fields.json`
  - Regenerated deterministically with claimed-sum vectors.

### Additional Gate/Probe Coverage (Passing)
- `zig build fmt`
- `cargo fmt --manifest-path tools/stwo-vector-gen/Cargo.toml`
- `cargo check --manifest-path tools/stwo-vector-gen/Cargo.toml`
- `python3 scripts/parity_fields.py --regenerate --skip-zig`
- `python3 scripts/parity_fields.py`
- `zig build test --summary all`

## Latest Slice (Examples Cross-Language Harness Report)
- `scripts/e2e_examples.py`
  - Added a dedicated examples parity harness that gates:
    - Rust fixture generation (`tools/stwo-vector-gen`)
    - committed-vector consistency checks
    - Zig parity execution (`zig build test`)
  - Added strict required-section coverage checks for:
    - `example_state_machine_trace`
    - `example_state_machine_transitions`
    - `example_state_machine_claimed_sum`
    - `example_xor_is_first`
    - `example_xor_is_step_with_offset`
  - Added machine-readable harness report output:
    - `vectors/reports/examples_parity_report.json`
    - convenience mirror `vectors/reports/latest_examples_parity_report.json`
  - Supports both:
    - check mode (must match committed vectors)
    - regenerate mode (`--regenerate`)

### Additional Gate/Probe Coverage (Passing)
- `python3 scripts/e2e_examples.py`
- `python3 scripts/e2e_examples.py --regenerate --skip-zig`
- `zig build fmt`
- `cargo check --manifest-path tools/stwo-vector-gen/Cargo.toml`
- `python3 scripts/parity_fields.py`
- `zig build test --summary all`

## Latest Slice (State-Machine Lookup Draw Parity)
- `src/examples/state_machine.zig`
  - Added `Elements.draw(channel)` for channel-driven lookup element sampling (`z`, `alpha`).
  - Added regression test to ensure successive draws evolve channel state.
- `tools/stwo-vector-gen/src/main.rs`
  - Extended vector schema with:
    - `example_state_machine_lookup_draw`
  - Added deterministic generator vectors that include:
    - `mix_u64`
    - `mix_u32s`
    - sampled `z` and `alpha` after channel mixing.
- `src/core/fields/parity_vectors.zig`
  - Added parser schema for `example_state_machine_lookup_draw`.
  - Added parity test that replays channel mixing and validates `Elements.draw`.
  - Added negative differential case:
    - perturb `mix_u64` and require a changed draw output.
- `vectors/fields.json`
  - Regenerated deterministically with lookup-draw vectors.

### Additional Gate/Probe Coverage (Passing)
- `zig build fmt`
- `cargo fmt --manifest-path tools/stwo-vector-gen/Cargo.toml`
- `cargo check --manifest-path tools/stwo-vector-gen/Cargo.toml`
- `python3 scripts/parity_fields.py --regenerate --skip-zig`
- `python3 scripts/parity_fields.py`
- `python3 scripts/e2e_examples.py`
- `zig build test --summary all`

## Latest Slice (State-Machine Statement API Wiring)
- `src/examples/state_machine.zig`
  - Added statement API types for parity with upstream state-machine flow:
    - `Statement0`
    - `Statement1`
    - `PreparedStatement`
  - Added entrypoints:
    - `prepareStatement(log_n_rows, initial_state, elements)`
    - `verifyStatement(statement, elements)`
  - `verifyStatement` returns `StatementNotSatisfied` on equation failure.
  - Added roundtrip tests for:
    - prepare/verify success path
    - failure-path via perturbed claimed sum.
- `src/core/fields/parity_vectors.zig`
  - Updated state-machine statement parity test to exercise new API directly:
    - validates `prepareStatement` output fields and claims.
    - validates `verifyStatement` success and expected rejection path.

### Additional Gate/Probe Coverage (Passing)
- `zig build fmt`
- `cargo check --manifest-path tools/stwo-vector-gen/Cargo.toml`
- `python3 scripts/parity_fields.py`
- `python3 scripts/e2e_examples.py`
- `zig build test --summary all`

## Latest Slice (State-Machine Statement Equation Parity)
- `src/examples/state_machine.zig`
  - Added statement validator:
    - `claimsSatisfyStatement(initial, final, x_claim, y_claim, elements)`
  - Added regression test for the upstream public statement equation.
- `tools/stwo-vector-gen/src/main.rs`
  - Extended vector schema with:
    - `example_state_machine_statement`
  - Added deterministic vectors for:
    - `log_n_rows`, `initial_state`
    - lookup elements (`z`, `alpha`)
    - `intermediate_state`, `final_state`
    - `x_axis_claimed_sum`, `y_axis_claimed_sum`
  - Uses non-degenerate samples only (skips zero-denominator combinations).
- `src/core/fields/parity_vectors.zig`
  - Added parser schema and parity test for `example_state_machine_statement`.
  - Test validates:
    - transition-state formulas
    - x/y telescoping claim derivations
    - statement equation satisfaction
  - Added negative differential case:
    - perturbed `y_axis_claimed_sum` must violate the statement.
- `vectors/fields.json`
  - Regenerated deterministically with statement vectors.

### Additional Gate/Probe Coverage (Passing)
- `zig build fmt`
- `cargo fmt --manifest-path tools/stwo-vector-gen/Cargo.toml`
- `cargo check --manifest-path tools/stwo-vector-gen/Cargo.toml`
- `python3 scripts/parity_fields.py --regenerate --skip-zig`
- `python3 scripts/parity_fields.py`
- `python3 scripts/e2e_examples.py`
- `zig build test --summary all`
