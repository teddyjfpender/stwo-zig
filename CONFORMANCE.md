# CONFORMANCE.md

## 1. Purpose

This document is a binding conformance contract for delivering a production-grade Zig port of Rust Stwo with strict parity, predictable velocity, and zero scope drift.

It has two equal goals:
1. Delivery formalities: exact quality, correctness, and interoperability gates.
2. Delivery velocity: enforceable process constraints that prevent endless refactors and non-goal work.

## 2. Normative Terms

The words `MUST`, `MUST NOT`, `REQUIRED`, `SHOULD`, and `MAY` are normative.

Any item marked `MUST` is a release blocker.

## 3. Source of Truth and Scope Lock

1. Rust upstream is the canonical behavior and API source of truth.
2. The pinned upstream commit in `UPSTREAM.md` is the legal compatibility target for each delivery slice.
3. Zig behavior that differs from the pinned Rust behavior is non-conformant unless approved as an explicit, documented divergence.
4. Scope is limited to achieving end-to-end proof generation, verification, and benchmark comparability against Rust Stwo.
5. Work that does not improve parity, correctness, or benchmark fidelity MUST NOT be prioritized.

## 4. Conformance Modes

### 4.1 Implementation Conformance

1. Zig implementations MUST preserve Rust semantics for:
   - field arithmetic and canonical representation
   - transcript and challenge sampling order
   - Merkle/VCS behavior and witness interpretation
   - FRI and PCS verifier/prover math and query handling
   - proof object semantics and wire encoding

2. Unsafe optimization, algorithmic substitutions, or policy differences MUST NOT alter externally observable behavior.

### 4.2 API Conformance

1. Public Zig APIs MUST map 1:1 to the intended Rust Stwo API surface for the pinned commit.
2. Every exported Zig symbol MUST have a Rust parity mapping or a documented compatibility rationale in `API_PARITY.md`.
3. Public API additions without parity rationale are prohibited.

### 4.3 Proof Interoperability Conformance

1. Rust-generated proofs for the pinned commit MUST verify in Zig.
2. Zig-generated proofs MUST verify in Rust for the same commit and parameter set.
3. Any incompatibility is a release blocker unless explicitly scoped as temporary and approved in writing.

## 5. Hard Delivery Gates

All gates are mandatory for production readiness.

| Gate | Requirement | Evidence Artifact |
|---|---|---|
| G1 | Upstream pin recorded and immutable for the sprint | `UPSTREAM.md` |
| G2 | Unit + property + law tests for modified modules | test files under `src/**` |
| G3 | Differential parity vectors updated and passing | `vectors/fields.json`, parity test modules |
| G4 | Verifier parity against Rust for supported modules | parity tests and vector coverage manifest |
| G5 | Prover parity against Rust for supported modules | parity tests and vector coverage manifest |
| G6 | Proof serialization/deserialization compatibility | compatibility fixtures and roundtrip tests |
| G7 | Rust->Zig and Zig->Rust e2e proof verification | e2e compatibility report |
| G8 | Benchmark harness comparability | benchmark config + raw metrics |
| G9 | Profiling and hotspot attribution | profiling report and flamegraphs |
| G10 | Documentation and divergence log current | `README.md`, `UPSTREAM.md`, `API_PARITY.md`, `handoff.md`, this file |

## 6. TDD and Test Formalities

1. Every bug fix MUST start with a failing regression test.
2. Every feature MUST include:
   - success-path test
   - edge-case test
   - failure-path test
3. Reusable abstractions MUST include law/property tests where feasible.
4. Randomized tests MUST use explicit deterministic seeds.
5. Tests MUST NOT depend on network access or system time without explicit injection.
6. A change that modifies logic without adding or updating relevant tests is non-conformant.

## 7. Parity Harness Formalities

1. Rust vector generation and Zig consumption schemas MUST be version-locked.
2. Vector files MUST include:
   - upstream commit id
   - seed strategy
   - sample counts
   - schema version
3. Parity coverage MUST include:
   - primitives: M31/CM31/QM31, FFT, circle ops
   - cryptographic hashes and Merkle logic
   - FRI fold/decommit paths
   - PCS quotient and query paths
   - verifier acceptance/rejection cases
   - prover witness construction and decommit paths
4. Every new parity slice MUST include at least one negative differential case.

## 8. Full E2E Conformance Criteria

Production conformance for this port is reached only when all items below pass:

1. Zig can generate full Stwo proofs for target examples/workloads.
2. Zig can verify Rust proofs for same pinned commit and params.
3. Rust can verify Zig proofs for same pinned commit and params.
4. Proof bytes are either:
   - wire-identical, or
   - schema-compatible with documented canonical transforms.
5. End-to-end benchmark harness compares identical workloads and parameters.

## 9. Benchmark and Profiling Formalities

### 9.1 Benchmark Protocol

1. Rust and Zig MUST run on identical hardware, CPU governor, and thread count.
2. Workloads, blowup factors, queries, and security settings MUST be identical.
3. Each benchmark MUST report:
   - prove latency
   - verify latency
   - throughput
   - peak RSS
   - allocation count and bytes
4. Results MUST include warmup and repeated runs with statistical summary.
5. Raw benchmark data MUST be preserved in machine-readable format.
6. A full benchmark parity track MUST cover the upstream 11-family surface (`bit_rev`, `eval_at_point`, `barycentric_eval_at_point`, `eval_at_point_by_folding`, `fft`, `field`, `fri`, `lookups`, `merkle`, `prefix_sum`, `pcs`) and publish static chart artifacts from committed data.

### 9.2 Performance Acceptance

1. Initial production target: Zig prove and verify within `<= 1.50x` Rust baseline.
2. Optimized target: Zig prove and verify within `<= 1.20x` Rust baseline.
3. Any regression over `5%` on critical benchmarks blocks merge unless approved with a mitigation plan.

### 9.3 Profiling Requirements

1. Each major milestone MUST include a profiling report.
2. Reports MUST identify top hotspots and show before/after when optimizations are claimed.
3. Optimizations without measurement evidence are non-conformant.
4. Optimization-track claims MUST include a baseline comparator report (`optimization_compare_report.json`) with explicit regression tolerances and settings-hash match.

## 10. Velocity and Scope-Divergence Controls

1. Work is executed in short, parity-scoped milestones with explicit entry/exit criteria.
2. A task is complete only when code, tests, vectors, and docs are all updated.
3. New abstractions MUST NOT be introduced without parity need and measurable benefit.
4. Refactors that do not improve parity, safety, or measured performance MUST be deferred.
5. Each sprint MUST publish:
   - committed parity scope
   - blocked items
   - variance against plan
   - next smallest shippable parity slice
6. Open-ended architecture work without linked gate impact is prohibited.

## 11. Change-Control Process

1. Any intentional divergence from Rust requires a written Divergence Record in `handoff.md` with:
   - rationale
   - risk
   - compatibility impact
   - rollback/closure plan
2. PRs that change public APIs MUST include parity mapping updates.
3. PRs that alter cryptographic semantics MUST include differential vectors and rejection tests.

## 12. CI Gate Order

CI MUST run in this order and fail fast:

1. format and static checks
2. unit tests
3. property/law tests
4. parity vector validation
5. interoperability tests
6. benchmark smoke and regression checks

No stage may be skipped for release branches.

## 13. Release Definition of Done

Release is conformant only if:

1. all hard gates in Section 5 are green
2. no unresolved high-severity divergence records exist
3. full e2e Rust<->Zig proof interoperability is demonstrated
4. benchmark and profiling reports are attached and signed off
5. documentation reflects actual behavior and current pinned upstream

## 14. Non-Conformance Handling

1. If any `MUST` gate fails, release status is automatically `NOT CONFORMANT`.
2. A remediation issue with owner and deadline MUST be created before new feature work.
3. Repeated non-conformance in the same area triggers scope freeze on that area until resolved.

## 15. Crate-by-Crate Remaining Roadmap (Rust -> Zig)

This section defines the remaining scope by upstream Rust crate and the required Zig delivery targets.

### 15.1 Roadmap Table

| Rust crate | Zig target area | Current status | Remaining required scope | Hard exit criteria |
|---|---|---|---|---|
| `crates/stwo` | `src/core/**`, `src/prover/**`, `src/tracing/**` | Complete | Delivered and evidence-gated: full prover pipeline (trace -> composition -> PCS/FRI -> proof), verifier parity paths, proof wire compatibility, transcript/channel compatibility, hash/VCS parity, and PoW/config parity. | Rust->Zig and Zig->Rust proof interoperability green for pinned commit; full module parity vectors and negative cases; no unresolved divergence records |
| `crates/constraint-framework` | `src/core/constraints.zig` plus dedicated constraint DSL/evaluator modules | Complete | Delivered and evidence-gated: quotient/evaluator edge semantics and broadened law/property coverage for expression rewrites used by prover paths. | Differential tests against Rust constraint outputs for fixed seeds/traces; all edge/failure tests green |
| `crates/air-utils` | `src/core/air/**` and supporting trace utilities | Complete | Delivered and evidence-gated: expanded trace helper surface plus deeper AIR composition plumbing in non-example prover paths. | Rust parity vectors for AIR utilities and composition checkpoints; full integration tests with proof generation and verification |
| `crates/air-utils-derive` | Zig compile-time generation layer (comptime helpers/macros equivalent) | Complete | Delivered and evidence-gated: derive-like helpers for upstream patterns beyond component adapters and lookup row helpers. | Compile-time generated outputs parity-tested against Rust expectations; no manual per-AIR boilerplate required beyond declared conformance limit |
| `crates/examples` | `src/examples/**` and e2e fixtures | Complete | Delivered and evidence-gated: deterministic bidirectional interop and tamper coverage for `xor`, `state_machine`, `wide_fibonacci`, `plonk`, `poseidon`, and `blake`. | Every selected Rust example has Zig equivalent and bidirectional verification with semantic tamper rejection |
| `crates/std-shims` | freestanding/minimal Zig verifier profile and build flags | Complete | Delivered and evidence-gated: behavior-parity coverage between standard verifier and freestanding profile across the checkpoint fixture matrix. | Freestanding verifier build passes conformance test matrix; behavior matches standard build for identical inputs |

### 15.2 Required Sequencing

Execution order is mandatory unless a written exception is approved:

Status at current pin: all six sequencing items are delivered and evidence-gated.

1. Finish `crates/stwo` proof-format and prover/verifier semantic parity for core path. (Delivered)
2. Close `crates/constraint-framework` parity gaps required by prover composition. (Delivered)
3. Close `crates/air-utils` parity gaps and integrate into e2e proof generation. (Delivered)
4. Implement `crates/air-utils-derive` Zig comptime equivalent where parity requires generation. (Delivered)
5. Port `crates/examples` and establish cross-language e2e proof fixtures. (Delivered)
6. Complete `crates/std-shims` freestanding verifier conformance. (Delivered)

### 15.3 Milestone Gates by Crate

Each crate milestone is complete only when all items below are satisfied:

1. API parity map is updated and reviewed.
2. Differential vectors are added/updated for changed semantics.
3. Unit, property/law, and failure-path tests are green.
4. Interoperability checks for affected proof paths are green.
5. Documentation (`README.md`, `UPSTREAM.md`, `handoff.md`, `CONFORMANCE.md`) is updated.

### 15.4 Out-of-Scope Until Conformance

The following remain explicitly out of scope until Sections 5 and 15 are green:

1. Non-parity refactors not tied to correctness or measured performance.
2. Feature additions not present in the pinned Rust commit.
3. Benchmark tuning without first achieving interoperability conformance.
