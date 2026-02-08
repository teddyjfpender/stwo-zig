# stwo-zig

`stwo-zig` is a parity-driven Zig port of StarkWare's Rust `stwo` stack.
The compatibility target is pinned in `/Users/theodorepender/Coding/stwo-zig/UPSTREAM.md` (`a8fcf4bdde3778ae72f1e6cfe61a38e2911648d2`).

## Equivalence Status (Formal)

At current `HEAD`, conformance evidence demonstrates:

- Bidirectional proof roundtrip parity on the pinned upstream commit:
  - Rust-generated proofs verify in Zig.
  - Zig-generated proofs verify in Rust.
  - Interop report: `/Users/theodorepender/Coding/stwo-zig/vectors/reports/latest_e2e_interop_report.json`
    (`status=ok`, `12/12` cases, `48/48` tamper rejections).
- Deterministic checkpoint parity:
  - `prove` and `prove_ex` proof bytes are equal for each checkpoint case.
  - Checkpoint report: `/Users/theodorepender/Coding/stwo-zig/vectors/reports/latest_prove_checkpoints_report.json`
    (`status=ok`, `12` cases).
- Exchange contract:
  - Interop uses `proof_exchange_json_wire_v1` JSON-wire artifacts.
  - Guaranteed by gate: schema/semantic compatibility and bidirectional verification.
  - Current observed state on committed interop artifacts: Rust and Zig `proof_bytes_hex` are byte-identical for the gated example matrix.

Equivalence scope is the pinned commit + gated matrices and fixtures; it is not an unbounded claim over arbitrary future parameters or upstream revisions.

## Scope

This repository includes prover/verifier plumbing, cross-language proof exchange,
parity vectors, checkpoint harnesses, and strict conformance gates.
Interop/checkpoint example set: `blake`, `poseidon`, `plonk`, `state_machine`, `wide_fibonacci`, `xor`.

## Requirements

- Zig 0.15.x
- Python 3
- Rust nightly `nightly-2025-07-14` (for Rust-side parity and interop tools)

## Core Commands

```bash
zig build test
zig build fmt
zig build api-parity
zig build upstream-surface
zig build vectors
zig build interop
zig build prove-checkpoints
zig build bench-smoke
zig build bench-strict
zig build bench-opt
zig build bench-contrast
zig build bench-full
zig build bench-pages
zig build bench-pages-validate
zig build profile-smoke
zig build profile-opt
zig build profile-contrast
zig build opt-gate
zig build deep-gate
zig build roadmap-baseline
zig build roadmap-audit
zig build std-shims-smoke
zig build std-shims-behavior
zig build release-evidence
```

## Release Gates

```bash
zig build release-gate
zig build release-gate-strict
```

- `release-gate`: fast/base confidence path.
- `release-gate-strict`: release-signoff path.
- `roadmap-audit`: section-15 closure gate; must pass with all roadmap crate rows marked `Complete`.

Strict sequence:
`fmt -> test -> api-parity -> deep-gate -> vectors -> interop -> prove-checkpoints -> bench-strict (warmups=3,repeats=11) -> profile-smoke -> std-shims-smoke -> std-shims-behavior -> release-evidence`

Full benchmark add-on:
`zig build bench-full` then `zig build bench-pages` / `zig build bench-pages-validate`.

Optimization track (non-authoritative for release conformance):
- `zig build bench-opt`
- `zig build bench-contrast` (adds large contrast workloads: `poseidon_large`, `blake_large`, `wide_fibonacci` fib(100/500/1000), and `plonk_large`)
- `zig build profile-opt`
- `zig build profile-contrast` (adds `wide_fibonacci` fib500 + `plonk_deep` hotspot capture)
- `zig build opt-gate` (runs baseline-compatible bench/profile plus comparator thresholds)
- Native-tuned measurements can also be compared manually via
  `python3 scripts/compare_optimization.py`.

## Reports

Primary machine-readable outputs are written under:
`/Users/theodorepender/Coding/stwo-zig/vectors/reports/`

Important artifacts:
- `e2e_interop_report.json`
- `prove_checkpoints_report.json`
- `benchmark_smoke_report.json`
- `benchmark_opt_report.json`
- `benchmark_contrast_report.json`
- `benchmark_full_report.json`
- `profile_smoke_report.json`
- `profile_opt_report.json`
- `std_shims_behavior_report.json`
- `release_evidence.json`
- `optimization_baseline.json`
- `optimization_compare_report.json`

## Conformance References

- `/Users/theodorepender/Coding/stwo-zig/CONFORMANCE.md`
- `/Users/theodorepender/Coding/stwo-zig/API_PARITY.md`
- `/Users/theodorepender/Coding/stwo-zig/handoff.md`

## License

Apache-2.0 (mirrors upstream Stwo licensing).
