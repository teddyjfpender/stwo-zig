# stwo-zig

`stwo-zig` is a parity-driven Zig port of StarkWare's Rust `stwo` stack.
The compatibility target is pinned in `/Users/theodorepender/Coding/stwo-zig/UPSTREAM.md` (`a8fcf4bdde3778ae72f1e6cfe61a38e2911648d2`).

## Scope

This repository includes prover/verifier plumbing, cross-language proof exchange,
parity vectors, checkpoint harnesses, and strict conformance gates.

## Requirements

- Zig 0.15.x
- Python 3
- Rust nightly `nightly-2025-07-14` (for Rust-side parity and interop tools)

## Core Commands

```bash
zig build test
zig build fmt
zig build api-parity
zig build vectors
zig build interop
zig build prove-checkpoints
zig build bench-smoke
zig build bench-strict
zig build bench-opt
zig build bench-full
zig build bench-pages
zig build bench-pages-validate
zig build profile-smoke
zig build profile-opt
zig build deep-gate
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

Strict sequence:
`fmt -> test -> api-parity -> deep-gate -> vectors -> interop -> prove-checkpoints -> bench-strict (warmups=3,repeats=11) -> profile-smoke -> std-shims-smoke -> std-shims-behavior -> release-evidence`

Full benchmark add-on:
`zig build bench-full` then `zig build bench-pages` / `zig build bench-pages-validate`.

Optimization track (non-authoritative for release conformance):
- `zig build bench-opt`
- `zig build profile-opt`
- Native-tuned measurements are compared against frozen baseline via
  `python3 scripts/compare_optimization.py`.

## Reports

Primary machine-readable outputs are written under:
`/Users/theodorepender/Coding/stwo-zig/vectors/reports/`

Important artifacts:
- `e2e_interop_report.json`
- `prove_checkpoints_report.json`
- `benchmark_smoke_report.json`
- `benchmark_opt_report.json`
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
