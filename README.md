# stwo-zig (milestone 0.1)

This repository is an **in-progress Zig port** of StarkWare's **S-two / Stwo** Circle-STARK framework.

This zip corresponds to a **"core primitives" milestone** focused on correctness and testability:

- **M31 finite field** (p = 2^31 - 1) arithmetic, with property tests
- **Circle group** operations over M31 (unit circle), including a verified generator of order 2^31
- **Merkle tree** commitments (hash = SHA-256 by default; build-time selection can be extended)
- **Fiat–Shamir transcript** (domain-separated, deterministic)
- **Proof-of-work helper** (toy PoW for transcript grinding tests)

> Note: This is **not yet** a complete prover/verifier.

## Requirements

- Zig **0.12.0+** recommended.

## Build & Test

```bash
zig build test
```

### Formatting gate

```bash
zig build fmt
```

### Conformance gates

```bash
zig build vectors
zig build interop
zig build prove-checkpoints
zig build bench-smoke
zig build bench-strict
zig build profile-smoke
zig build std-shims-smoke
zig build release-evidence
zig build deep-gate
```

`zig build interop` performs true Rust<->Zig proof exchange for `plonk`, `xor`,
`state_machine`, and `wide_fibonacci`
(`proof_exchange_json_wire_v1`) and includes semantic statement-tamper plus
proof-byte tamper rejection checks. It uses
Rust toolchain `nightly-2025-07-14` (pinned by upstream at `a8fcf4bd...`).

`zig build vectors` now validates both:
- `vectors/fields.json` via `scripts/parity_fields.py`
- `vectors/constraint_expr.json` via `scripts/parity_constraint_expr.py`
- `vectors/air_derive.json` via `scripts/parity_air_derive.py`

`zig build prove-checkpoints` runs deterministic `prove`/`prove_ex` checkpoint parity
for `plonk`, `xor`, `state_machine`, and `wide_fibonacci` across base and non-zero blowup
settings, and enforces
semantic tamper rejection plus invalid-`prove_mode` metadata rejection in both Zig and Rust
verifiers.

`zig build bench-smoke` now runs a matched Rust-vs-Zig workload matrix over release
interop binaries, records raw prove/verify timing samples, RSS, proof-size/decommit
shape metrics, and enforces `<= 1.50x` Zig-over-Rust latency threshold by default on
the base workload tier. The current release matrix uses deterministic
`state_machine` workloads for base/medium tiers.

`zig build bench-strict` runs the same protocol with `--include-medium` enabled and is
the benchmark requirement for release signoff.

`zig build profile-smoke` now runs deep proving workloads with `time -l` metrics and
`sample`-based hotspot attribution, and emits mitigation hints in the profile report.

`zig build std-shims-smoke` builds `src/std_shims/verifier_profile.zig` for
`wasm32-freestanding` to enforce freestanding verifier profile compile parity.

`zig build release-evidence` generates the canonical machine-readable release manifest:
`vectors/reports/release_evidence.json`.

`zig build deep-gate` runs expanded compile/test graph coverage (`refAllDeclsRecursive`
paths) to catch legacy modules outside the minimal default test path.

### Deterministic release sequence

```bash
zig build release-gate
zig build release-gate-strict
```

`zig build release-gate` is the fast/base CI gate.
`zig build release-gate-strict` is the required release-signoff gate.
The strict gate emits `vectors/reports/release_evidence.json` after profile checks.
It includes `deep-gate` and `prove-checkpoints` before benchmark/profile stages.

## Layout

- `src/core/fields/m31.zig` — M31 field
- `src/core/circle.zig` — Circle group points + group law
- `src/core/vcs/merkle.zig` — Merkle tree + inclusion proofs
- `src/core/channel/transcript.zig` — Fiat–Shamir transcript
- `src/core/proof_of_work.zig` — PoW helper

## License

Apache-2.0 (mirrors upstream Stwo).
