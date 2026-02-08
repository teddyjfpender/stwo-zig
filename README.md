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
zig build bench-smoke
zig build bench-strict
zig build profile-smoke
```

`zig build interop` performs true Rust<->Zig proof exchange for `xor` and `state_machine`
(`proof_exchange_json_wire_v1`) and includes semantic statement-tamper plus
proof-byte tamper rejection checks. It uses
Rust toolchain `nightly-2025-07-14` (pinned by upstream at `a8fcf4bd...`).

`zig build bench-smoke` now runs a matched Rust-vs-Zig workload matrix over release
interop binaries, records raw prove/verify timing samples, RSS, proof-size/decommit
shape metrics, and enforces `<= 1.50x` Zig-over-Rust latency threshold by default on
the base workload tier.

`zig build bench-strict` runs the same protocol with `--include-medium` enabled and is
the benchmark requirement for release signoff.

`zig build profile-smoke` now runs deep proving workloads with `time -l` metrics and
`sample`-based hotspot attribution, and emits mitigation hints in the profile report.

### Deterministic release sequence

```bash
zig build release-gate
zig build release-gate-strict
```

`zig build release-gate` is the fast/base CI gate.
`zig build release-gate-strict` is the required release-signoff gate.

## Layout

- `src/core/fields/m31.zig` — M31 field
- `src/core/circle.zig` — Circle group points + group law
- `src/core/vcs/merkle.zig` — Merkle tree + inclusion proofs
- `src/core/channel/transcript.zig` — Fiat–Shamir transcript
- `src/core/proof_of_work.zig` — PoW helper

## License

Apache-2.0 (mirrors upstream Stwo).
