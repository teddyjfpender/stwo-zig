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

### Conformance gates (smoke)

```bash
zig build vectors
zig build interop
zig build bench-smoke
zig build profile-smoke
```

## Layout

- `src/core/fields/m31.zig` — M31 field
- `src/core/circle.zig` — Circle group points + group law
- `src/core/vcs/merkle.zig` — Merkle tree + inclusion proofs
- `src/core/channel/transcript.zig` — Fiat–Shamir transcript
- `src/core/proof_of_work.zig` — PoW helper

## License

Apache-2.0 (mirrors upstream Stwo).
