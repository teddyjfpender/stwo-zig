---
title: Metal BLAKE3 software product proof matches CPU bytes and both independent verifiers
author: Teddy Pender
created_utc: 2026-09-22T12:12:53Z
---

# Ordinary BLAKE3 Metal product proof — 2026-09-22

The Metal product builds with explicit BLAKE3 suite selection and the current
authenticated core AOT bundle. The ordinary SHA-256/128-byte CSP guest (14,056
cycles) passes prove, fresh-process verify, and one-sample/no-warmup benchmark
commands at secure parameters (70 queries / 26 PoW bits). The retained JSON
artifact is v5, prove report riscv_prove_v2, benchmark riscv_proof_v4, and fresh
receipts riscv_verify_v2 with typed BLAKE3 transcripts.

The proof bytes and completed transcript are byte-identical to the prior CPU
product proof for this input. Both CPU and Metal CLI verifiers accept the Metal
artifact, and both reject explicit blake2s selection with ProofSuiteMismatch.
Resident polynomial telemetry reports 16 eligible base components, 13 eligible
lookup components, one batch dispatch for each class, zero declines, one verified
sample with dispatch. Runtime admission uses the product-bound manifest, with no
source-JIT fallback.

Single diagnostic prove command: proving 0.366627334 s, in-process verification
0.0976185 s. These development products carry dirty-source identities and are
not an admitted clean full-suite cohort. This is not a repeated speedup study.
The separate benchmark report is retained with its own one-sample timing; do not
substitute either number for the full suite or ECDSA result.

Build command:

```
python3 scripts/zig_serial_build.py --cwd . stwo-riscv-metal -Dmetal-core-aot-bundle=/tmp/stwo-blake3-core-aot-20260922 -Doptimize=ReleaseFast --summary all
```

Build passes 2/2 steps, 1 minute / 5 GiB maximum RSS. An initial incorrect target
name stwo-zig-riscv-metal was rejected before this command. CLI commands use
`--proof-suite blake3` before prove/verify/bench. Logs and retained proof/receipts
are included. The earlier tamper rejection was CPU product qualification; this
turn additionally establishes cross-backend parity and verification.

Runner reporting now records the requested proof_suite at top level and rejects
any measurement row whose protocol omits or disagrees with it. Seventy-three
focused Python tests pass, including mixed/missing cohort suite cases.

Next: establish source-pinned clean benchmark products and run the full canonical
CPU/Metal BLAKE3 matrix. Legacy guest-profile publication, captured work receipts,
remaining prover-owned Poseidon identities and production recursion remain
incomplete. No completion/default-promotion claim is made.
