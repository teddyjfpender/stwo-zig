---
title: Canonical CSP BLAKE3 regression: serial PoW explains 91 percent of measured delta
author: Teddy Pender
created_utc: 2026-09-22T09:32:41Z
---

# Canonical CSP BLAKE3 slowdown attribution

2026-09-22, ReleaseFast CPU, 16 proof workers, ECDSA precompile enabled in both
suites, canonical 70 queries/26 PoW bits, same input/ELF and 1,828 guest cycles.
The two proof/verification gates pass (7/7 build steps, 2/2 tests). Stage recording
is opt-in via STWO_CSP_PROFILE and uses the existing prover recorder.

| Stage | BLAKE2s seconds | BLAKE3 seconds |
|---|---:|---:|
| Total proving | 0.858626541 | 2.523295083 |
| PoW | 0.125382 | 1.640898 |
| Total less PoW | 0.733244541 | 0.882397083 |
| Three trace Merkle commits (sum) | 0.181790 | 0.250084 |
| Composition evaluation | 0.152065 | 0.153403 |

The PoW delta accounts for 91.04% of the total measured delta. This is stage
attribution from a single qualification per suite, not a statistical A/B verdict.
Total-less-PoW is a subtraction, not a second benchmark or canonical total.
The reference BLAKE3 channel grind searches serially; the production BLAKE2s
prover path uses its persistent worker pool and batched nonce hashing. Thus the
16-worker setting does not imply a 16-worker BLAKE3 PoW search. Hash suites produce
different transcripts/nonces, so equal difficulty does not mean equal candidate
counts. Fixed deterministic transcripts can reproduce the same search workload;
repetition alone does not randomize that workload.

Next: retain the exact BLAKE3 predicate and lowest-valid-nonce semantics while
moving its search onto the bounded prover pool; isolate candidate hashing before
adding SIMD, and remeasure canonical total plus stage times. Then investigate the
remaining commitment delta. No default promotion or speedup claim is justified.

Command:
```sh
STWO_CSP_PROFILE=1 STWO_CSP_FIXTURE_ROOT="$PWD/vectors/riscv_csp" python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-csp-ecdsa test-csp-ecdsa-guest-proof -Doptimize=ReleaseFast --summary all
```
