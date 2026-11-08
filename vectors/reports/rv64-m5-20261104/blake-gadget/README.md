# Stream blake-gadget, M5: `fused_blake2s_v1` (receipts)

Labels: **[M]** measured, with a receipt in this directory. **[D]** arithmetic on measured numbers (`scripts/blake_gadget/fused_census.py`). **[E]** estimate.

| file | what |
|---|---|
| `gpu-selftest-16M-histogram-review.log` | review re-run with the XOR table-row fix: same 16.7 M random rows, plus an entry-by-entry device-vs-host multiplicity histogram (4,096 rows + 16 padding rows): 0 mismatches. The pre-fix kernel fails this check with 185,164 mismatched entries |
| `gpu-selftest-16M.log` | `tests/cuda/rv64/fused_blake2s_selftest.cu` on an RTX 5090: 16,777,216 random compressions, the device checker, negative probes, fill timing |
| `zig-spec-tests-1M-and-gpu-dump.log` | spec tests with 1,048,576 random CPU rows; the GPU dump (4,096 rows, 13.6 M cells) equals the CPU fill |
| `zig-spec-and-corpus-tests.log` | 22/22 spec + negative corpus BG01–BG08 hooks |
| `24628607-fb-{check,shadow,off}-service.json` | resident-daemon receipts: flag `check`, flag `shadow`, and the flag-off control. Same build (`916685c9c`), M4 env, arena on, `--store none` because `/root` had 9 GB free |
| `24628607-fb-check-shadow-lines.log`, `24628607-fb-shadow-lines.log` | raw `FUSED_BLAKE2S_V1_SHADOW` lines, one per outer node |
| `24628607-fused-census-{k1,k2}-q{108,51}.json` | `scripts/blake_gadget/fused_census.py` output |
| `build.json` | pod build receipt (driver, receiver, CUDA image with `rv64/fused_blake2s.cu`) |

## Gadget results [M]

- **Completeness.** The gadget matches std `Blake2s256` and the RFC 7693 vectors (chained, 0–4,096 bytes). 1,048,576 random compressions on the CPU and 16,777,216 on the GPU all pass with **0 violations**. The XOR multiplicities balance exactly (rows × 704 / 320 / 320).
- **GPU fill equals CPU fill** cell for cell: 4,096 rows × 3,328 columns.
- **Soundness smoke.**
  - All 13,312 single-cell perturbations are rejected on the CPU.
  - 27 of 27 corruptions are caught by the device checker.
  - Corpus BG01–BG08 is green.
- **Fill kernel** (72 registers, no stack, column-major coalesced stores), median of 7 runs:

  | rows | with XOR-multiplicity atomics | fill only (write-bound) |
  |---:|---:|---:|
  | 2^16 | 1.24 ms (18.9 ns/compression) | 0.55 ms (8.35 ns, 1.59 TB/s) |
  | 2^18 | 4.78 ms | 2.34 ms |

## 24628607 with the flag on

**Correctness [M].**
- Proofs: every proof in all 5 requests is byte-identical to the M3 integrate receipt.
- Receiver: the fresh receiver accepted the `check` run (71.8 s, load 32).
- Gather: on all 33 nodes, every chunk with Blake shape was rebuilt into a hint-tape record. Each record reproduced all 80 G-gate outputs from the device values (`shape == valid`), giving **1,845,347 compressions**.
- Device check: re-evaluating every fused constraint, lookup and output found **0 violations**.
- XOR multiplicities: balanced exactly (rows × 1,344).

**Fused rows and fill cost [M].**
- Fused rows: 1,913,344 (1.91 M) across ≤ 3 instances per node, so fused padding is 3.5 % of rows on average per node. Today the `blake_g_gate` rows carry **35.0 %** padding (8,388,608 rows padded for ≤ 72,559 × 80).
- Fill: writing all 25.5 GB of fused trace (1.91 M rows × 3,328 × 4 B) plus multiplicities takes **41.3 ms of GPU time for the whole tree** (about 1.25 ms per node); building the tape (gather) takes 34.4 ms. Both are means over 33 nodes, from events in `shadow` mode.

**Cells [D]** (log sizes [M] × component widths). Committed interaction is 2× the facts widths, from the M4.0 reconciliation. The model reproduces M4.0's 53.39 G − 4.65 G PP = **48.74 G** main+interaction exactly.

| | instances / node | own cells (33 nodes) | own factor | tree incl. parent width, q108 (r1, today) | tree, q51 (m3) |
|---|---:|---:|---:|---:|---:|
| today | 1 | 48.74 G | 1 | 1 | 1 |
| fused v1 (k=1, built, `MAX_INSTANCES` = 3) | 3 | 23.84 G | ×0.489 | **×1.51** | ×0.97 |
| fused v1 (k=1), one power-of-two instance | 1 | 29.22 G | ×0.599 | ×0.93 | **×0.76** |
| fused k=2 (analytic), 3 instances | 3 | 25.06 G | ×0.514 | ×1.10 | ×0.79 |
| fused k=2 (analytic), 1 instance | 1 | 30.84 G | ×0.633 | **×0.82** | **×0.72** |

Per leaf, the own factor is ×0.50–0.54 for CPU leaves and ×0.415 for truth leaves; per fold it is ×0.47–0.71 (3 instances).

**Review correction (2026-11-04).** The first census counted the fused component's columns once per child. Each power-of-two instance is a separate component with its own committed columns, and a parent opens every column of every component at each query. With the 3 instances every node actually uses, a k=1 child carries 26,601 committed columns, not 8,937. The tree factors above are recomputed with `scripts/blake_gadget/fused_census.py --max-instances {3,1}` from the same shadow log. The earlier ×0.82 / ×0.65 (k=1) and ×0.70 / ×0.60 (k=2) figures were wrong. Files: `24628607-fused-census-{k1,k2}-q{108,51}.json` (3 instances, as logged) and `…-inst1.json` (one instance).

**Parent width is the catch.** A parent opens every committed column of every child component at every query: 8,937 columns per fused instance (k=1), against 418 today. At q108, one instance costs +508 M cells per verified child, and three instances cost +1.56 G [D, first order, DEEP rows and the parent's per-instance OODS evaluation of 640 constraints and 1,376 lookups excluded]. Under this model, the padding-saving 3-instance plan is a net loss at q108.

**Recommendation for M7** (it revises diet's): use **one instance per node**. The 3.5 % padding win does not pay for doubling or tripling the opened width. Ship v1 rows only with outer GKR (drops the 2×2,752 interaction columns) and q51, or use the k=2 layout. At q108 with k=1 and no GKR, the tree gain is ×0.93 at best.

**Recursion time with the flag on [M, not quotable].** These are single observations at load 24–32, against the protocol's quiet bar of 8.

| run | request 1 | request 2 | recursion 1 / 2 |
|---|---:|---:|---:|
| flag off (control) | 43.96 s | 28.65 s | 21.07 / 19.24 s |
| `shadow` | 44.97 s | 31.09 s | 21.58 / 21.45 s |
| `check` | 47.74 s | — | 22.65 s |

- `shadow` adds 0.83–1.0 s of host-synchronised shadow wall per request. That is diagnostic overhead (one sync per node plus allocations), not the fused prover.
- No fused proof is produced yet, so **the recursion-time win is not measured**. It needs the M7 proof-format wiring (see `M5-INTERFACES.md` §blake-gadget and the soundness note §8.4).
- [D] estimate, labelled as such, at today's 14.9 recursion kernel GPU-s per 48.74 G committed cells (revised for per-instance width):
  - with 3 instances, k=1: the own-cell reduction is worth about 7.6 GPU-s, against about 15.3 GPU-s of parent width at q108 (a net loss) or 7.2 GPU-s at q51;
  - with one instance, k=1: about 6.0 GPU-s against 5.0 GPU-s (q108) or 2.4 GPU-s (q51).
