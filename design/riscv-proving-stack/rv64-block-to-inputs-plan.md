# Plan: block in → all segment inputs ready in < 0.3 s (CPU side, GKR route)

Status: plan, 2026-11-03. Owner track: CPU-side, parallel to the GPU proving work (#314).
Builds on `rv64-fast-execution.md` (fast first pass, checkpoints), `rv64-minimal-trace-design.md`
(ZisK-style minimal trace) and `rv64-gpu-2s-block-plan.md` (tracks C1, C2, G4).

## 1. Where the time goes today (block 24,628,607, 26.89 M steps, 7 segments)

Measured on main `89f607a22` (M4 Max, 14 cores, AC power; complete-block run `fbmain` and a
`nativeprepare` run; shares from `/usr/bin/sample`).

| # | Stage | Wall | Serial? | Notes |
|---|---|---:|---|---|
| A | `nativeprepare` (separate process) | 4.13 s | publisher serial | traced reference walk ≈1.3 s (≈20 MHz); legacy Poseidon frontier graph + sparse root ≈1.3 s (not used by the GKR route); packet SHA-256 + write + fsync ≈0.9 s; 1.69 GB written |
| B | image + program init | 0.16 s | yes | |
| C | packet import + capture + ordered ledger | 1.80 s | 2-wide cap; ledger serial | re-hashes packets (≈0.6 s); capture 43 ns/step; global RAM/service ledger 0.38 s serial (14 ns/step) |
| D | setup | 6.97 s | serial in the chain | `FixedSet.init` ≈4.1 s + `Keys.initPolicy` ≈2.8 s; **block-independent**; each key is committed twice (production suite, then candidate rate) |
| E | witness sources inside prove | 10.9 s summed (≈5.4 s critical path) | 2 lanes | ≈400 ns/step core (CPU sources), ≈620 ns/step including truth sources |

Serial chain before the first commit: **≈13.0 s**, plus witness building inside the 75 s prove.
The fresh verifier pays the same setup again (7.25 s).

## 2. Target, made precise

"Inputs ready" means **compact per-segment inputs**: the record stream from which the prover (CPU
today, GPU via track G4) builds MAIN. Full MAIN is ≈400 B/step (≈39 GB for an average block,
more than host RAM), so it is streamed per segment and never materialised for the whole block.

| Metric | Today | Target |
|---|---:|---:|
| T_first: block in → segment 0 inputs ready | ≈13 s | **≤ 30 ms** |
| T_all, 24,628,607 (26.9 M steps) | ≈13 s | **≤ 0.3 s** |
| T_all, average basket block (97 M steps) | ≈25 s (est.) | ≤ 0.5 s with the interpreter; **≤ 0.3 s needs a 0.6–1 GHz executor (phase 6)** |
| Setup per block | 6.97 s | ≈0 resident, ≤ 0.25 s cold load |
| Basket coverage | 8 / 15 blocks (4 MiB input cap) | 15 / 15 |

T_first matters most: proving overlaps everything after segment 0.

## 3. Phases

Every phase is gated by **byte-identical proofs** against main for the 4-packet prefix and the
complete block of 24,628,607 (`vectors/reports/rv64-gkr-memory-20261102/run.sh`), plus a fresh
receiver accepting, plus the existing local suites (truth-gkr, services-gkr-local,
keccak-throughput, word16-v3-services, word16-combined-services). Statement and AIR do not change
unless a phase says so.

| Phase | Work | Saves (24,628,607) | Effort | Proof bytes |
|---|---|---:|---|---|
| **P0 Harness** | One `block-to-inputs` timer (T_first, T_all, per stage) in the GKR producer; basket runner over `basket.json`; receipts under `vectors/reports/`. | — | 1–2 days | none |
| **P1 Setup cache** | Make setup a pure function cached by (ELF hash, geometry rung, suite): resident in a long-lived prover, loaded from disk otherwise, skipping the re-hash of 266.8 M coefficient cells on acquire. Precompute the basket's union of rungs (est. 1–3 GB). Investigate removing the first (production-suite) key commit: the statement binds only the fixed identity/root (`fixed_authority.zig:62-73`). Same cache for the verifier. | 6.97 s → ≈0 / ≤0.25 s | 3–5 days | none (removing the double commit must leave identity/root unchanged; prove it with byte identity) |
| **P2 In-process direct capture on GKR** | Wire `direct.zig` (`captureWithSegments`, `Packet.fromNative`) and `--segment-workers` into `gkr_main`. Delete packets, SHA-256, fsync, the Poseidon frontier graph and the terminal RAM proof from this route (they carry no authority here, `packet.zig:1-3`). Lift the 2-wide capture cap. | A + C: 5.9 s → ≈1–1.5 s | 1 week | none |
| **P3 Minimal trace + parallel replay** | Fast engine emits the thin log of `rv64-minimal-trace-design.md` (chunk headers every 2^18 steps + one before-word per LS + service before-states, ≈2.8 B/step). Workers replay chunks in parallel, overlapped with execution. Global RAM ledger becomes per-segment local passes + a serial merge over first-touch cells. BINARY/ALU/SHIFT dedup becomes per-chunk maps merged in chunk order, keeping first-occurrence order, so bytes stay identical. Service call-id prefix sums from per-segment counts. | ≈1–1.5 s → ≈0.15 s | 3–4 weeks | none, if regenerated advice is bit-identical (the gate) |
| **P4 Input cap** | Raise the 4 MiB expected-image cap (`expected_image.zig:24`) in producer and receiver; inputs stay pinned by SHA-256. | 7 basket blocks become provable | 1–2 days | none for existing blocks |
| **P5 Record spec for the GPU (C2)** | Freeze the per-segment compact record format the GPU expands (G4; LS-D64 expansion already measured at ≈5 ps/cell on a 5090). Keep a CPU reference expander for parity. In parallel, cut CPU source cost (400–620 ns/step) for the CPU-only path. | moves 10.9 s of source building off the CPU | 1–2 weeks (spec), with the GPU team | none |
| **P6 Faster executor** | Direct page paths for bulk memory and services first (the engine is ≈57% of samples on the largest block), then an AOT RV64→host translator only if the average block still misses 0.3 s. A second instruction semantics must be differentially tested against the reference interpreter on the whole basket. | average block 0.31 s → 0.1–0.16 s | 2 weeks; AOT 4–6 weeks | none (the proof checks the input) |

Order: P0 → P1 and P2 in parallel → P4 → P3 → P5 (with the GPU team) → P6.
P1 + P2 alone take block 24,628,607 from ≈13 s to ≈1.5 s; P3 reaches the 0.3 s target for it.

## 4. What is generic (ZisK-style) and what is ours

- **Generic, copy the pattern:** serial work = execution plus a thin log; chunk headers plus a
  memory-read log; parallel chunk replay overlapped with execution; witness built where the prover
  runs (the GPU).
- **Ours to design:** global RAM epochs/ticks/rights and INIT/TEARDOWN cells (a merge over
  per-segment boundaries); first-occurrence dedup order; service sidecars and call-id prefix sums;
  the Word16 MAIN projection; the 4 MiB cap; setup caching and the double key commit.

## 5. Risks

- **Byte identity in P3.** Reordering any fact or ledger entry changes proof bytes. The merge
  rules above preserve order; if one cannot, a sorted order is sound but needs a fresh receiver
  and new receipts.
- **Verifier-side setup cache** is a trust decision: the cache must be keyed and integrity-checked
  so a stale or tampered key cannot be accepted.
- **Memory.** Compact sources are ≈92 B/step today (≈8.9 GB for an average block); P3's records
  are ≈2.8 B/step, but the replay working set must stay bounded per segment.
- **Average-block execution** needs phase 6; the interpreter alone gives ≈0.31 s at 316 MHz.
