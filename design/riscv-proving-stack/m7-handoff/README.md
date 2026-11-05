# RV64 GPU prover: M7 handoff (2026-11-05)

M7 was planned and launched as a 10-stream workflow, then stopped about 15 minutes in so the owner can take over.
This folder holds everything needed to pick it up. No M7 stream committed code; the only code artifact is a WIP branch (see "Branch state").

| file | what it is |
|---|---|
| `README.md` | this document: where we are, what we learned, and what each M7 stream must do |
| `PROTOCOL-M7.md` | campaign rules: pod access, GPU and build locks, branches, receipts and progress ledger, acceptance, the M6 time sinks, M7 targets |
| `rv64-m7-workflow.js` | the exact workflow script, with all 10 stream prompts and 5 adversarial check prompts. Re-run it as is, or take the prompts one by one. |
| `M7-INTERFACES-snapshot.md` | the pod's `/workspace/m3/M7-INTERFACES.md` when work stopped: profiles' reserved profile names, corpus v5 case IDs and review protocol; outer-gkr's DW-R1 fix plan; native-witness's compact-record draft |

Labels: **[M]** measured (a receipt exists), **[D]** arithmetic on measured numbers, **[E]** estimate.

---

## 1. Where we are (PR branch `codex/rv64-cuda-ethereum` @ 26ca20793, M6 integrate)

**24628607**, warm resident service on 2×5090. Every timing is a single observation on a loaded pod.

| column | M3 | M4 | M5 | **M6 (default)** | M7 target |
|---|---:|---:|---:|---:|---:|
| request | 51.1 s | 28.5 s | 27.4 s | **18.2–19.2 s** | ≤ 8 s (stretch 6) |
| capture | 3.3 s | 2.8 s | 2.5 s | **2.07 s** | ≤ 1.0 s (stretch 0.6) |
| setup (warm / cold first request) | 12.6 s | 0.15 s | 0.15 s | **0.15 / 8.6–10.7 s** | ≤ 0.5 / ≤ 3 s |
| native | 7.8 s | 5.9 s | 6.1–6.4 s | **4.45 s** | ≤ 2 s |
| recursion (harness stage) | 27.3 s | 19.5 s | 18.2 s | **11.35 s** | ≤ 4 s |
| tail after the last leaf | — | — | ~4.6 s | **2.15 s** | ≤ 2 s |
| root-only verify | (full tree 77 s) | 61 s | 13.7 s | **1.41 s** | ≤ 1 s |
| derive-vk-tables (once) | — | — | 45.2 s | **28.3 s** | ≤ 20 s |
| final proof | 708 KB | 706 KB | 706 KB | **708.7 KB** | ≤ 120 KB (stretch 100) |
| service RSS | 25 GiB | 27.5 GiB | 32.8 GiB | **33.5 GiB** | ≤ 20 GiB |
| device peak | — | 31.5 GB | 31.5 GB | **31.5 GB** (27.8 GB with the 22G arena, +0.9 s) | ≤ 28 GB |
| recursion nodes | 33 | 33 | 33 | **23** (4-ary folds) | ≤ 10 |
| recursion-window GPU kernel busy | — | 38% | 39.8% | **41.6%** | ≥ 70% |
| launches / syncs per request | — | 223k / 57.8k | 223k / 10.7k | **82.4k / 6.8k** | — |

- 26235156: 13.2 s (M3 34.3 s).
- Scale probe 24697070: 73.5 s one-shot cold (M3 86.4 s).
- Default format since M6: `m6_outer_diet_k4_cap3_r1_b2_q108_p20_fold4_v1` (4-ary folds, fold Merkle cap 3). It is set in `scripts/rv64_m3_pod.py DEFAULT_PRODUCER_ENV`.
- Receipts: `vectors/reports/rv64-m{3,4,5,6}-2026110{4,5}/` and `vectors/reports/progress/PROGRESS.md`.
- Gate tooling: `vectors/reports/rv64-m6-20261105/integrate/gate.sh`.

---

## 2. What the data taught us (read this before designing anything)

1. **Each milestone so far switched on less than it built.**
   - M5 built the outer GKR section, fused Blake2s, native GKR v1, the chi chain and root-only verify, but request time barely moved.
   - In M6, outer GKR and native GKR were still not switched on.
   - **Rule:** a stream is done only when its change runs in the production prover/receiver on both dev blocks, measured end to end. Reference or model numbers do not count.
2. **Recursion is bound by host latency, not by GPU work.**
   - M6's 4-ary folds plus caps cut recursion cells ×0.69 and GPU time 23–34%, yet the wall moved by only 0.3–5 s.
   - The wall is set by host prep per leaf, 1.6–2.1 s each, because leaves still build the verifier graph and the host DAG plan. The first wave costs about 1.5 s before any device work starts.
   - The leaf's device DAG has about 146k dependency levels, 101k of them Blake-G levels of mean width 26, at about 0.77 µs per level (113 ms). It is limited by serial depth, not by launches.
   - The fold seed tape works: fold host prep dropped 0.39 → 0.027 s. Cold fold classes, including the root fold, still cost 1–2.7 s.
3. **GPUs idle during recursion: 41.6% busy.**
   - Each node still has 123.5 blocking calls and 1,774 launches.
   - Device transcript and CUDA graphs were never built.
   - `RECURSION_LANES_PER_DEVICE=2` fails because it needs per-lane trace-commit and composition contexts.
4. **Native: 4.45 s, against GPU kernel busy of only 1.5–2.4 s per GPU.**
   - Owner-thread idle is 1.1–2.0 s per GPU: callbacks run synchronously on one owner thread.
   - H2D is 213–223 B per instruction; the largest item is the 56 B/row CPU metadata.
   - GPU witness widening was not built.
5. **Native GKR: the measured potential is large, but it is not in production.**
   - The census reconciles exactly with measured cells. Native INTER is 1,854 M cells on 607, which is 7.8k bits/gas (15.6k LDE). ZisK is at 28.3k LDE, so we are already 1.8× below it.
   - v2-gkr on the strict classes [D]: INTER 2,270.7 → 1,124.2 M; Keccak truth 742.8 → 110.4 M.
   - `v2-strict` (opt-in, accepted, corpus-clean) is **slower** today: +16–22% cells from rung padding (610 M on 607; terminal alone +220 M). It is **not total**: there is no `cpu_single` rung, and `cpu_last` only covers cpu_log 20–22.
   - The CUDA cap of 64 GKR instances must become 128, because strict CPU classes reach 68. A WIP patch exists (see "Branch state").
   - The mass gate must use source-bound masses: the conservative 128 × 2^28 = 2^35 is ≥ p.
6. **Outer GKR is not wired.**
   - Review item DW-R1 was reopened: the eq column E is unconstrained.
   - The fix plan is in `M7-INTERFACES-snapshot.md` §outer-gkr OG1. Use the reviewed native construction (`services/gkr_local/binding.zig emitFor`): E endpoints, recurrence `E − E_next2·carry`, and a cyclic prefix.
   - first/second/carry are derived by the verifier with the existing succinct O(log² N) evaluator `logup_gkr/mle_point.zig evalAnchorsFor / evalCarryQuotientFor`, over OM31 natively and over the circuit lane field in-circuit. Every z_row coordinate must be ≠ 0, 1.
   - Expected interaction width: 304 → about 128 base columns [D]. That should also cure the q51-profile OOM (the 304-column interaction LDE needed 23.7 GB).
   - The GPU GKR needs fused projection; unfused it needs 26.9 GB.
7. **Fused Blake2s:** with 3 power-of-two instances per node it is a net loss (×1.51 at q108). Use **one instance per node**: ×0.93 / ×0.76 at q108 / q51.
8. **Canonical VK costs time.** A uniform fold VK adds +10–23% recursion; set-v2 adds +4% and is the preferred canonical shape.
9. **Capture: 2.07 s.** The critical path is:
   - image/program init 0.5 s (cache it per image);
   - batch-0 admission plus CPU capture about 0.45 s;
   - the serial ledger about 0.5 s (shard 0 is 225 ms: sponge 97, bulk 86, first touch 68, LS 39 ms);
   - finish 0.05 s.

   The emulator is no longer the bottleneck: the fast path runs at 45 ns/step and 15 MIPS per worker. AOT pays off only after the ledger and init are fixed.
10. **Service:**
    - The first request per block pays 8.6–10.7 s of cold setup (`--store none`).
    - RSS has an 18–20 GiB floor between requests. canon-vk's class-PP retention caused +5.4 GiB.
    - Native retention is all-or-nothing per device: with more than 4 CPU segments per GPU it replays everything, so large blocks lose native-stream's gain.
11. **Measurement hygiene.**
    - The pod is shared, and the 1-minute load was 5–40 throughout, so most numbers are single observations.
    - sched's −6 s headline turned out to be −2.1 s: the control run had slowed down under load.
    - Always run paired A/B in the same session and record the load. `ncu` cannot run in the container (no access to performance counters).

---

## 3. M7 streams: what to do and what to focus on

Each stream has its own branch, `codex/rv64-m7-<stream>`, cut from 26ca20793 (worktrees `~/Coding/ge-wt/rv64-m7-<stream>`).
The full prompts are in `rv64-m7-workflow.js`. Expected effect on 24628607 is an estimate unless labelled.

| # | stream | proof change? | focus | gate | expected effect [E] |
|---|---|---|---|---|---|
| 1 | **leaf-tape** | no (byte-identical to M6) | Leaf seed tape built from the converted native capture plus class templates, so leaves build no host graph. Break the serial depth: one wide kernel recomputes every Blake compression from tape-recorded inputs and chaining values, and the same for Merkle paths and FRI folds; the DAG keeps only genuinely dependent arithmetic (~11 fill kernels per node). Precompute cold fold-class templates, including the root fold. | host prep ≤ 0.1 s per node for leaves and folds; byte identity | recursion −4…−6 s (removes the 1.6–2.1 s per-leaf host wall) |
| 2 | **device-graph** | no | Fiat–Shamir on the device (fallback `cudaLaunchHostFunc`). One captured CUDA graph per class. Per-lane trace-commit and composition contexts, so 2 nodes run per GPU within the 22 GiB arena. Add a sync lint. | ≤ 10 blocking calls and ≤ 500 launches per node; GPU busy ≥ 70%; transcript parity | recursion ×0.6–0.7 |
| 3 | **outer-gkr** | yes (`m7_outer_gkr_*`) | Close DW-R1 first (plan above) and get profiles to re-review it. Then wire outer GKR into every leaf and fold, with GPU GKR using fused projection. Then fused Blake2s as one instance per node. Then retry q51 for folds and root. | cells per leaf ≤ 0.5 G; fresh receiver; `--audit`; GKR/Blake tamper corpus | recursion cells ×0.57 (M5 model), with time following once 1 and 2 land |
| 4 | **native-gkr** | yes (`m7_native_v2_gkr_b2_q108_p20_fold4`) | Raise the oracle cap to 128 (WIP exists). Run v2-gkr end to end: drop the classic global and truth columns; GKR roots carry the global claims; source-bound mass gate; Keccak fully under GKR. Make v2 total (`cpu_single`, finer `cpu_last`) and cut the rung padding tax. Make retention byte-budgeted per device. | faster than flat on both blocks; INTER ×0.5; fresh receiver; NG corpus | native −0.5…−1 s; leaf cells −6% |
| 5 | **native-witness** | no | Upload compact per-instruction records (≤ 16 B/row, NW2 draft) plus a per-image decode table once, and widen them on the device. Streaming commit. Native CUDA graphs. Remove the synchronous owner-thread callbacks. | native ≤ 2 s; H2D ≤ 80 B/instruction; byte identity | native 4.45 → ~2 s |
| 6 | **compress** | yes (`m7_compress_c1_*`, `m7_compress_c2_*`) | Two-stage, **pure Circle STARK, no SNARK**. C1 (b8_q36_p20 or b16_q27_p20) verifies exactly one root; C2 (b64_q18_p20_fold3 or b16_q27_p20_fold3) verifies exactly one C1. Merkle caps, multiproof dedup, pruned last FRI layer. A compressed-proof receiver with VK tables from a pinned commit. Overlap with the tail. | proof ≤ 120 KB; C2 tail ≤ 2.5 s (else ship it as an async compact proof); CP corpus | proof 709 → 100–120 KB |
| 7 | **fold-circuit** | yes (`m7_outer_fold_v3_*`) | Fold v3 in-circuit (T_rec membership, NS interval chain with the seg_lo range check, PCD self-VK, k-ary null slots and caps), so root-only becomes the acceptance path without `--audit`. Set-v2 canonical fold classes shared across blocks. Root-only ≤ 1 s, derive ≤ 20 s. | F3xx corpus; fresh root-only receiver accepts with stores deleted | verifier 1.41 → ≤ 1 s; removes cold fold-class cost |
| 8 | **capture** | no | Cache image/program init per image; make the ledger two-phase or parallel; deliver segment 0 to native earlier (1.2 s today). AOT emulator only if it lands on the critical path. | capture ≤ 1.0 s; captured-value sha unchanged | capture −1 s, mostly hidden by streaming |
| 9 | **service** | no | An install step that persists every per-image class artifact (native FIXED per strict class, recursion PP/plans/templates, VK tables). RSS ≤ 20 GiB (drop retained host copies; per-request arenas). The 22G arena with no time cost, on by default. | cold first request ≤ 3 s of setup; RSS; byte identity | first request −6…−8 s |
| 10 | **profiles** | registry and notes | Second reviewer of 3, 4, 6 and 7. PROFILES entries with conjectured-128 tests for every name in PR1. Corpus v5 (PR2 IDs). M8 prep: written analysis of D2 (native b4_q54_p20), bigger rungs and batched services, recursion arity 8, and a multilinear (WHIR/Basefold-style) recursion per plan §3.5 S-ML. | REOPEN blocks promotion | — |

Then **integrate**:
- **Merge order:** capture, profiles, service, native-witness, leaf-tape, device-graph (proof-neutral), then native-gkr, fold-circuit, outer-gkr, compress.
- **Gates:**
  - (a) the pipeline on the M6 default format, byte-identical to M6;
  - (b) the full M7 format, accepted by fresh root-only and compressed-proof receivers, with `--audit` agreeing and every corpus clean.
- Run both gates warm and on a cold first request, paired against M6 in the same session, then one scale probe on 24697070.
- **Ordering:**
  - Streams 1, 2 and 5 are the critical path for request time. They are proof-neutral, so they can merge independently.
  - Streams 3, 4 and 6 bring the big cell and proof-size cuts, but they only show up in time after 1 and 2 remove the host latency.

**Expected M7 result if everything lands** [E, plan model]: 24628607 at **6–8 s**, 26235156 at about 5–6 s, all 15 blocks at about 200–295 s in total (M3: 1,843 s). Given how earlier milestones slipped, a realistic band is about 1.5× that (24628607 at 9–12 s).

## 4. After M7: M8–M10 (owner directive)

Plan M8, M9 and M10 the same way: from M7's measured data plus the frontier lessons, with big architectural steps rather than greedy tweaks. The ordered scale-up (one block at a time, stop on the first failure) moves to after M10. Candidate levers from the data so far:
- a narrower Keccak AIR, or Keccak lookups streamed straight into GKR (the largest native item);
- sharing eq/prefix binding columns across components of one row log (about half of the native INTER cells left after v2-gkr);
- whole-request streaming (capture → native → leaves → folds → compress), so latency equals the slowest stage;
- wider and shallower recursion (arity 8, q51) once memory allows;
- per-program native key caching, for sub-second verification;
- key-affinity multi-GPU scheduling that scales close to linearly, 2 → 8 GPUs.

## 5. Branch state when work stopped

- `codex/rv64-cuda-ethereum` @ 26ca20793 (M6) plus this handoff commit.
- `codex/rv64-m7-native-gkr` @ 3d5ace6d7: **WIP, unbuilt, untested.** Raises `STWO_RV64_BATCH_MAX_ORACLES` to 128 and resizes the static asserts. Capacity only; it should be byte-identical. Build it on the pod and check byte identity against the M6 receipts before relying on it.
- The other `codex/rv64-m7-*` branches have no commits (they sit at 26ca20793).
- Pod: `/workspace` had about 37 GB free after pruning. Keep `runs/integrate` (M3 receipts), `runs/m4-integrate`, `build/m5-integrate`, `build/infra`, and the M6 integrate build and runs. Reviewer copies (`*-adv`) are the main disk consumers; delete them when done.
- Standing rules: no basket loops (develop on 26235156 and 24628607 only); proof-format changes need named profiles, a written argument, fresh-receiver acceptance and the corpus; benchmark data in every performance commit; OP Stack P3 and compression are pure STARK, no SNARK wrap.
