# V3 OM31/GKR route: per-phase profile and the gap to the classic route

Block 24,628,607, real 4-packet prefix (16,777,212 instructions, 4 CPU and 8
truth proofs), proved on the 14-core M4 Max host shared with other agents
(memguard; AC power). Source: `codex/rv64-ge-gkr-v3perf` (PR #310 head
5f06a9ea6 plus this branch). Scripts and logs: `~/Coding/ge-cache/gkrperf/`
(`gkr_phases.py RUN_DIR LOG`, `run_gkr.sh`).

Receipt files (per-run phase JSON, reports, artifact hashes, fresh receiver,
experiment diff): `vectors/reports/rv64-v3-gkr-perf-20261102/`.

**Summary.** On the same prefix, source and host the GKR route proves in
65.9 s (mean of 2) against 29.5 s classic: 2.2x, the same ratio as the
full-block receipts. The gap is the interaction side (+110 core-s: local GKR,
binding and OM31 interactions at blowup 4), the PCS back end at blowup 4 in
OM31 (+85), OM31 composition (+58) and MAIN commitment at blowup 4 (+36),
partly offset by P0 (-30). Compact CPU decode is now qualified and the GKR V3
default: -5.4% committed cells, -1.5% CPU, -3.8% wall (63.4 s). Moving to
blowup 2 with 436 queries inside the same proven unique-decoding model would
cut a further 12.3% wall / 19% CPU (54.4 s) at +32% proof bytes; it is
measured but not admitted pending a re-instantiated security review.

Time is reported two ways. **Core-seconds** are the sum of per-lane
`lane_user_seconds` over recorded leaf stages; they are stable across runs.
**Wall** depends on lane overlap and on the other jobs on the host; single runs
here vary by about ±5%. Neither run is a controlled speedup measurement.

## Telemetry added

The GKR route's stage recorder did not cover the two CPU-only phases that
replace classic interaction work, so the earlier `cost-per-cell.md` method
could not see them. This branch adds two observation-only stage scopes:
`source_construction` (CPU witness from native capture, `coordinator.zig`) and
`local_gkr_prove` (local GKR inputs, layers and sumchecks, `cpu_worker.zig`).
They never enter proof authority: all 14 proof artifacts and `bundle.json` of
the prefix are byte-identical to the PR #310 binary's (checked by SHA-256).

## Profile

PCS on the GKR route: OM31 (degree 8), **log_blowup 2 (blowup 4)**, 256
queries, PoW 0, fold step 4 (`om31_security_candidate.config()`:
`FriConfig.init(0, 2, 256)`). The receipt README's "blowup 2" refers to
`β2 = log_blowup 2`. Classic route: QM31, log_blowup 1, 70 queries, PoW 26,
fold step 1.

GKR route, `off4` (PR #310 layout, telemetry build), prove **66.28 s**, process
user 571 s, peak RSS 22.3 GB. Committed MAIN 1,909 M and INTER 1,229 M M31 cells
(INTER = 16 Eq/prefix binding columns per GKR role row plus classic OM31
interaction of global relations and of the truth proofs).

| Phase | GKR core-s | % | Classic core-s (§classic) |
|---|---:|---:|---:|
| CPU witness (`source_construction`) | 8.0 | 1.7 | 11.5 (incl. truth sources) |
| **Local GKR prove** (inputs, layers, sumchecks) | **80.8** | **17.0** | — |
| MAIN LDE / MAIN Merkle | 25.0 / 39.3 | 5.3 / 8.3 | 12.8 / 15.1 |
| GKR binding finalize (Eq/prefix) | 5.2 | 1.1 | — |
| Interaction generation (global + truth LogUp) | 16.7 | 3.5 | 14.3 (all LogUp) |
| Interaction LDE / Merkle | 15.5 / 25.7 | 3.3 / 5.4 | 8.3 / 11.3 |
| **Composition evaluation** | **132.3** | **27.9** | 74.8 |
| Composition interpolate / commit | 1.3 / 15.4 | 0.3 / 3.2 | 0.7 / 5.7 |
| OODS sampled values | 11.5 | 2.4 | 3.3 |
| **DEEP quotients + FRI commit (q256, fold 4)** | **76.1** | **16.0** | 23.0 (q70, fold 1) |
| Proof of work | 0.0 | 0 | 29.5 (26 bits x 12 proofs) |
| FRI decommit / trace decommit | 4.0 / 17.7 | 0.8 / 3.7 | 0.0 / 7.5 |
| Retained-MAIN spill/restore | 6.7 s wall, ~0 core | | |
| **Recorded total** | **474.4** | | **218.2** |

By proof group (core-s): 4 CPU proofs 312.8 (78 each; 20 of it local GKR),
Keccak truth (2^18, r27 throughput policy) 119.8 (67 of it composition), the
other 7 truths 42.

### Classic control (same source, host and prefix)

`classic4`: `rv64-word16-ethereum produce` from the same branch head (classic
QM31, q70, PoW 26, blowup 2, fold 1, classic V3 layout defaults including
compact decode and the fused component pairs), same ELF/input, 4 CPU + 8 truth
proofs: prove **29.46 s**, process user 237.7 s, peak RSS 20.3 GB. Committed
native cells: preprocessed 183 M, MAIN 1,741 M, INTER 1,017 M (one QM31
column = 4 cells). Per CPU segment 26-32 core-s, Keccak truth 67.5, the other
7 truths 42 (of which PoW 23).

So on this prefix the GKR route is **2.25x in prove wall (66.28 / 29.46 s)
and 2.17x in recorded core-seconds (474 / 218)**, the same ratio as the
full-block receipts (81.78 / 37.71 s = 2.17x). Per CPU segment it is 2.9x
(78 vs 27 core-s), per Keccak truth 1.8x (120 vs 67.5), the small truths are
equal (42 vs 42: GKR has no PoW but OM31 FRI on tiny domains).

Note also that the GKR route commits *more* cells on this prefix (3,138 M vs
2,758 M MAIN+INTER): the 16 Eq/prefix binding columns per role row of every
GKR role cost about as much as the classic CPU interaction they replace, and
the classic route already uses compact decode and the fused component pairs.


## Why the GKR route is about 2.2x slower on CPU

The full-block receipt is 81.78 s (GKR) against 37.71 s (classic). On the
prefix the extra 256 core-s decompose as (GKR minus classic, core-s):

| Source | delta |
|---|---:|
| Interaction side: local GKR 80.8 + binding 5.2 + OM31 global/truth interaction gen/LDE/Merkle 57.9, vs classic LogUp 33.9 | +110 |
| PCS back end at blowup 4 + OM31: composition commit, OODS, DEEP/FRI, decommits (124.7 vs 39.5) | +85 |
| Composition evaluation in OM31 (132.3 vs 74.8; Keccak 67 vs 39) | +58 |
| MAIN LDE + Merkle at blowup 4 (64.3 vs 27.9) | +36 |
| PoW removed (P0) | -30 |
| Witness | -4 |
| **Total** | **+256** |

In decreasing order of cause:

1. **Blowup 4 instead of 2.** Every commitment-side phase runs on a 4n
   domain: MAIN and interaction LDE and Merkle hashing (106 core-s), the
   composition commit (15), DEEP quotients and the first FRI layers (76).
   These are 2.2-3.3x the classic phases. Blowup is the
   single largest factor, and it is a security-parameter choice (§Parameters),
   not an implementation inefficiency.
2. **OM31 instead of QM31.** Every extension-field value has 8 instead of 4
   M31 coordinates. A full OM31 multiply is ~3-4x a QM31 multiply; M31xOM31 is
   2x M31xQM31. This roughly doubles composition accumulation (random-coefficient
   powers, denominators), OODS, DEEP row work, FRI folding, the composition
   polynomial (8 split columns instead of 4) and every truth proof's LogUp
   interaction (8 cells per extension column instead of 4). The Keccak truth,
   which keeps classic LogUp, costs 120 core-s here against 67.5 classic.
3. **Local GKR work.** 80.8 core-s for 4 CPU segments (20 per 2^22 segment,
   17% of recorded core time) plus 5.2 binding finalize. In exchange the CPU
   interaction commitment shrinks to 16 binding columns per role row plus the
   global relations. On CPU this is not a saving: the classic CPU interaction
   (generation + LDE + Merkle) cost 5.9 core-s per segment at blowup 2; the
   GKR segment spends 20.2 (GKR) + 1.3 (binding) + 5.8 (binding/global
   interaction LDE/Merkle at blowup 4) = 27.3, i.e. +21 core-s per segment.
4. **256 queries** (vs 70): trace decommit 17.7 core-s and FRI decommit 4.0,
   about 2.3x classic. Small on CPU (4.5%), larger in proof size and recursion.
5. **No PoW** (P0) removes a classic cost of 29.5 core-s (13.5% of classic). This is the one
   phase where the GKR profile is cheaper.
6. **Fixed per-proof costs and the truth count.** On this prefix the 6 small
   truths (everything but the two large ones) cost under 2 core-s together:
   with P0 there is no per-proof grind, and their LDE/FRI on tiny domains is
   negligible. The receipt's 11 truths (vs 6 classic) are mostly the same
   Keccak/secp work split differently, not extra fixed cost. Batching small
   truths into one PCS would save < 1% CPU time on this route (it still
   matters on GPU for launch/transcript latency).
7. **Wall-clock effects.** Retained-MAIN parking adds 6.7 s of spill/restore
   wall (no CPU) and the two-lane schedule leaves cores idle while the single
   Keccak proof's composition runs; the receipt's 93 s process wall includes
   8.4 s fixed setup (candidate fixed-authority roots).

## Compact CPU decode on the GKR route (now the GKR V3 default)

`Geometry.cpu_compact_decode` (CPU MAIN 47 -> 37 columns) is qualified on the
GKR route and is the `CpuLayout.forGkrProfile` default for
`ethereum_services_v3`. Design and soundness argument:
`src/frontends/riscv/rv64/air/word16_execution/README.md` (compact section,
"V3 local GKR route"). In short: a separate MAIN-only role `.cpu_compact`, the
same 14 local terms/relations/weights over the compact tuples, the ROM pc
coordinate read from the previous row both in the native GKR input and in the
authenticated binding masks, binding degree still 3, the compact identity
mixed into the GKR worker statement, source-bound accounting changed only in
MAIN width and residual count.

Same binary source, same native jobs, same resources, ABBA order
(off, cmp, cmp, off); repeated runs reproduce every proof artifact
byte-for-byte:

| 4-packet prefix | PR #310 layout (`off4`) | compact (`cmp4`) | delta |
|---|---:|---:|---:|
| Committed MAIN cells | 1,909 M | 1,741 M | -168 M (-10 x 4 x 2^22) |
| Committed MAIN+INTER cells | 3,138 M | 2,970 M | **-5.4%** |
| MAIN LDE + Merkle core-s | 64.2 | 58.0 | -6.3 (-9.8%) |
| Recorded stage core-s (2 runs) | 474.4, 482.1 | 469.7, 473.7 | -1.4% |
| Process user-s (2 runs) | 570.6, 579.0 | 563.5, 567.9 | -1.6% |
| Prove wall (2 runs) | 66.28, 65.56 s | 62.04, 64.78 s | **-3.8%** (mean 65.92 -> 63.41 s; shared host) |
| Peak RSS | 22.33 GB | 22.49 GB | |
| Proof files | 110.7 MB | 110.6 MB | |

The compact prefix verifies in the producer and in a fresh receiver process
(`verify-prefix-candidate`, accepted, 4 CPU + 8 truth proofs, 0.96 s verify).
Per-cell savings are only in MAIN commitment (and the MAIN share of DEEP and
decommit, below noise here); composition and GKR are unchanged because the
compact AIR has the same lookups and fewer, not cheaper, constraints. Expect
about -5% committed cells and -1.5% CPU core time on a complete block (the
wall delta above is within shared-host noise); the cell saving carries over
1:1 to GPU commitment work.

Adversarial gates (`zig build test-riscv64-services-gkr-local`, ReleaseSafe,
all pass): fresh-receiver rejection of a forged static `next` PC that keeps
every MAIN-only residual zero, of a changed binding target, Eq and prefix
(`COMPACT_CPU_BINDING_TAMPER`, OodsNotMatching); a complete two-shard compact
services execution (SHA-256, arith256, memset/memcpy) closes every global debt
in a fresh receiver and rejects a wrong final PC, a wrong global claim
(OodsNotMatching), a paired-layout receiver (InvalidSumcheck) and a wrong
initial PC (UntrustedGlobalGenesis).

Not yet done for compact: a complete-block run and the re-instantiated
bounded security model (`model.py --v3-source-bounds`) on its bundle. The
model's terms that change are columns (fewer) and constraint count (fewer); the
lookup relations, arities and slots per row are identical, so the numerical
bound can only improve, but the review is pinned to the actual roster and must
be rerun on a compact complete-block bundle.


## Parameters: blowup 4 / q256 vs blowup 2 / more queries (measured, not admitted)

The documented 128-bit target uses the **proven unique-decoding** argument of
`rv64-v3-bounded-security-review.md`, not the ethSTARK conjecture: per query
the error is the analysis agreement `alpha`, which must exceed
`(1 + rho_plus)/2` with `rho_plus = rho * 34/32` (17/64 at rho = 1/4), and the
query union is `P * alpha^q` with P = 18 proofs. At blowup 4 the review uses
alpha = 41/64: `18 * (41/64)^256 = 2^-160.30`. Its 128-bit claim (success per
RO query < 2^-129.69 for T <= 2^120) needs the query term below roughly
2^-152 at T = 1, so q256 has ~8 bits of slack (q >= 243 would do).

Same model at other rates (alpha = smallest multiple of 1/256 above the
unique-decoding bound; q chosen to keep the query term at <= 2^-160.30):

| log_blowup | rho | rho_plus | UD bound | alpha | bits/query | q for 2^-160.3 | q for ~2^-152 |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | 1/2 | 17/32 | 0.7656 | 197/256 | 0.378 | **436** | 413 |
| 2 (now) | 1/4 | 17/64 | 0.6328 | 41/64 | 0.643 | **256** | 243 |
| 3 | 1/8 | 17/128 | 0.5664 | 73/128 | 0.810 | 204 | 193 |

The ethSTARK-conjectured alternative (q ~ 128 at blowup 2) is outside the
documented assumption set and is not considered.

**Measured blowup 2 / q436** (experiment binary: `FriConfig.init(0, 1, 436)`,
identity words updated, beta-rate checks in `worker_protocol` and
`fixed_authority` set to 1; compact layout; same prefix, jobs and resources;
not committed):

| 4-packet prefix, compact | blowup 4, q256 (`cmp4`) | blowup 2, q436 (`b1cmp4`) | delta |
|---|---:|---:|---:|
| Prove (wall) | 62.04 s | **54.39 s** | **-12.3%** |
| Process user-s | 563.5 | 454.0 | -19.4% |
| Recorded core-s | 469.7 | 388.4 | -17.3% |
| MAIN + INTER LDE/Merkle core-s | 99.7 | 51.4 | -48% |
| DEEP + FRI commit | 78.8 | 57.0 | -28% |
| Composition commit | 15.1 | 7.8 | -48% |
| Trace + FRI decommit | 21.4 | 14.7 | -31% |
| Composition evaluation / local GKR | 131.3 / 81.4 | 134.5 / 81.1 | unchanged |
| Proof files | 110.6 MB | 146.1 MB | +32% |
| Peak RSS | 22.5 GB | 22.0 GB | |

The same-process receiver accepted the blowup-2 bundle. Composition and GKR do
not depend on the blowup (composition is evaluated on 2n either way), so the
saving is the whole commitment/DEEP/FRI side; on GPU it also halves the
extended-trace VRAM per proof. The costs are 1.7x queries (+32% proof bytes
here, a larger recursion leaf verifier) and a tighter unique-decoding margin:
`2*alpha - 1 = 0.539` against `rho_plus = 0.531` (margin 0.008, against
0.281 vs 0.266 = 0.016 at blowup 4), and the `34/32` quotient-extraction enlargement must be
re-derived for rho = 1/2. It is therefore **not** made the default here: it
needs a new assumption-set identity, the bounded review and `model.py`
reinstantiated at (beta1, q436), and a recursion-cost check. It is the largest
CPU-side lever found (-12% wall, -19% CPU) that stays inside the documented
proven-UD model.

## Other CPU-side levers checked

- **Truth batching / fixed per-proof cost.** With P0 there is no grind; the
  six small truths cost < 2 core-s in total on this prefix. Batching them into
  one PCS would save < 1% CPU (it remains a GPU latency item).
- **PoW.** Already 0 bits on this route (the classic route spends 29.5 core-s
  = 13.5% on 26-bit grinds).
- **Fold step.** fold 4 is already used; FRI layer commits are < 2% here.
- **Composition (28%) and local GKR (17%)** are the largest remaining phases
  and are independent of PCS parameters. The OM31 composition kernels and the
  GKR sumcheck kernels were already optimised by the #309/#311 lines of work;
  no further byte-identical kernel change was attempted in this pass.
- **Retained-MAIN parking** costs 6.2-6.7 s of wall with ~0 CPU (memory
  policy for the 22 GB host); it disappears with more RAM or VRAM residency.


## What remains for the GPU port

- Composition (28% here) and DEEP/FRI (16%) dominate the per-cell work and
  are compute-bound in OM31: an OM31 GPU kernel set (M31xOM31 accumulation with
  lazy reduction, Karatsuba OM31 = 2x QM31 over M31 limbs) is the first need.
  No resident OM31 PCS exists yet (the CUDA PCS matches the classic QM31
  route only).
- The local GKR prover (17%) is a streaming reduction: #311's resident
  sumcheck is the right shape; it needs the CPU role inputs generated on
  device (`pair_projection` / `native_provider` row projections, now including
  the compact previous-row read).
- Blowup 4 doubles VRAM per proof (a 2^22 CPU segment's extended MAIN+INTER is
  about 2x the classic 5.3 GB). Parameter choice (§Parameters) directly sets
  GPU memory and HBM traffic.
- The Keccak truth is the critical-path proof (120 core-s on CPU at 2^18 with
  the r27 throughput policy); its degree-5 4n composition is the single largest
  kernel.
