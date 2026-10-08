# RTX 5090 Cairo PIE proving research (2026-10-07)

This report tracks an RTX 5090 proof-time and memory Pareto search against the
historical H200 PIE receipts. The qualification rule is an exact proof hash plus
an independent Rust verifier verdict, with full-command, adapted-input-to-proof,
and proof-execution times reported separately. Hardware and source differences
make the historical H200 comparison indicative until a source-matched pair runs.

## Environment

- Source: `dc5dcf5402367d6ff2829d4339b460b97ea21a14`, plus the local CUDA 13
  API compatibility and compact-device patches documented below. Each trial
  receipt records the working-tree diff hash or binary hash.
- ReleaseFast, CUDA 13.0, sm_120, driver 595.91.07, one RTX 5090 with 32,607 MiB
  reported device memory. The first working pod has a 62,000,000,000-byte host
  memory cgroup and no swap.
- Canonical fixed coefficients and Cairo artifacts; 70-query, 26-bit-PoW proof
  protocol. Each successful proof was independently verified by the pinned Rust
  official verifier. Detailed receipts are under `working-host/`.
- The first pod had a 62 GB host-memory limit; the later, better provisioned
  5090 pod had 167 GB host RAM and driver 580.65.06. All final pipeline and
  capacity-boundary results below are from the latter pod.
- `measurements.csv` is rebuilt from the retained receipts by
  `summarize_trials.py`. It records 114 trials, including 87 exact-hash,
  independently verified successes, 24 failures, and three deliberately
  disqualified source/policy trials. The verifier receipt supplies the proof
  digest when an older trial has no separate `proof.sha256` sidecar.
- `pareto.csv` selects verified trials for which no same-PIE trial is no worse
  on both adapted-input-to-publication time and sampled device peak, and
  strictly better on at least one. It is
  an exploratory frontier across source revisions and pod conditions, not a
  controlled or production-qualified benchmark ranking. Close points need
  idle-host repeats because device sampling and timings have noise.

## Current outcome

The final compact policy proves the qualified 2.81M–5.34M-step cohort at
**1.85–3.20×** historical H200 adapted-input-to-publication time, below the
requested **4.5×** economic screen. The latest-source two-distinct-PIE recursive
pipeline takes **33.197 s**, or **2.18×** the historical H200 full command,
with the exact saved root. These are different timing boundaries; the
[final-default table](#final-default-compact-policy-and-two-leaf-pipeline)
keeps them separate. Hardware and source builds are not matched, so the
ratios are routing evidence rather than a controlled GPU comparison.

The 20.85M-step dense PIE also produces the exact verified proof on a 5090,
but even the best research placement is still many times slower than the
4.5× screen. This matters for real workloads: the H200 512-PIE campaign's
median input is **20.266M steps**, and only **21 of 512** inputs fall within
the qualified ≤5.34M-step range. The next architecture target is bounded
relation and constraint staging, not another global managed-memory hint.

| Large PIE | Historical H200 publication | 4.5× ceiling | Measured 5090 relation stage alone |
|---|---:|---:|---:|
| 6.00M steps | 5.018 s | 22.581 s | 40.864 s |
| 20.85M steps | 15.314 s | 68.913 s | 138.168 s |
| 22.67M Pedersen-heavy steps | 8.755 s | 39.398 s | 177.835 s |

These exact-proof observations establish that no ingress or late-opening
optimization alone can satisfy the large-PIE cost rule. The relation stage
must be redesigned to keep a bounded source working set on device.

The subsequent **1.5× H200 target** is stricter than the original 4.5×
screen. On the comparable historical adapted-input-to-publication boundary,
the current best verified 5090 points are:

| PIE | H200 publication | 1.5× ceiling | Best verified 5090 publication | Ratio |
|---|---:|---:|---:|---:|
| 2.81M EC-heavy | 4.200 s | 6.300 s | 8.668 s opt-in, 8.848 s final default | 2.06× opt-in |
| 3.60M Pedersen-heavy | 4.995 s | 7.493 s | 9.100 s opt-in, 9.227 s final default | 1.82× opt-in |
| 4.00M | 4.635 s | 6.953 s | 8.234 s opt-in, 9.028 s final default | 1.78× opt-in |
| 5.34M | 5.103 s | 7.655 s | 11.816 s opt-in three-run median | 2.32× |
| 6.00M | 5.018 s | 7.527 s | 87.431 s opt-in | 17.42× |
| 20.85M | 15.314 s | 22.971 s | 274.577 s opt-in | 17.93× |
| 22.67M single-block Pedersen | 8.755 s | 13.133 s | 320.338 s opt-in | 36.59× |

None meets 1.5× yet. The 2.81–4M rows have about 3.7 s of cold ingress and
approximately 5.1–5.5 s of proof/decode; a warm service may improve the full
boundary, but cannot by itself satisfy a **proof-only** 1.5× comparison.
The large rows require an algorithmic working-set change: their measured
relation stage alone exceeds the new total publication ceiling. The H200
source/timing caveat above still applies.

## Verified small PIE

Input `15627902-15627904.prover_input.cpi` has 1,224,007 OS steps and SHA-256
`c92a1ecd5baf8651e88c6d96f016cfa2646bbda2cf646fec9bc0558c200a6f81`.
All runs yielded proof SHA-256
`980841d3e5dda240bfc88a28aa5a757d3d8418c4562678832af3079b7446c4d1`.

| Run | Full command | Adapted input to proof | Ingress | Proof execution and decode | GPU peak | Host RSS peak | Rust verifier |
|---|---:|---:|---:|---:|---:|---:|---|
| 1 | 5.597 s | 5.038 s | 4.520 s | 0.433 s | 24.93 GiB | 2.79 GiB | pass |
| 2 | 6.237 s | 5.447 s | 4.916 s | 0.436 s | 24.93 GiB | 2.78 GiB | pass |
| 3 | 6.250 s | 5.446 s | 4.906 s | 0.449 s | 24.93 GiB | 2.79 GiB | pass |

The median proof-execution time is 0.436 s. The median adapted-input-to-proof
time is 5.446 s. In the first run, static setup occupied 2.906 s of 4.520 s
ingress, including 0.572 s preprocessed loading and 0.117 s initial upload.
The remaining static work needs finer profiling before attribution.

The historical H200 proving-service receipt for this PIE records 0.439 s Cairo
proof execution and 2.654 s ingress, but uses an earlier source build and a
different service timing boundary. It is not a controlled hardware speedup
claim. It does indicate that this 5090 small-case proof time is already close
to the earlier H200 observation.

A second independently verified input,
`15627905-15627907.prover_input.cpi` (SHA-256
`3c898538af071069385e5deae70a086a31e8ab87198fa198cd6fcf0f3e3d1557`),
completed in 0.455 s proof execution, 6.593 s adapted-input-to-proof,
and 7.389 s full command, with a 24.31 GiB sampled GPU peak. Its exact proof
SHA-256 was `02c0356818f99c29d169cbe984c7ba99a2af4552534798c764c5e8f15e656d05`.
The first run includes cold fixed-asset ingestion; it is not a warm-service
throughput measurement.

On the 167 GB host, a same-source build with the new relation-window kernel
path proved the first small PIE in 0.347 s proof execution, versus 0.341 s for
its ordinary global-kernel path. Both produced the same exact proof SHA-256
and passed the independent verifier. This qualifies the instance grid
partition for a small PIE; the later dense trial found no material speedup
from instance-window launches alone.

## Dense PIE and memory limit

For `15582797_15582797` (20,848,320 OS steps, 113,595,953 trace cells,
408,205,744 input bytes), the physical arena plan is 88,627,473,376 bytes.
Managed-memory capacity placement reached trace generation in 19.643 s and
preprocessed commit in 20.107 s. The process was then killed by the 62 GB host
memory cgroup before a proof was produced; this is a failed run, not a 5090
device-memory capacity measurement. The log and memory samples are retained in
`working-host/rtx5090-capacity-baseline/15582797_15582797/`.

CUDA 13 managed-memory discard was tested separately with 35 GiB of host-touched
pages followed by another 35 GiB allocation. The discard call and stream sync
succeeded, but host memory did not drop and the second touch triggered the
cgroup OOM. Discard alone is therefore not a qualified remedy on this host.

The same 5090 class with 167 GB of host RAM completed the dense PIE with the
expected proof SHA-256
`fcc457fee3bcaca85efd97d308daa1a16e849c633b4571144417543158eb1eeb`
and a passing independent Rust verdict. Its proof execution was **371.363 s**,
adapted-input-to-publication **375.382 s**, full command **380.146 s**,
sampled GPU peak **17.615 GiB**, and process RSS peak **72.625 GiB**. The
host's driver was 580.65.06. A native CPU-targeted build was required because
the first host's Xeon-targeted executable used instructions unavailable on the
second host's AMD EPYC 7C13.

| Proof stage | Elapsed time |
|---|---:|
| Trace generation | 54.693 s |
| Preprocessed and main commitment | 7.134 s |
| Relation generation | 139.899 s |
| Interaction commitment | 24.542 s |
| Constraint evaluation | 127.416 s |
| OODS, quotient, FRI, decommit | 17.659 s |

The historical H200 data for the same PIE is 1.293 s proof execution and
15.314 s adapted-input-to-proof; the 4.5× thresholds are 5.819 s and
68.913 s respectively, subject to the source/timing caveat above. The managed
5090 baseline misses both by a wide margin. Its low HBM peak is a capacity
success, but host-preferred pages are too expensive in the three dominant
stages. The next tests must change memory access granularity and residency,
not merely reduce allocation size.

## Main-coefficient HBM experiment

An opt-in capacity policy left the 12.55 GB main-coefficient slot in device
memory while retaining host preference for interaction coefficients and writer
scratch. The exact proof hash and independent Rust verdict still matched. The
same host recorded 327.247 s proof execution, 331.364 s
adapted-input-to-publication, 335.848 s full command, a 29.242 GiB sampled
GPU peak, and 60.935 GiB RSS peak. Relation generation fell from 139.899 to
103.247 s; trace generation fell from 54.693 to 48.449 s. Constraint
evaluation stayed near 130 s. This is an 11.9% proof-time reduction with lower
host use, but it remains far outside the H200-relative economics threshold.
The next policy experiment leaves the interaction-coefficient slot on device
instead, to isolate which hot buffer gives the better speed/memory tradeoff.

That second policy also produced the exact proof and passed Rust verification.
It recorded **310.373 s** proof execution, **314.503 s** publication,
**318.903 s** full command, **27.242 GiB** sampled GPU peak, and **62.906 GiB**
RSS peak. Compared with the baseline, relation generation only fell from
139.899 to 136.051 s, but interaction commitment fell from 24.542 to 4.629 s
and constraint evaluation from 127.416 to 93.242 s. This is the best measured
single-slot policy so far, 16.4% faster in proof execution than the original
capacity placement, yet still far from the economics threshold. The
phase-dependent tradeoff means choosing one HBM slot cannot solve the
out-of-core working-set problem on its own.

Keeping writer scratch in HBM by itself reduced trace generation from 54.693 s
to 16.468 s. Its exact proof and Rust verdict passed, with 335.675 s proof
execution, 339.654 s adapted-input-to-publication, 344.379 s full command,
27.117 GiB sampled device peak, and 72.620 GiB RSS peak. An attempted
combined-policy run is invalid because its build used an older proof-session
source file from another checkout; it is not evidence about that policy.
Standalone 5090 tests showed neither
CUDA 13 discard nor prefetch-to-host immediately recovered free HBM after a
12 GiB managed allocation was GPU-touched. The combined opt-in was removed
from source pending a source-matched dense trial and real HBM reclamation.

Instance-window relation launches without prefetch preserved exact dense
proof bytes and Rust verification, but did not materially improve proof time
(310.422 s versus 310.373 s for the global launch under the same
interaction-coefficient policy). Prefetching each instance's whole source
columns raised relation time and later failed from CUDA allocation pressure;
the 8 GiB-per-component constraint-source prefetch also failed. These are
rejected experiments, with receipts and problem-match notes retained here.

## The 5090 capacity boundary: 2M and 4M steps

Two additional 10-block PIEs were fetched from the same API and adapted with
the pinned Cairo leaf bootloader. Adaptation happened before the GPU command
and is recorded separately. Their exact proof SHA-256 values match the saved
H200 results, and every successful 5090 variant below passed the independent
Rust verifier. Historical H200 timings use an older source build, so ratios
are screening comparisons rather than controlled hardware benchmarks.

| PIE and policy | Planned arena | 5090 proof | 5090 input→publication | Device peak | H200 proof / input→publication |
|---|---:|---:|---:|---:|---:|
| `15567390_15567399`, 2.00M steps, ordinary device arena | 28.12 GiB | 0.412 s | 3.601 s | 28.36 GiB | 0.429 / 4.618 s |
| `15574540_15574549`, 4.00M steps, managed with no placement | 31.20 GiB | failed at constraint | — | 30.56 GiB | 0.454 / 4.635 s |
| same 4M PIE, broad capacity policy | 31.20 GiB | 142.626 s | 146.249 s | 16.74 GiB | 0.454 / 4.635 s |
| same 4M PIE, interaction evaluations fully host-preferred | 31.20 GiB | 19.025 s | 22.659 s | 29.12 GiB | 0.454 / 4.635 s |
| same 4M PIE, last 50% host-preferred | 31.20 GiB | 11.218 s | 14.863 s | 30.74 GiB | 0.454 / 4.635 s |
| same 4M PIE, last 75% host-preferred | 31.20 GiB | 14.724 s | 18.339 s | 29.99 GiB | 0.454 / 4.635 s |
| same 4M PIE, last 25% host-preferred | 31.20 GiB | 7.719 s | 11.380 s | 31.36 GiB | 0.454 / 4.635 s |
| same 4M PIE, preprocessed Merkle hashes host-preferred | 31.20 GiB | **5.554 s** | **9.282 s** | **28.49 GiB** | 0.454 / 4.635 s |

The 4M no-placement attempt reached constraint evaluation in 3.063 s, then
failed with CUDA allocation status 2. The broad capacity policy spent about
65 s in decommit alone. Offloading only part of one 3.69 GB committed
evaluation range retained the fast trace path and reduced host-side reads in
constraint evaluation. The 25% result is a one-run performance point at
essentially the full CUDA device budget; it is not a safe admission default.
The 50% and 75% settings each have three exact, Rust-verified runs with stable
timing and memory, recorded alongside this report. Their input-to-publication
times are about 3.21× and 3.96× the saved H200 result, respectively. The
proof-execution-only ratios remain much larger, so the user-specified 4.5×
criterion is met here on the end-to-end timing boundary, not on proof time.

The Merkle-tree placement is a better Pareto point than spilling evaluation
columns: it fits with 2.87 GiB of headroom against the CUDA-reported 31.36 GiB
usable HBM, while constraint evaluation returns to 0.876 s. Its preprocessed
commitment takes 1.727 s instead of roughly 0.7 s. Three exact,
Rust-verified repetitions recorded 9.282, 9.118, and 9.280 s
input-to-publication; the median is 9.280 s. The policy has since verified on
two additional boundary PIEs below. For the 8M-step PIE
`15554590_15554599`, combining this tree with a 75% interaction-evaluation
spill still reached CUDA allocation pressure during constraint evaluation;
that failed receipt is saved. The next candidate places the two other trace
Merkle trees on host before their first writes.

## Boundary cohort on the corrected managed allocator

The CLI uses the retained execution cache. An earlier `force` attempt altered
only the direct transaction allocator and is not valid evidence about forced
managed memory. The corrected binary logs `cuda prepared arena mode=managed`
for each run below. All successful rows match the saved exact proof SHA-256
and pass the independent pinned Rust verifier. The H200 receipts are historical
and use an earlier source, so these ratios guide research rather than qualify
a source-matched hardware comparison.

| PIE | Steps | 5090 policy | 5090 proof | 5090 input→publication | H200 input→publication | Ratio | 5090 GPU peak |
|---|---:|---|---:|---:|---:|---:|---:|
| `15608951_15608963`, EC-heavy | 2.81M | forced managed + cold preprocessed tree | 5.501 s | 9.184 s | 4.200 s | 2.19× | 27.37 GiB |
| `15574910_15574919`, Pedersen-heavy | 3.60M | same | 6.046 s | 9.806 s | 4.995 s | 1.96× | 28.99 GiB |
| `15563360_15563369` | 5.34M | forced managed + all trace trees + 75% interaction evaluations on host | 26.061 s | 29.762 s | 5.103 s | 5.83× | 31.36 GiB |
| same 5.34M PIE | 5.34M | forced managed + all trace trees + 50% main coefficients on host | ≈17.0 s | 20.827 s median | 5.103 s | 4.08× | 29.87 GiB |
| same 5.34M PIE | 5.34M | broad capacity spill, interaction coefficients in HBM | 102.673 s | 106.373 s | 5.103 s | 20.84× | 15.24 GiB |

The first two rows meet the requested 4.5× economics screen on the
input-to-publication boundary, with several GiB of sampled device headroom.
Their proof-only ratios are substantially worse (12.76× and 13.26×), so the
choice of timing boundary is explicit. For the 5.34M PIE, the preprocessed
tree alone and that tree plus a 75% interaction-evaluation spill both failed
during constraint evaluation at the device cap. Spilling all trace trees too
produced a valid proof, but constraint evaluation took 18.386 s and the device
peak reached the CUDA-reported usable limit. The broad capacity placement
reduced device use but was far slower. A new targeted experiment tests whether
spilling a fraction of main coefficients instead keeps the constraint source
in HBM and clears the 22.96 s economics limit.

That targeted coefficient test succeeded twice with the same exact proof and
passing Rust verdict: 20.734 and 20.919 s input-to-publication at 50% spill,
29.87 GiB GPU peak in each run. Its median of 20.827 s is **4.08×** the saved
H200 time, with about 1.49 GiB of sampled headroom. Constraint evaluation
fell from 18.386 to 0.928 s; relation generation rose to 10.036 s. A 40%
spill also verified but was slightly slower (21.018 s) and used 30.24 GiB.
This is a material policy improvement over spilling the interaction
evaluations, not evidence that every 5M-step geometry will fit. The next test
uses a separate 6M-step PIE.

For that 6.00M-step PIE (`15557240_15557249`), the current arena is
44,229,177,920 bytes (41.19 GiB). Hosting all three trace trees and 50% or
75% of the main coefficients still failed from CUDA allocation pressure in
constraint evaluation. These failures are recorded; they are not proof-time
measurements. The 50% 5.34M policy's 29.87 GiB sampled peak is therefore a
useful, but not universal, geometry boundary.

## Partial fixed-tree spill

For the 4.00M-step PIE, hosting only a portion of the 4.29 GB preprocessed
Merkle tree improved the exact, Rust-verified result. All variants below used
the same source and proof bytes. Head and tail placement differed by less
than 0.1 s at 50% and 75%; the amount hosted mattered more in these trials.

| Hosted tree fraction | Input→publication | Proof execution | GPU peak | Approximate free HBM |
|---:|---:|---:|---:|---:|
| 100% | 9.280 s median of three | 5.554 s first run | 28.49 GiB | 2.87 GiB |
| 75% tail | 8.896 s | 5.223 s | 29.49 GiB | 1.87 GiB |
| 60% tail | 8.689 s | 5.002 s | 30.12 GiB | 1.24 GiB |
| 50% tail | 8.462 s | 4.840 s | 30.49 GiB | 0.87 GiB |

The 75% fraction also proved the EC-heavy 2.81M PIE in 8.668 s publication
at 28.37 GiB and the Pedersen-heavy 3.60M PIE in 9.100 s at 29.99 GiB.
Those are 2.06× and 1.82× their saved H200 publication times. Each proof
matched the expected hash and passed Rust verification. The 50% point is
faster on one PIE but has little device headroom; 75% is the broader tested
choice. Relation instance prefetch was rejected because it triggered
`StrictAotViolation` at finish, even though its intermediate kernels ran.
The rejected relation-window and evaluation-prefetch code was removed after
the trial; only its receipts and problem-match notes remain.

## One-flag compact-device policy

`STWO_CUDA_COMPACT_DEVICE_PROFILE=1` applies the measured policy by compiled
arena size on a 30–36 GiB CUDA device. It uses a 2 GiB allocation reserve so
near-capacity plans choose managed memory before later proof allocations,
while a smaller 2M-step plan keeps its faster device arena. Managed plans at
or below 34 GiB host-prefer 75% of the preprocessed tree; plans above 34 GiB
and at or below 38 GiB host-prefer all three trace trees and half of the main
coefficients. Plans above the qualified 38 GiB envelope fail admission, with
no claim that the envelope is a proof of fit for every component mix.

| PIE | Arena mode | Input→publication | GPU peak | H200 historical ratio | Proof match / Rust verifier |
|---|---|---:|---:|---:|---|
| `15567390_15567399`, 2.00M | device | 3.507 s | 28.36 GiB | 0.76× | exact / pass |
| `15608951_15608963`, 2.81M EC-heavy | managed | 8.868 s | 28.37 GiB | 2.11× | exact / pass |
| `15574910_15574919`, 3.60M Pedersen-heavy | managed | 9.119 s | 29.99 GiB | 1.83× | exact / pass |
| `15574540_15574549`, 4.00M | managed | 8.957 s | 29.49 GiB | 1.93× | exact / pass |
| `15563360_15563369`, 5.34M | managed | 21.616 s | 29.87 GiB | 4.24× | exact / pass |

This is a single-run qualification for the integrated policy; several manual
policy variants above have repeats. `15557240_15557249` has a 41.19 GiB
arena and was rejected by this profile instead of entering an unqualified
out-of-core proof. The profile is opt-in pending broader geometry coverage.

After removing the rejected relation and evaluation prefetch implementations,
the cleaned binary reproduced the expected proof hashes and Rust verdicts for
both sizing tiers: the 4.00M PIE published in **8.776 s** at **29.49 GiB**,
and the 5.34M PIE in **21.602 s** at **29.87 GiB**. The latter is **4.23×**
the historical H200 publication time. Moving the oversized-plan gate into
arena preparation reduced the 6M PIE's failed command from 4.09 to 3.01 s
and its sampled device peak from 5.25 to 0.50 GiB, without starting proof
work. Multi-leaf compact-profile batches also disable the default 2.17 GB
fixed-coefficient device image, retaining the authenticated host snapshot;
an explicit request for that device image conflicts with the compact profile.

## Production workload implication

The saved H200 512-PIE campaign's `pie_analysis.csv` contains 512 measured
PIEs with a median of 20.27M OS steps; 437 have at least 10M steps, and 263
have at least 20M. The compact profile above therefore covers a useful small
geometry class, **not** that campaign's typical PIE. A representative 20.85M
PIE currently takes 310.373 s proof execution and 314.503 s
input-to-publication on the 5090 with the best qualified capacity placement,
versus 1.293 s and 15.314 s in the historical H200 receipt. That is 20.54×
on publication, well beyond the 4.5× economics screen. Either the large-PIE
out-of-core path needs a major change, or the upstream construction service
must produce more, smaller PIEs and the extra recursion cost must be measured.
OS step count alone is not an admission rule: component mix and arena geometry
matter, and the current policy gates on compiled arena size.

## Recursive fold and complete pipeline qualification

The resident circuit-recursion product previously admitted only SM 80 and SM
90, even when built with `-Dcuda-arch=120`. Its build now passes the selected
architecture to the product. On the 5090, a two-leaf `fold-tree` then matched
the saved H200 proof, outputs and packed-tree SHA-256 digests byte for byte.
The 5090 recorded **0.516 s circuit resident proof**, **2.740 s full command**
and **26.77 GiB sampled device peak**. The historical H200 command is 2.579 s;
the hardware/source comparison is indicative. The exact hashes and full
receipt are in `fold5090-two/`.

The first complete serial PIE-to-root attempts exposed an architecture
admission error and then a capacity error: the Cairo and circuit arenas were
co-resident during the verified leaf callback. The single-leaf path now lends
the live Cairo CUDA runtime to circuit proving after releasing the prepared
Cairo arena. Opening a second runtime was rejected because the runtime is
single-owner and correctly returned `InvalidState`.

The resulting serial pipeline proved the two distinct Cairo PIEs, wrapped
both verified leaves on CUDA, then folded them to one root on CUDA. The exact
root proof, outputs and packed-tree SHA-256 digests match the H200 fixture.
The 5090 recorded **46.248 s full command** and **30.49 GiB sampled GPU peak**.
The historical H200 full command was 15.252 s, so this is **3.03×** on that
indicative cross-source comparison, within the 4.5× end-to-end screen. Cairo
leaf proof execution and decoding took **13.713 and 14.155 s**; the two
circuit leaf proofs took **0.485 and 0.541 s**, and the terminal circuit root
proof took **0.513 s**. The main optimization target is therefore memory
placement during the Cairo leaves. The full receipt and per-stage logs are in
`pipeline5090-two/`.

A manual 25% main-coefficient spill, with the three trace hash trees hosted,
improved the same two-PIE pipeline to **42.081 s full command** at **30.74 GiB**.
Both Cairo leaves and the final root remain byte-identical to the reference.
The first leaf's Cairo proof and decode fell from 13.713 to 12.465 s, and the
second from 14.155 to 11.711 s. This is **2.76×** the saved H200 full-command
time. The same placement gave an exact, independently Rust-verified proof for
the 5.34M-step PIE in **17.282 s input-to-publication**, down from the
21.602 s compact-policy result, at **30.62 GiB**. Both geometries have arenas
below 37 GiB, so the one-flag compact profile now selects this 25% policy in
that range and retains 50% above it. The resulting one-flag build is being
qualified separately.

The 6.00M-step PIE remained at the 5090's physical capacity limit and failed
constraint evaluation with 25%, 50%, and 75% of interaction evaluations
host-preferred, despite also hosting all trace hash trees and half the main
coefficients. Those failed receipts are retained. Merely changing this
fraction does not establish a viable 6M-step path; it likely needs a different
memory layout or more substantial phase-aware streaming.

A later **managed-capacity** trial of the same 6M-step PIE did complete with
the exact expected proof and a passing independent Rust verdict. With half of
writer scratch host-preferred, all trace trees hosted, and 20% of interaction
evaluations prefetched to GPU, it took **150.146 s** to publish, **152.667 s**
full command, used **16.490 GiB** sampled device memory and **33.90 GB**
process-tree RSS. Its large relation (**66.510 s**) and late opening work
show that this is a capacity result, not a viable 4.5× economic result. The
receipt is under `rtx5090-six-m-capacity-writer50-eval80/`. It also shows why
the compact-profile failures above must not be interpreted as a physical
impossibility on the 5090.

On the same source and PIE, leaving the trace trees on device reduced
publication to **147.544 s**, at **22.490 GiB** peak. Then retaining nearly
all main coefficients in HBM reduced relation generation from **66.674 to
40.769 s**, yielding **115.620 s** publication at **26.739 GiB** peak. Both
proofs matched the expected SHA-256 and passed the pinned Rust verifier;
receipts are under `rtx5090-six-m-capacity-treesdevice-*/`. The latter is a
**23.0%** improvement over the first completed capacity proof, but still
about **23×** the historical H200 publication time. This geometry has a
different hot-set balance from the 20.85M-step PIE; copying its placement
policy wholesale wasted device capacity and PCIe bandwidth.
Prefetching 30% of main evaluations into that remaining capacity then reduced
relation generation to **29.615 s** and publication to **106.272 s** at
**29.241 GiB** peak. This third point again matched the exact proof SHA-256
and passed Rust verification; its receipt is under
`rtx5090-six-m-capacity-treesdevice-maincoeff1-maineval70-writer50-eval80/`.
It is **29.2% faster** than the first completed 6M capacity proof, still
roughly **21.2×** the historical H200 publication time. The measured gain
justifies geometry-aware stage placement, while the remaining ratio requires
bounded source staging rather than another static global hint.
An independent opt-in trial kept 30% of the writer lookup-input slot on the
device while returning main evaluations to the fully hosted capacity policy.
Relation stayed at **40.864 s**, but trace fell to **6.050 s** and the measured
decommit phase fell from about **18.85 s to 0.021 s**. Its exact proof and
independent Rust verdict matched, with **87.431 s** publication and
**29.990 GiB** whole-device peak. See
`rtx5090-six-m-capacity-lookup70-maincoeff1-writer50-eval80/`. This is a
real complete-proof gain, though the phase effect likely depends on later
managed-page residency and must be checked across other component mixes.
The 4.5× screen for this PIE is **22.581 s**, so even this best 6M point is
about **17.4×** the historical H200 publication time.

The one-flag compact profile reproduced the 5.34M exact proof and independent
Rust verdict in **17.772 s input-to-publication**, with **30.62 GiB** sampled
GPU peak. The full two-PIE serial pipeline also reproduced the exact root in
**42.764 s full command**, with **30.74 GiB** peak. The integrated batch mode
reused setup but took **51.598 s** and reached the GPU's 31.36 GiB usable
limit; its second Cairo proof and decode rose to 24.817 s. Disabling circuit
arena reuse in that batch took **86.809 s**. All modes yielded the same root;
at this stage, process-separated serial leaves were faster. The pool-trimming
change documented below subsequently made the integrated batch faster.
The compact single-leaf handoff is being restricted to the compact-device
profile so larger GPUs retain their existing handoff behavior.

The final compatibility build, with that restriction in place, again produced
the same Cairo leaves and exact root. It took **42.563 s full command**, with
**30.742 GiB sampled GPU peak**. The two Cairo leaf input-to-publication
windows were 16.231 and 15.341 s; their proof-and-decode portions were 12.690
and 11.734 s. The full command is **2.79×** the historical H200 15.252 s
receipt. The final-source receipt and all phase logs are in
`pipeline5090-two/final-source/`; the three root hashes match the H200 fixture.

An additional 6.00M-step experiment hosted 25% of main evaluations and 50%
of interaction evaluations, on top of all three trace trees and 50% of main
coefficients. It again exhausted the CUDA device during constraint evaluation,
after **50.790 s** full command and a **31.356 GiB** sampled device peak.
Relation generation alone took about 21 s, already consuming almost all of
the 22.581 s historical-H200-relative publication budget. This rules out that
placement as a useful route to the 4.5× economics target.

## Rejected lookup-residency experiment

For the 20.85M-step PIE, retaining the 2.28 GB relation lookup slab in HBM
while also retaining the interaction coefficients improved trace generation
from 52.876 to 41.725 s, but left relation time essentially unchanged
(136.721 vs 136.051 s), raised interaction commitment from 4.629 to
14.071 s, and exhausted the card during constraint evaluation after
291.805 s of full-command time. The peak was 31.35 GiB, at the CUDA-reported
usable capacity. The failed receipt is retained under
`rtx5090-capacity-interactioncoeff-lookup/`; the opt-in flag was removed from
source. It produced no proof and is not a performance improvement.

## Further placement and arena search

For the 5.34M-step PIE, hosting the *tail* 25% of main coefficients instead of
the head produced the same exact proof and passed the independent Rust
verifier. Input-to-publication fell from the integrated head-placement result
of 17.772 s to **16.135 s**, with **30.617 GiB** peak. Relation generation fell
from 7.320 s in the head-placement receipt to **5.719 s**. This is a useful
opt-in Pareto point; `STWO_CUDA_SELECTIVE_HOST_TAIL=1` applies it to the manual
fractional policy. Applying the tail choice to the compact profile for the
two-leaf recursive pipeline yielded the same exact root, but full time rose
from 42.563 to **42.998 s** and both Cairo leaves were slightly slower. The
default therefore retains the broadly qualified head placement rather than
making a geometry-specific change from one standalone result. Receipts are
under `rtx5090-five-m-all-hashes-maincoeff25-tail/` and
`pipeline5090-two/tail-policy/`.

Substituting host-preferred trace-writer scratch for the main-coefficient
spill also matched the exact proof and passed Rust verification, but raised
input-to-publication to **31.480 s**. Trace generation grew from about 2.2 s
to 9.7 s, so that option was removed from source. Its receipt remains under
`rtx5090-five-m-all-hashes-writer-host/`.

A more aggressive ordering experiment was tried against the existing bounded
arena packer for the 6.00M-step geometry. Its 193-slot plan shrank by only
**32 bytes**, from
44,229,177,920 to 44,229,177,888 bytes. The phase-overlap lower bound is
43,711,489,616 bytes, so alternative packing cannot bring this geometry
below the compact profile's 38 GiB planning envelope. The additional search
experiment was removed; the existing packer remains. The failed-admission
receipt is under
`rtx5090-six-m-arena-search/`. Reducing this class needs shorter live ranges
or a different allocation/streaming architecture, not a new ordering of the
same buffers.

With all three trace hash trees host-preferred, a sweep of the main-coefficient
tail on the same 5.34M PIE found the following exact, independently
Rust-verified points. Each is one run on an otherwise idle 5090. The
CUDA-reported usable capacity was 31.36 GiB; the last rows have too little
headroom for an admission default.

| Hosted coefficient tail | Input→publication | Full command | Sampled GPU peak | Historical H200 publication ratio |
|---:|---:|---:|---:|---:|
| 25% | 16.135 s | 17.265 s | 30.617 GiB | 3.16× |
| 22% | 15.625 s | 17.027 s | 30.742 GiB | 3.06× |
| 20% | 15.074 s | 16.401 s | 30.867 GiB | 2.95× |
| 15% | 13.674 s | 14.836 s | 30.992 GiB | 2.68× |
| 10% | 13.501 s | 14.705 s | 31.117 GiB | 2.65× |
| 5% | **11.938 s** | **13.406 s** | **31.242 GiB** | **2.34×** |

This is a material speed frontier over the broad compact profile's 17.772 s
for this PIE, but the 5% point has only about 0.12 GiB sampled headroom. It
is a research result, not a safe setting for arbitrary PIE geometry. The
receipts are in the corresponding `rtx5090-five-m-all-hashes-maincoeff*-tail/`
directories. H200 ratios remain indicative because its saved receipt used an
older source build.

Two more idle-host repeats of the 5% point published in **11.759** and
**11.816 s**, with the same exact proof, passing Rust verdict, and **31.242 GiB**
sampled peak in both. The three-run publication median is **11.816 s**. This
supports repeatability on the tested host, but still leaves only about
0.12 GiB of sampled HBM headroom for that one geometry.

An attempt to move the writer lookup-input slab to host memory before its
first write, while retaining the 5% coefficient-tail policy, failed during
constraint evaluation with CUDA allocation status 2 at **31.355 GiB** sampled
device use. The lookup slab shares physical arena space with later work; this
policy did not create usable headroom at the critical phase. The opt-in code
was discarded and the failed receipt is under
`rtx5090-lookup-host-coeff5/`.

A later opt-in trial kept the fixed preprocessed tree's leaf half on device
and hosted its upper half. It reduced preprocessed commitment from **1.72 s**
to **1.09 s**, but the 5.34M-step PIE then failed in constraint evaluation at
**31.356 GiB** sampled device use. Its receipt is under
`rtx5090-five-m-tree-tail50/`. The failed policy code was removed; a bounded
commitment/tree representation is needed to obtain this hashing gain without
spending the scarce HBM at the later constraint stage.

Spilling the last **5% of interaction evaluations** in addition to the 5%
coefficient tail produced the same exact proof and passed the independent
Rust verifier, but took **12.880 s** input-to-publication and still peaked at
**31.242 GiB**. It is dominated by the simpler 11.816 s median policy: the
extra host placement slowed the proof without reducing its sampled peak.
The receipt is under `rtx5090-eval-tail5-coeff5/`.

On the 4.00M-step PIE, reducing the hosted preprocessed-tree fraction from
the profile's 75% to 25% yielded **8.234 s** publication with the same exact
proof and Rust verdict, versus 8.776 s for the profile. But sampled GPU use
rose to **31.355 GiB**, essentially the entire 31.36 GiB usable device. The
0.54 s gain does not justify that capacity risk as a default. The receipt is
under `rtx5090-medium-merkle-head25/`.

## Reclaiming the CUDA pool between proof families

The integrated two-leaf batch originally took 51.598 s because the second
Cairo proof-and-decode phase rose to 24.817 s. The context's async pool has a
high release threshold, so freed circuit arena pages stayed reserved. The
compact profile now synchronizes completed frees and trims the pool when it
evicts a prepared arena between Cairo and circuit proof families. The measured
transition returned **28.15 GB** of unused pool reservation; the second Cairo
proof-and-decode phase fell to **11.586 s**. CUDA's [stream-ordered allocator
contract](https://docs.nvidia.com/cuda/cuda-runtime-api/cuda_runtime_api/group__CUDART__MEMORY__POOLS.html)
specifies that a trim releases safely unused pool pages after asynchronous
frees are observed by the host. This change is limited to the opt-in compact
device profile; larger GPU paths keep their existing reuse policy.

| Complete two-PIE→root mode | Full command | GPU peak | Root proof, outputs and packed tree |
|---|---:|---:|---|
| Integrated batch before pool trim | 51.598 s | 31.36 GiB | exact H200 match |
| Integrated batch with pool trim, run 1 | **38.082 s** | **30.742 GiB** | exact H200 match |
| Integrated batch with pool trim, run 2 | **38.848 s** | **30.742 GiB** | exact H200 match |
| Integrated batch, cleaned final source | **38.381 s** | **30.742 GiB** | exact H200 match |
| Separate processes with pool trim | 42.194 s | 30.742 GiB | exact H200 match |

The batch median of the three runs is **38.381 s**, about **2.52×** the saved
H200 15.252 s full command, subject to the historical-source caveat. It is
about **25% faster** than the old 51.598 s batch and **10% faster** than the
separate-process 42.563 s result. The exact final root hashes remain
`9093f941c4a9144fd653441c582cc0921bac8431df8df46bdd556b8e661af724`
for the proof, `abaefd94d716e2e4f07b5a2fcd521764e5d4c0f8dd04ec60e095bf74d0e1349b`
for outputs, and `72f17bf582e5438defd30e2f3c52f87ff47e5d6f0d1223b98d37bac8007c54a2`
for the packed tree. Receipts and phase logs are under
`pipeline5090-two/pool-trim/`.

The compact batch now retires verified fixed-storage slots at their actual
last use because its Cairo arena is explicitly evicted before the circuit
leaf. This removed 2.17 GB from each small-leaf arena plan without changing
the root. With the prior 25% main-coefficient spill, the full batch took
**38.918 s** at **28.615 GiB** sampled peak. Reducing that spill to 5% for
these smaller plans then gave **34.779** and **34.855 s** on two otherwise idle
5090 runs, with **28.865 GiB** peak in both. Their Cairo leaf proof-and-decode
times were 10.525/10.128 s and 10.508/10.214 s respectively. All three root
hashes match the saved H200 root exactly. The new two-run median is
**34.817 s**, **2.28×** the historical H200 full command and **9.3% faster**
than the prior pool-trim median while using **1.877 GiB less** sampled HBM.
These are still cross-source hardware ratios. Receipts, leaf stage reports,
and complete logs are under `pipeline5090-two/transient-static/` and
`pipeline5090-two/transient-static-coeff5/`.

The next same-binary experiment kept a progressively larger upper portion of
each trace Merkle tree on the GPU. The hosted fraction applies to the head of
each tree. Every successful run below has the same wrapped-leaf hashes and the
same exact root proof, outputs, and packed-tree digests. The CUDA-reported
usable memory was 31.36 GiB.

| Hosted trace-tree fraction | Full two-PIE→root command | GPU peak | Measured headroom |
|---:|---:|---:|---:|
| 100% | 34.779, 34.855 s | 28.865 GiB | 2.49 GiB |
| 90% | 33.184 s | 29.615 GiB | 1.74 GiB |
| 85% | 32.592, 32.981 s | 30.117 GiB | 1.24 GiB |
| 80% | 32.133 s | 30.492 GiB | 0.87 GiB |
| 75% | 31.558, 31.524 s | 30.867 GiB | 0.49 GiB |

The 85% two-run median is **32.786 s**, or **2.15×** the historical H200
15.252 s command, and leaves materially more room than the 75% fast edge.
The 75% median is **31.541 s** but is a narrow-capacity research point. The
compact profile selects 85% by default only for the tested sub-35-GiB arena
range with transient static storage; retained-cache sessions keep the earlier
conservative placement. Larger plans retain the fully hosted trace-tree
policy. Detailed
receipts are under `pipeline5090-two/measure-transient-hash*/` and
`pipeline5090-two/output-transient-hash*/`.

Building the entire hash tree on the GPU and moving it to host memory *after*
each commitment produced the exact root in **31.009 s**, but reached
**31.355 GiB**, essentially the card's entire reported capacity. A hybrid
that hosted 25% before commitment and migrated the rest afterward also
matched the root, but took **33.731 s** and hit the same capacity limit.
Late managed-memory migration did not provide usable headroom here. Both
opt-in variants were removed from the implementation; their receipts remain
under `pipeline5090-two/*postcommit*/` and `pipeline5090-two/*hybrid25*/`.

Early pipeline `process_rss_peak_bytes` values sampled only the Python
launcher, so they must not be read as prover host-memory measurements. The
measurement script now sums the launched process tree and labels that scope
in new receipts. For the second 85% run this measured **14.72 GB** peak RSS;
its **30.117 GiB** whole-device GPU peak is independently sampled by NVML.

The registry-bound geometry tool now has `--transient-static`, which plans the
same shortened fixed-slot lifetimes as an integrated compact leaf. For the
first pipeline PIE it reports **37,257,364,800 bytes**, exactly matching the
prover receipt, instead of the retained-cache **39,429,769,536-byte** plan.
The partition planner accepts `--managed-arena-limit-bytes` with these
explicitly marked transient receipts; it no longer has to pretend a managed
arena must fit under `device_bytes - reserve_bytes`. For example:

```sh
zig build cairo-trace-geometry cairo-pie-construction-plan -Doptimize=ReleaseFast
STWO_CAIRO_CUDA_PREPROCESSED_VARIANT=canonical zig-out/bin/cairo-trace-geometry \
  --circuit-registry vectors/circuit/official/registries/production.json \
  --artifact-dir vectors/cairo --transient-static --jsonl input-a.cpi input-b.cpi \
  > geometry.jsonl
zig-out/bin/cairo-pie-construction-plan \
  --candidates candidates.json --geometry geometry.jsonl \
  --circuit-registry vectors/circuit/official/registries/production.json \
  --device-bytes 33668988928 --managed-arena-limit-bytes 37580963840
```

The example 35-GiB managed-arena limit is a conservative planning screen for
the observed small-leaf cohort, not a proof that every PIE below it will fit
or meet the time target. The planner still marks its result
`proof_qualified: false`; measured whole-device peaks and exact proofs remain
the admission evidence. The two test PIEs generated matching geometry
receipts locally, and a one-candidate planner smoke check selected the
transient receipt under this limit; non-transient geometry was rejected by
the managed planner.

### Final default compact policy and two-leaf pipeline

The cleaned final-source default was then built in ReleaseFast for SM 120
and measured on the otherwise idle 5090. Each standalone proof below had
its expected exact SHA-256 and passed the pinned independent Rust verifier.
The two-PIE pipeline matched the saved wrapped-leaf and final-root hashes.

| Final default workload | Input→proof publication | Proof and decode | Full command | Whole-device peak | Historical H200 input→publication ratio |
|---|---:|---:|---:|---:|---:|
| EC-heavy 2.81M-step PIE | 8.848 s | 5.109 s | 9.786 s | 28.365 GiB | 2.11× |
| Pedersen-heavy 3.60M-step PIE | 9.227 s | 5.487 s | 10.344 s | 29.992 GiB | 1.85× |
| 4.00M-step PIE | 9.028 s | 5.242 s | 10.053 s | 29.490 GiB | 1.95× |
| 5.34M-step PIE | 16.351 s | 12.610 s | 17.560 s | 30.617 GiB | 3.20× |
| Two distinct small PIEs → one root | — | 9.374 / 9.389 s Cairo leaves | **32.688 s** | **30.117 GiB** | **2.14× full command** |

The 4M standalone still selected a managed arena; shortening static slot
lifetimes did not make that geometry a device-only proof. The pipeline's
corrected process-tree peak RSS was **14.72 GB**. Its two Cairo leaf ingresses
were 3.252 and 1.681 s, while the circuit wraps and fold were included in
the 32.688 s full command. Receipts are under `rtx5090-*-final-default/`
and `pipeline5090-two/measure-final-default-r1/`. The historical H200
source/timing caveat applies to every ratio in this table.

The small pipeline's arena inventory still holds four 4.295 GB trace Merkle
trees through decommitment. A sparse authenticated-tree representation is
therefore a larger potential memory and speed change than another percentage
adjustment to managed placement; its opening paths must be reconstructed and
verified exactly before adoption.

For the standalone 5.34M-step PIE, the transient plan is 35.11 GiB. With
all trace trees hosted, a 15% coefficient-tail spill published in **14.110 s**
at **30.992 GiB** peak; the 5% tail published in **11.881 s** at
**31.242 GiB** peak. Both match the expected proof SHA-256 and pass the pinned
Rust verifier. The faster 5% point has only about 0.12 GiB of sampled HBM
headroom. The default in the 35–37 GiB plan range keeps its 25% spill while
placing it at the tail, which improved the earlier same-geometry receipt
without consuming additional HBM. The optional percentage and placement
controls retain the faster research points for explicit use.

A four-leaf **synthetic stress case** repeated the two distinct small PIEs in
the order `[A, B, A, B]`. This is not a contiguous block chain or a new
four-PIE production claim. The cleaned final source completed all four Cairo
proofs, four leaf wraps, and three recursive reductions to one root in
**71.769 s** full command, with **30.744 GiB** sampled whole-device peak.
Each transition released about **28.15 GB** of unused pool reservation; the
four Cairo proof-and-decode stages were **12.526, 11.666, 12.399, and
11.575 s**. The three fold reductions took **2.801 s** total. This tests
bounded memory across repeated Cairo/circuit transitions, not equivalence to
an independent H200 root for this synthetic input. The case definition,
receipt, phase logs, and memory samples are retained under
`pipeline5090-four-synthetic/`; the generated proof files remain on the
benchmark host and are excluded from the repository.

The same synthetic pattern extended to **eight leaves** (`[A, B]` repeated
four times) completed in **138.773 s**, with **30.744 GiB** sampled peak. All
eight Cairo proofs and wraps completed; seven recursive reductions took
**6.327 s** and produced one root. This is a longer memory-lifetime test,
not a contiguous eight-PIE workload or an H200-relative speed measurement.
Its case and receipts are under `pipeline5090-eight-synthetic/`.

## Static-cache lifetime experiment

A labeled arena inventory on the 5.34M-step PIE confirmed that the following
immutable process-cache slots were reserved through proof assembly, although
the authenticated plan gives shorter in-request last-use stages:

| Slot | Bytes | In-request last use | Previous physical lifetime |
|---|---:|---|---|
| Fixed coefficients | 2.172 GB | OODS | proof assembly |
| Fixed evaluations | 4.345 GB | decommit | proof assembly |
| Fixed Merkle hashes | 4.295 GB | decommit | proof assembly |
| Forward and inverse twiddles | 0.268 GB total | FRI commit | proof assembly |

The inventory proof still matched its exact reference SHA-256 and passed the
independent Rust verifier. Its receipt is under `rtx5090-slot-kind-diagnostic/`.
The large-slot dump is now opt-in via `STWO_CUDA_ARENA_SLOT_DIAGNOSTIC=1`,
so routine proving does not print that inventory for every PIE.
The [problem-match brief](../../../autoresearch/notes/20261008-005303-rtx-5090-compact-cairo-static-liveness-problem-match.md) explains
why only the compact recursive leaf boundary can shorten these physical
lifetimes: it explicitly evicts the Cairo arena before every circuit wrap.
Other sessions must retain the process-cache contract. The compact-leaf
implementation passed the complete two-leaf exact-root check: planned arenas
fell from **39.430 and 39.021 GB** to **37.257 and 36.849 GB**. Full time was
**38.918 s** and sampled whole-device peak **28.615 GiB**, versus **38.381 s**
and **30.742 GiB** for the preceding final-source pool-trim run. The proof,
outputs, and packed tree matched the H200 reference byte for byte. This is a
**2.127 GiB device-peak reduction** with essentially unchanged time; receipts
are under `pipeline5090-two/transient-static/`. The next experiment uses the
recovered capacity to keep more main coefficients in HBM.

## Dense final-source profile and remaining architecture gap

The cleaned final source also reproduced the 20.85M-step dense PIE on the
167 GB host. Its proof SHA-256 was again
`fcc457fee3bcaca85efd97d308daa1a16e849c633b4571144417543158eb1eeb`,
and the pinned independent Rust verifier returned `verified: true`. It took
**314.100 s** for proof execution and decode, **318.230 s** from adapted
input to publication, and **322.715 s** for the full command. The measured
whole-device peak was **27.242 GiB**; the process-tree host RSS peak was
**67.548 GB**. This is about **20.8×** the historical H200
input-to-publication result, well outside the 4.5× economics target. The
H200 receipt uses earlier source, so this ratio is a research screen rather
than a controlled hardware comparison.

| GPU proof stage | Elapsed time |
|---|---:|
| Trace generation | 54.872 s |
| Preprocessed and main commitments | 7.027 s |
| Relation generation | 137.092 s |
| Interaction commitment | 4.626 s |
| Constraint evaluation | 93.961 s |
| OODS, quotient, FRI, and decommit | 16.523 s |

The receipt includes a one-second `nvidia-smi dmon` timeline. Approximate
stage-aligned windows show mean PCIe receive/transmit rates of **1.43/2.02
GB/s** during relation generation and **2.87/2.19 GB/s** during constraint
evaluation. The alignment is within a few seconds because the device samples
and proof-stage timer use separate clocks. This is strong evidence that
managed-memory traffic dominates the two long stages; it is not a kernel-level
attribution. The proof report's explicit host-to-device copy counter covers
only commanded copies, so it does not account for the managed-memory traffic
visible in the device timeline. The exact receipt and sampled timeline are
under `rtx5090-dense-final-profile/`.

The retained full Merkle-tree hashes are an actionable architecture target.
`resident_plan.zig` keeps every trace tree from commitment through
decommitment. At the dense geometry, the fixed tree reserves **4.295 GB** and
each of the three request-dependent trace trees reserves **1.074 GB**. The
generic CUDA decommit API already supports unretained bottom
layers and sparse parent assembly, but Cairo's `openTrace` currently passes
zero unretained layers and empty sparse buffers. A correct sparse-retention
implementation would keep authenticated upper layers, regenerate only sampled
lower subtrees from the still-retained evaluations after query sampling, and
assemble the same opening paths. It requires a sampled mixed-height leaf-hash
kernel, bounded sparse buffers, revised arena lifetimes, and exact-root/proof
tests across all tree roles. No sparse-retention speedup is claimed here;
discarding hashes without that reconstruction would break verification.
The [dense working-set problem match](../../../autoresearch/notes/20261008-020915-rtx5090-dense-cairo-working-set-problem-match.md)
sets out the full time budget and the bounded-stage redesign implied by it.

The following same-input, same-device placement trials all produced the exact
proof hash above and passed the pinned Rust verifier. `eval host` is the
preferred-host fraction of the 20.864 GB interaction-evaluation slot; the
remaining pages were left to the driver's ordinary placement policy. These
are one-shot research points, not qualified production defaults.

| Placement | Input→publication | Relation | Constraint | Device peak |
|---|---:|---:|---:|---:|
| Interaction coefficients in HBM, other capacity slots hosted | 318.230 s | 137.092 s | 93.961 s | 27.242 GiB |
| Same, 85% eval host | 316.911 s | 135.893 s | 94.668 s | 27.242 GiB |
| Fixed tree host, 85% eval host | 314.517 s | 134.508 s | 93.236 s | 23.240 GiB |
| Fixed tree host, 50% eval host | 317.121 s | 135.865 s | 93.645 s | 23.240 GiB |
| Fixed tree host, 70% eval host, prefetch remaining 30% to GPU | **298.134 s** | 138.238 s | **71.264 s** | 29.117 GiB |
| All three trace trees host, 60% eval host, prefetch remaining 40% to GPU | **287.082 s** | 137.177 s | **60.808 s** | 30.115 GiB |
| Same policy, independent repeat | **287.166 s** | 135.646 s | **62.588 s** | 30.115 GiB |
| Half of writer scratch hosted, all trees hosted, 90% eval hosted, 10% prefetched | **278.038 s** | 135.921 s | 85.753 s | **28.367 GiB** |
| Half of writer scratch hosted, all trees hosted, 80% eval hosted, 20% prefetched | **274.577 s** | 138.168 s | **79.629 s** | 30.362 GiB |

Hosting the fixed tree saved exactly **4.002 GiB** of sampled GPU peak at a
roughly one-second fixed-commitment cost. It raised host RSS by about 4.3 GB.
Changing the unhinted evaluation fraction from 15% to 50% did not increase
sampled HBM use or improve constraint time, so hints alone did not keep
those pages resident. Explicit prefetch was then tested before the
interaction commitment. The first four receipts are in
`rtx5090-dense-final-profile/`,
`rtx5090-capacity-eval85/`, `rtx5090-capacity-tree-eval85/`, and
`rtx5090-capacity-tree-eval50/`, respectively.

Explicitly prefetching the 50% remainder filled the card to **31.355 GiB**
and failed during constraint evaluation with CUDA allocation status 2. The
30% remainder avoided that failure, matched the exact proof SHA-256, passed
the pinned Rust verifier, and reduced input-to-publication time by **6.3%**
against the dense baseline. Its receipt is under
`rtx5090-capacity-tree-eval70-prefetch/`; the failed 50% receipt is under
`rtx5090-capacity-tree-eval50-prefetch/`. This still leaves the dense case
about **19.5×** the historical H200 publication time, so it is a research
Pareto point, not a claim that the 5090 economics target is met.
Its measured process-tree host RSS peak was **71.79 GB**, so a 64 GB host
would not qualify this out-of-core dense policy even though the device peak
fits. The earlier 62 GB-cgroup pod failure is consistent with that limit.

The composed all-tree-host policy traded the two additional 1.074 GB trace
trees for another 2.086 GB of interaction evaluations in HBM. It reduced
constraint evaluation to **60.808 s** and publication to **287.082 s**, an
overall **9.8%** reduction from the dense baseline, with an independently
verified exact proof. Its peak was **30.115 GiB** of device memory and
**72.86 GB** process-tree RSS, leaving only about 1.24 GiB of measured HBM
headroom. The receipt is under `rtx5090-capacity-alltrees-eval60-prefetch/`.
The independent repeat under `rtx5090-capacity-alltrees-eval60-prefetch-r2/`
produced the same proof SHA-256, passed the pinned Rust verifier, and measured
287.166 s from input to publication. The two-run median is **287.124 s**;
sampled GPU peaks were both 30.115 GiB, and process-tree RSS was 72.86 GB
in both runs. This confirms the narrow Pareto gain without resolving the
large remaining H200 gap.
The half-hosted writer-scratch point under
`rtx5090-capacity-writer50-alltrees-eval90prefetch/` cut trace generation
from 55.404 to **21.757 s**. Its constraint stage rose from 60.808 to
85.753 s, but total publication still fell to **278.038 s** while sampled
HBM use fell by **1.748 GiB**. Its proof SHA-256 matched exactly and Rust
verification passed. The recorder omitted the new writer-scratch policy key
from this first run's summary; the exact operator-specified value is preserved
in its `policy-env-supplement.json`, and later trials record it directly.
This point is opt-in pending a repeat and other-geometry qualification.
Keeping the same writer placement and prefetching 20% of the interaction
evaluations passed the pinned Rust verifier with the same proof SHA-256. It
published in **274.577 s**, another 3.461 s faster, with a **30.362 GiB**
sampled device peak; see `rtx5090-capacity-writer50-alltrees-eval80prefetch/`.
Prefetching 30% with the same writer placement reached **31.189 GiB** sampled
device use and failed in constraint evaluation with CUDA allocation status 2;
its receipt is under `rtx5090-capacity-writer50-alltrees-eval70prefetch/`.
There is no proof or time result for that failed point.
The best of these points still takes about **17.9×** the historical H200
publication time; the
large-PIE working-set redesign described above is still required.

## Pedersen-heavy 22.67M-step single-block stress

The pre-existing H200 extreme-PIE fixture `15590913_15590913` contains
**22,673,315 OS steps** in one block and **217,608 Pedersen operations**.
Its adapted CPI is 443,939,388 bytes with SHA-256
`9d503fa0c6c818d8de84d3d71208df641bb62ec93e480687252128f698294bc3`.
The first, conservative 5090 capacity run produced the exact expected proof
SHA-256 `23ef11f1f7bbf0b31d6ede197bd67d2548975b951283c4cedc0fb6148e443af9`
and passed the pinned Rust verifier. It took **423.597 s** from adapted input
to publication, **429.487 s** full command, and peaked at **18.740 GiB**
whole-device GPU memory and **98.11 GB** process-tree RSS. Its receipt is
under `rtx5090-pedersen22m-capacity-safe/`.

The safe placement took **177.835 s** in relation generation and **137.326 s**
in constraint evaluation. The saved H200 publication time for the same PIE
is **8.755 s**, a historical-source comparison of about **48.4×**; the
requested 4.5× ceiling would be **39.398 s**. One-block geometry rules out
repacking at block boundaries. This run establishes correctness and capacity,
not economic viability. The following same-input trials test partially
resident interaction coefficients.

Hosting only 25% of the 12.57 GB interaction-coefficient slot before its
first write produced the same exact proof and passed the Rust verifier. It
reduced interaction commitment from **26.661 to 15.591 s** and constraint
evaluation from **137.326 to 76.527 s**. Publication fell to **347.795 s**,
or **17.9%** below the safe baseline, with **27.492 GiB** device peak and
**88.68 GB** process-tree RSS. The complete receipt is under
`rtx5090-pedersen22m-interactioncoeff25/`. This is a verified, opt-in Pareto
point, still about **39.7×** the saved H200 publication time.
Hosting only 1% of the slot improved the same exact proof again: interaction
commitment **6.633 s**, constraint evaluation **61.504 s**, publication
**320.338 s**, and full command **325.932 s**. The peak rose to
**30.362 GiB** of GPU memory with **85.66 GB** process-tree RSS. The proof
SHA-256 matched and the pinned Rust verifier passed; see
`rtx5090-pedersen22m-interactioncoeff1/`. This is **24.4%** faster than the
safe 5090 baseline but still **36.6×** the historical H200 publication time.
Its roughly 1 GiB sampled device headroom and large host requirement make it
a research Pareto point, not a production default.

The [512-PIE campaign step inventory](h200-campaign-512-pie-step-sizes.csv)
was extracted from the H200 proving-service campaign's `pie_analysis.csv`
(source SHA-256
`2731237cccb1b1375d66f6c1cd2c632e37b3945d624861b0b928db0006679d68`).
Only **21/512 PIEs (4.1%)** have at most 5.34M OS steps, and **75/512
(14.6%)** have at most 10M. All **300 single-block PIEs** in that campaign
have at least 10M steps. The median is **20.266M steps** and the largest is
**24.974M**; thus the measured 20.85M-step dense PIE is close to the campaign
median rather than an outlier. The 21 small PIEs represent only **0.74% of the
campaign's 8.856 billion OS steps**. Step count is only one feature of geometry, so
these are upper bounds on coverage by the currently qualified small-PIE
5090 regime, not an admission classification for those exact 512 inputs.
Block-boundary repacking cannot make the 300 single-block PIEs smaller. The
economic large-PIE path needs a genuinely bounded working set or a different
segmentation boundary with its own proof soundness argument.

## Final-source regression

After the transient-arena policy was included in the prepared proof-session
identity, a fresh CUDA build again proved the first 1.22M-step PIE with the
exact expected proof SHA-256 and a passing independent Rust verifier verdict.
Its adapted-input-to-publication time was **3.481 s**, proof execution and
decode **0.353 s**, full command **4.083 s**, and whole-device peak
**24.926 GiB**. The receipt is under `rtx5090-final-source-smoke-small2/`.
The same build proved both distinct Cairo leaves, wrapped them, and produced
the exact saved two-leaf root proof, outputs, and packed hashes in **32.675 s**
full command with **30.117 GiB** whole-device peak and **14.73 GB** process-tree
RSS. Its receipts are under `pipeline5090-two/*final-source-v2/`. The root is
the actual recursive proof produced by the circuit product, and its proof,
outputs, and packed-byte hashes match the saved reference fixture exactly.
After the final opt-in capacity controls were added, the same default
two-leaf pipeline was rerun once more: **33.197 s** full command,
**30.117 GiB** whole-device peak, **14.73 GB** process-tree RSS, and the
same leaf/root/output/packed hashes. Its latest-source receipts are under
`pipeline5090-two/*final-source-v3/`. This is the final default-path
regression check; the opt-in dense placement trials above use separate
policies.
