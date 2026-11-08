# CPU-first OP continuation on Apple M5 Max

The [unit-weight/ownership qualification](recursion-m7-unit-owned.json)
still reproduces all five M7 physical proofs and passes fresh strict reception.
Each unit specialization checks the actual immutable numerator array before
using the existing singles kernel; changing one weight selects weighted work.
Constant numerator contributions are hoisted from the binding projection.
M7 also transfers INTER once through the explicit monolithic PCS API. The
full wrapper failure/retirement and physical corruption suite passes.

The single qualification takes 38.143 s with 3.710 s fresh reception. Repeated
trials have substantial drift and do not establish another complete-root
speedup or an RSS reduction; the final control tail also overlaps a short
compiler/test. Per-proof GKR metrics now split tree construction and sumcheck
and record specialized facts. Layer bytes exclude inputs and other owners and
must not be summed into a peak RSS estimate.

The [direct-load kernel probe](rejected-om31-direct-load.json) also preserves
all transcripts but gives no useful gain. That source experiment is reverted.

The [joined CPU-wave comparison](recursion-m7-joined.json) reduces M7's
cyclic binding construction from 6.083 to 1.613 s and composition from
11.782 to 9.097 s summed over four outer proofs. Four cold interleaved trials
give complete recursion medians of 47.989 and 42.194 s. Every physical proof
file remains identical and every separately started strict receiver accepts.
Native proving is additional. There are only two trials per variant; M7
remains opt-in and does not beat the best M6 result.

Binding workers write logical scan chunks and then contiguous physical rows,
avoiding bit-reversed scatter false sharing. Public auxiliary columns share
one forward twiddle tower and the existing pooled FFT. The packed GKR route
also reuses the caller's bounded pool without private helper pools. It is
transcript-identical, but its GKR stage itself regresses from 8.800 to 9.579 s
here; this is an open optimization, not a claimed GKR speedup. Allocation
injection found two nested-owner cleanup leaks in the existing fast prover;
both are fixed and the complete allocation-failure sweep now passes.

The [M7 packed-polynomial comparison](recursion-m7-polynomial.json) separates
base-field nodes from full octic nodes, precomputes parameter-only expressions,
and binds validated reads once per component. All five real execution-root
proof files remain identical and every fresh receiver accepts. Four interleaved
cold trials show a modest composition reduction, but less than one percent
change in median complete-root wall time. This is not a major speedup and M7
remains opt-in. Per-component counters now distinguish public auxiliary FFTs,
metadata preparation and row evaluation without changing receiver authority.
The focused test target is `test-riscv64-outer-gkr-cpu-polynomial`.

The [default R1 regression](recursion-r1-aot-parity.json) also reproduces all
six original recursive proof files byte-for-byte, with fresh strict reception.
Its 56.960 s production is a qualification run with build activity and a changed
worker count, rather than a controlled comparison with the original 191 s.

The [compiled OM31 evaluator A/B](recursion-aot.json) replaces domain bytecode
dispatch with eight-coordinate C kernels generated from the same hash-pinned
AIR. Four cold real-root trials preserve all physical proof bytes and pass
separate receivers. Composition medians are 8.016 s for the SIMD interpreter
and 5.740 s compiled; recursion production medians are 37.194 s and 34.685 s.
There are two trials per variant and observable drift over trial order, so this
is a limited interleaved comparison. Native proving is additional. The ~19 s
recursion target remains open; no whole OP validity or 10x claim is made.

Read geometry and coefficients are bound once per component, shared by bounded
row workers, and freed before the phase returns. Both octic interaction halves,
cyclic offsets, three source lifts and additive tiling match the scalar oracle.
Every metadata allocation failure and invalid-source path releases its owners.
The scalar OODS receiver is unchanged, as are all eleven generated quartic C
kernels. Missing registered programs use the existing SIMD interpreter;
`STWO_CIRCUIT_OM31_INTERPRETER=1` selects the control for qualification. The
compiled domain route is enabled on the qualified AArch64 host only. M7's
separate receiver-derived hybrid IR is not silently routed through these kernels.

The subsequent [OM31 SIMD inversion A/B](recursion-packed-inverse.json)
preserves all recursive proof bytes. Interaction generation medians decrease
from 9.155 s to 7.731 s; four cold trials do not establish an end-to-end wall
speedup. No extra heap scratch is introduced and QM31 dispatch is unchanged.

The [ownership qualification](recursion-owned-monolithic.json) transfers raw
INTER columns to PCS while retaining its parallel monolithic commitment.
Peak RSS is 27.344 GiB versus 31.640 GiB in the control, with identical proof
bytes and a separately started strict receiver. Production takes 38.790 s with
guest compilation active, so this is qualification, not a quiet benchmark.
The new API is explicit; default PCS scheduling is unchanged. Mixed-height,
129-column parity and injected allocation failures cover the ownership move.
The [rejected automatic-streaming A/B](rejected-owned-streaming.json) records
why ownership and batching must be independent: 64-column streaming doubled
INTER commit time despite the same memory saving. That policy is not adopted.

## Controlled CPU M6 versus M7 qualification

The [six cold trials](recursion-m7-cpu.json) compare the same complete native
D2 execution of block 120794432, with 16 proof workers and independently pinned
receiver policies. Native proving is excluded from these recursion timings.

| Outer construction | Production median, three trials | Fresh receive median | Root bytes |
| --- | ---: | ---: | ---: |
| M6 classic LogUp | 41.716 s | 3.860 s | 745,400 |
| M7 hybrid LogUp/GKR | 50.943 s | 3.743 s | 731,620 |

M7 now has a complete CPU producer for the existing M7 wire and receiver; it
remains explicit opt-in because it is slower here. Each trial builds all three
leaves and one fold from scratch, with no restored proofs. Every independent
receiver accepts the pinned OP output, and proof bytes match across all three
trials of each profile. A corrupted leaf, coherently corrupted root/final fold,
and swapped child order reject in fresh M7 receivers. This remains an execution
root, with `security_qualified=false`, rather than anchored OP validity.

The new producer uses bounded SIMD late projection and composition, retains the
same GKR authority and transcript, and requires host setup. A balanced false-fact
test preserves the rational lookup sum but fails MAIN binding. The lifecycle
tests cover callback failure, wrapper failure, serialization, restoration and
retirement under an explicit live-allocation budget. They found and fixed a
528-byte per-child verifier-metadata leak at both callers. The native public
auxiliary bound remains 22; the outer uses its independently admitted bound 28.
Earlier geometry failures and shutdown-aborted runs are recorded as failures,
not included in the successful cold-run medians. No production default changes.

The [qualification receipt](qualification.json) records two complete native OP
Mainnet execution proofs from a rebuilt canonical GLV guest, plus the first
successful full synthetic ordered application fold on this machine. These are
qualification runs with compilation or other tests potentially active, not quiet
benchmark medians or a measured speedup over another prover.

| OP Mainnet block | Instructions | CPU / service proofs | Production wall | Fresh receive wall | Production peak RSS |
| --- | ---: | ---: | ---: | ---: | ---: |
| 120794432 | 796,520 | 1 / 2 | 6.995 s | 1.312 s | 3.662 GiB |
| 121057303 | 5,928,533 | 6 / 7 | 34.606 s | 3.665 s | 4.932 GiB |

Both cases match the independent native Kona output and Unicorn machine/service
oracle. Each fresh native receiver rebuilds authority and accepts the full
bundle, then rejects physical CPU proof corruption both before and after the
transport hash is recomputed. The request uses 1,048,575-step batches, eight
proof workers and two setup builders; the receiver uses four setup helpers and
12 GiB requested-live admission. Geometry, exact commands, profiles, hashes and
per-child wall/user/system/RSS data are in the receipt. The host has 64 GiB RAM.
Guest/build/proof products are retained outside the source checkout.

The native profile remains `conjectured128_b2_q108_p20_fold4` with
`security_qualified=false`. No proof parameter or Ethereum engine code changed.
The corrected resource collector interprets macOS RSS as bytes and Linux RSS as
KiB; old receipts have not been silently rewritten.

The synthetic public-fold fixture builds two actual child STARKs over fixed
OD/OP public values and a parent STARK, reconstructs its authority without
assignments, verifies the encoded parent, and rejects output mutation and swapped
roles. It completed with 22,544,384 circuit variables and a 706,584-byte root
under a 32 GiB requested-live budget. This qualifies the fixture's physical
folding path, not Kona derivation, a real OP recursive root or settlement.

## Real Mainnet execution root

The subsequent [physical recursion receipt](real-recursion.json) closes the
execution-only root for block 120794432: three native children wrapped into
three OM31 circuit STARKs and two binary folds, then accepted by a separately
started, assignment-free receiver. Production took 191.121 s at 30.118 GiB
peak RSS; fresh reception took 6.403 s at 6.714 GiB. The root is 746,584 bytes.
The outer profile is `r1_b2_q108_p20_fold4`, with 40 GiB requested-live
production admission and 24 GiB receiver admission. No GPU was used.

The recursion timing is additional to the roughly 7 s native proof. The saved
root report attributes 111.718 s to wrapping three children and 76.842 s to
two binary folds. Those wrappers have 28,034,346, 24,455,291 and 25,970,601
variables. This is the CPU `r1_b2_q108_p20_fold4` correctness path; it is not
timing parity with the newer Ethereum device recursion configuration.

Inspection found that the CPU domain interpreter evaluated base-field AIR
arithmetic with scalar octic values. Its replacement keeps base arithmetic in
native-width packed M31 and extension arithmetic in packed OM31, with the
scalar OODS verifier unchanged. Qualification must preserve the physical
8-coordinate interaction lens and every saved proof byte. The existing native
D2 construction is also exposed for explicit operator-selected qualification;
its fewer openings are a separate experiment, not an established OP speedup.

The [SIMD qualification receipt](recursion-simd.json) reproduces all six saved
proof files byte-for-byte and passes a separately started strict receiver.
Production took 136.427 s with 846.785 user CPU seconds; fresh reception took
7.715 s. A heavy OP proof was running concurrently, so this is qualification
evidence and an indicative timing, not a controlled speedup measurement. The
focused AIR, physical mutation and serial/2-worker/3-worker proof parity suites
also pass. The full timing remains too high to call this route optimized.

The subsequent [D2/M6 qualification](recursion-d2-m6.json) uses the existing
native `d2_native_b4_q54_p20_fold4` construction and outer
`m6_outer_diet_k4_cap3_r1_b2_q108_p20_fold4_v1` profile. It wraps the same
complete OP execution into three leaves and one three-child fold, taking
62.614 s at 31.623 GiB peak RSS, with 4.616 s fresh reception. Its internal
report attributes 37.953 s to wrappers and 22.422 s to folding. The strict
receiver pins both profiles independently and accepts; corrupted leaf, coherent
root/fold corruption, and swapped child order reject. This changes the proof
construction, so expected-output/closure parity replaces proof-byte parity
against r1. Native D2 proving took 8.674 s, fresh native reception 2.083 s.

These are single-run qualification timings, not quiet medians. The D2-only
binary-fold trial used four proof workers and took 133.952 s; the M6 trial uses
eight workers. The original baseline also used eight. Combined improvements
are not independently attributed. The ~3x reduction from the original 191 s
recursion still falls well short of the requested 10x improvement; defaults
and the security qualification flag remain unchanged.

The [field-shape and worker qualification](recursion-field-shapes.json)
further reduces the same D2/M6 root from 65.643 s (instrumented packed control)
to 58.268 s with field-shape specialization at eight workers, and 38.015 s at
16 workers. Every trial preserves all five recursive proof files byte-for-byte;
fresh strict receivers accept. The 16-worker native harness also produces all
three native proof files byte-identically and rejects both corruptions. The
Python tools now allow the native engine's existing 1..32 proof-worker range;
setup concurrency retains its separate 1..8 bound. Defaults are unchanged.

| Summed outer proving stage | Packed, 8 workers | Field shapes, 8 workers | Field shapes, 16 workers |
| --- | ---: | ---: | ---: |
| MAIN commit | 5.52 s | 5.43 s | 3.39 s |
| Interaction witness | 12.63 s | 12.22 s | 8.84 s |
| Interaction commit | 12.28 s | 12.04 s | 7.31 s |
| Composition | 18.99 s | 12.23 s | 7.89 s |
| FRI quotient | 4.63 s | 4.61 s | 2.87 s |

These are single-run engineering qualifications. A compiler overlapped the
packed control and focused tests overlapped part of the 16-worker trial; they
are not quiet benchmark medians. CPU recursion is still about 38 s, not the
requested ~19 s (10x below the original 191 s). The remaining structural target
is interaction volume: the existing M7 hybrid path reduces classic interaction
columns from 304 to 128, but CPU production currently refuses it with
`HybridFactoryRequired` and its CPU domain component returns
`HybridResidentCompositionRequired`. Its CPU port requires authenticated GKR
inputs, late cyclic binding, a CPU domain evaluator, fresh recursive reception
and a measured end-to-end win; exposing the enum alone does not deliver it.

This is an exact-shape execution root, not a portable constant-key checkpoint,
an anchored derivation root, an OD/OP in-circuit join or complete settlement.
The 24 GiB baseline production attempt failed with `OutOfMemory`; it is retained
alongside the successful trial. A subsequent ownership-only experiment also
failed at that cap. The receiver rejects a corrupted leaf, corruption of both
the root and its final-fold copy, and reordered tree children. The first two
reach `RootMismatch`; the order mutation reaches `RecursiveReceiverArtifactMismatch`.

The [bounded-commit experiment](rejected-commit-experiment.json) reproduced all
six recursive proof files byte-for-byte, including the root, and passed the
strict independent receiver. It used 26.934 GiB peak RSS versus 30.118 GiB, but
took 224.141 s versus 191.121 s in these qualification runs. It also still
failed at the 24 GiB admission. It is **not landed**: the shared CPU prover is
unchanged. The small [experimental patch](rejected-bounded-commit.patch) is
evidence, not an active implementation or a speedup claim.

## Heavy block and redundant capture

The [heavy guest receipt](heavy-guest.json) reproduces 121065789 with the
canonical GLV guest and with its existing checked pairing-hint variant. Native
Kona and the independent oracle agree on the complete result. Instructions fall
from 621,480,160 to 425,537,671 (31.53%); Fp2 calls fall from 928,200 to 678,888
(26.86%). This is a guest-work reduction, not a measured proving speedup.

The first whole-block CPU attempt retained its failure: the 102-CPU / 24-service
roster requires a represented retained inventory of 51,853,871,529 bytes and was
refused under a 48 GiB component admission. Source planning took 124.693 s and
the refused producer 163.659 s. The [52 GiB retry](heavy-native.json) now
completes all 102 CPU and 24 service proofs. Production took 1,723.236 s
(28.72 minutes) at 46.932 GiB peak RSS; separate reception took 38.325 s.
Both corrupted-proof controls reject, including a changed proof with a
recomputed transport hash. This is complete native execution/service closure,
not derivation or recursion. Builds, tests and a small recursive proof overlapped
part of production; it is a qualification timing, not a quiet benchmark.

The Python producer no longer runs that extra standalone plan by default. Native
production already performs its source/geometry/resource admissions. `--plan-first`
restores the diagnostic census explicitly; the standard path captures once.
A first-native-command test pins both choices and complete-block request framing.

Validation: 39 OP Python tests; 93 CI planner/selection tests; 36 pinned Rust
execution/derivation/precompile tests. The actual new `opstack_python` CI lane
also passes from a fresh virtual environment. Explicit OP lanes prevent tooling
changes from triggering the unrelated Cairo/Metal fallback, while unknown files
and shared-engine changes retain their existing coverage. The first attempted
push hit that unrelated Metal AOT gate; the pre-commit source-layout failures
are also outside the changed files. Both exceptions are recorded in the receipt.

The [delivery checklist](../../../opstack/COMPLETION.md) remains open for a
physical anchored transition proof and its recursive closure, an accumulating
checkpoint and practical complete STARK settlement. The 3.07-billion-instruction
anchored transition still exceeds the admitted 256-proof roster. Its retained
witness archive has not been located locally; execution-only fixtures are not a
substitute for that transition.
