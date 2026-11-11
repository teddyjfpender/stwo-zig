# CPU-first OP continuation on Apple M5 Max

The latest [complete native heavy-block comparison](heavy-cpu-scheduling-and-guest.json)
qualifies the existing bounded two-lane schedule and selected guest inlining
on OP 121065789. Every fresh receiver accepts and both corruption controls
reject. The two-lane control preserves every original proof byte.

| Configuration | Instructions | CPU / service proofs | Native production | Fresh receiver | Peak RSS |
| --- | ---: | ---: | ---: | ---: | ---: |
| Original guest, one lane of 8 | 425,537,671 | 102 / 24 | 1,723.236 s | 38.325 s | 46.932 GiB |
| Original guest, two lanes of 8 | 425,537,671 | 102 / 24 | 1,428.146 s | 27.917 s | 48.922 GiB |
| Selected inlining, two lanes of 8 | 380,167,068 | 91 / 24 | 1,298.007 s | 37.047 s | 47.876 GiB |

The combined production reduction is 24.7%; the guest alone reduces retired
instructions by 10.66% and represented MAIN/INTER cells by about 10.1%.
These are one-run qualification timings with development overlap, not quiet
paired performance claims. Stage one remains mostly serial at the chosen
16 GiB transient scheduler cap; stage two benefits from overlap but its summed
worker time increases from contention. No memory multiplier is established.
Recursion and authenticated L1 derivation are additional work.

The subsequent [capture and packed-accumulation qualification](capture-and-packed-accumulation.json)
uses four bounded capture jobs and directly accumulates packed native constraints.
The selected heavy guest completes native production in **1,222.972 s** and fresh
reception in **32.358 s**, with both corruption controls rejecting. All 120 proof
and statement artifacts match the preceding selected-guest run; timing and
schedule telemetry are excluded. Capture falls from 111.239 to 48.286 s. Peak
RSS rises to **49.979 GiB**. This is another single development qualification,
not a quiet median, and includes no recursion. The prefix ABBA establishes a
7.2% constraint-row stage reduction but no whole-prefix wall improvement.

The [AArch64 grouped lookup-dot experiment](rejected-arm-lookup-dot.json) also
preserves physical proofs and passes fresh receivers, but produces no useful
local-GKR or total-wall improvement in the cold ABBA comparison. Its production
dispatch change is rejected; broader zero-coordinate reference tests remain.

The [heavy execution recursion receipt](heavy-recursion-ternary.json) closes OP
121065789: 102 CPU and 24 service proofs, 126 wraps and 64 ternary folds. A
separate strict receiver accepts and both physical leaf corruption and a missing
final fold reject. Production is **2,536.789 s**, additional to native proving;
fresh native-plus-recursive reception is **193.250 s**. Producer RSS peaks at
**31.125 GiB** under a 52 GiB requested-live admission. Builds/tests overlapped,
so this is qualification evidence, not a quiet benchmark.

Leaf wrapping accounts for 1,540.263 s, folding 897.961 s and leaf graph
construction 54.926 s. The 749,304-byte root still requires the native bundle and
all 190 original recursive nodes for this strict receiver. It is execution-only,
not a root-only portable checkpoint or anchored OP validity. The failed M7
four-child memory attempt and refused binary override are retained explicitly.

The optional [Arkworks Montgomery client](arkworks-montgomery-service.json)
reduces full one-/two-blob KZG verification from 51.37M/73.33M to
28.49M/40.54M retired instructions. All fourteen positive probes agree with
native software and Unicorn; seven malformed KZG inputs reject. Shifted scalar
inputs also pass physical services-lane proofs and fresh receivers. These are
execution savings, **not measured complete proving speedups**. The retained
anchored transition proof remains open. See [client design and reproduction](../../../opstack/MONTGOMERY.md).

The optional [GROUP2 arithmetic qualification](recursion-group-structural.json)
uses symbolic zero identities and a seven-row full OM31 product. Every add and
multiply costs one QM31 arithmetic row here; native Karatsuba's three products
require nine rows once its additions/subtractions are included. All 64 basis
products, random values, all-coordinate corruption, scope and allocation tests
pass. The real OP root and independent receiver pass, as do the old GROUP1 and
original M7 tree authorities under the default policy.

Active arithmetic rows fall to 10,757,366 but still pad to 16,777,216. The
20.195 s final qualification is not evidence of another whole-root speedup.
The [bounded expression-cache experiment](rejected-group-expression-memo.json)
also passes physical reception, but only 5.87% of queries hit and the padding
stays unchanged. It adds complexity without an established wall gain and is
**not landed**; its patch and qualification remain as experimental evidence.

The [native-verifier group comparison](recursion-native-groups.json) replaces
three wrapped native verifiers and one fold with one outer proof of all three
native verifiers. No native equations are removed. The complete execution-only
root, independent trace-only receiver and corruption/missing/profile controls
pass on real OP block 120794432.

| Three cold trials per variant | Recursion wall median | Fresh receiver | Peak RSS median |
| --- | ---: | ---: | ---: |
| Existing M6 tree | 35.766 s | 3.994 s | 27.34 GiB |
| Existing M7 tree, compiled | 40.944 s | 4.139 s | 35.44 GiB |
| One M7 native group, compiled | 21.981 s | 2.942 s | 39.16 GiB |

This is a 1.63x recursion gain over the M6 control and 1.86x over the M7 control,
with a memory increase. Native production is additional. Balanced-order runs
have observable drift; all same-variant proof files are identical and every
fresh receiver accepts. Summed M7 GKR time falls from 9.367 to 3.592 s, and
composition from 7.449 to 3.789 s. These are stage medians, not additive wall
attribution. The ~19 s recursion target remains open.

The explicit grouped route refuses rosters larger than four workers. It still
requires the native bundle and receiver-derived statement-specific authority;
it is not a portable checkpoint, anchored transition, accumulator or complete
settlement. See the [composition review](../../../design/riscv-proving-stack/rv64-native-verifier-groups.md).

The [M7 compiled-coordinate qualification](recursion-m7-coordinate-native.json)
lowers the receiver-derived hybrid program into scalar M31 expressions at build
time, then emits packed C kernels for all eleven components. It preserves the
original program identity, transcript and all five actual OP proof files. The
final qualification takes 36.375 s plus 3.736 s fresh strict reception, at
35.44 GiB peak RSS. All 44 domain calls use the compiled registry.

Four cold interleaved trials give composition medians of 8.606 s interpreted
and 7.209 s compiled (16% lower); complete-root medians are 39.737 and 39.132 s
(1.5% lower). Two samples per variant and trial drift do not establish a strong
whole-root gain. This remains opt-in with `STWO_RV64_OUTER_GKR_NATIVE=1`;
`STWO_RV64_OUTER_GKR_INTERPRETER=1` selects the control. M6 remains the fastest
measured complete-root CPU configuration. The original quartic Cairo and M6
kernels are unchanged. Unknown programs fall back; malformed input geometry,
secure carry and output coordinate planes reject before entering C.

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

The [packed base-scalar verifier path](solidity-base-scalar.json) avoids the
extension tower for canonical M31 literals in the internal OM31 representation.
Sixty-four repeated multiplications fall from about 501k gas to 53k–109k for
zero, one and other base scalars, with no heap growth. Dense multiplication
increases 0.71%; the 2,048-node mixed program increases 0.27%, while the real
177-node receiver-pinned AIR costs 1,064,808 gas. All 24 default settlement
tests pass; three external large-fixture tests remain explicitly skipped.
This is a component improvement, not a practical complete settlement claim.

The [complete heavy D2 native qualification](heavy-d2-native.json) admits the
same selected guest and all 115 native workers under the existing blowup-4,
query-54 construction. Fresh verification and both corruption controls pass.
Native production takes **1,586.092 s** and fresh reception **53.803 s**; its
trace cell counts are unchanged, while physical proof bytes fall from
332,950,620 to 200,502,208. This is a larger-domain tradeoff for fewer recursive
openings, **not a native speedup**. It uses one 16-worker lane and an explicit
8 GiB fixed-key admission; the 4 GiB refusal remains recorded. Defaults stay
unchanged. Full native-plus-recursive timing decides its adoption.

The [complete heavy recursion comparison](heavy-d2-recursion-comparison.json)
closes all **115 native members and 173 recursive nodes** of the selected D2
bundle. Serial production takes **1,781.674 s**, additional to **1,586.092 s**
native production; fresh native-plus-recursive reception takes **171.860 s**.
Two proof lanes take **1,790.027 s** at **39.119 GiB** versus serial
**31.117 GiB**, with every physical proof byte identical and both strict fresh
receivers accepting. Fanout is removed from production; its [patch](rejected-cpu-recursion-lanes.patch)
and bounded-admission tests remain recoverable. The native two-lane schedule is
a different mechanism and keeps its earlier complete-block qualification.
These are one-run development qualifications, not a controlled repeated speedup.

The subsequent [packed tower kernel](solidity-packed-tower.json) removes expanded
input/output arrays and reduces only the final eight coordinates. Dense
64-multiply gas falls **508,926 → 192,367**; the 2,048-node mixed AIR falls
**6,783,106 → 4,100,021**, and the real 177-node pinned AIR falls
**1,064,808 → 637,484**. Both the independent polynomial model and original
array tower agree on basis, edge and dense vectors. All 24 default settlement
tests pass; the three external-fixture skips remain. This supersedes the dense
tradeoff above without changing proof bytes or verifier authority.

The [final profiled heavy root](heavy-d2-recursion-profile.json) completes in
**1,742.353 s**, followed by **182.234 s** fresh committed-source reception.
All 174 physical proof files match the accepted serial control; all 173 outer
profiles match the tree's authority multiset. Peak producer RSS is **32.025 GiB**.
The explicit 1 GiB freed-block cache reduces new mappings 355,826 → 276,224
while increasing memory relative to the 64 MiB control. This is one profiled
qualification with brief source checks during startup, **not a controlled
cache speedup or a new default**. Native production is additional.

| Complete heavy outer stage | Summed seconds | Average busy process cores |
| --- | ---: | ---: |
| INTER preparation + Merkle | 409.291 | 13.51 |
| Composition | 333.679 | 10.20 |
| Interaction generation | 256.068 | 15.46 |
| MAIN preparation + Merkle | 189.925 | 11.26 |
| FRI quotient | 174.483 | 12.59 |
| Sampled values | 44.717 | 12.09 |

These root-level serial intervals total 1,507.328 s across all stages; nested
scopes are not added to that total. INTER contains 235.028 s Merkle hashing
and 174.262 s preparation; BLAKE gate rows consume 185.096 s of interaction
generation. Remaining wall includes 59.008 s initial setup, 28.521 s graph
construction and uninstrumented per-wrap/fold overhead. CPU counters cover all
process threads; different M5 core classes are not equal-throughput workers.

The next heavy-block multiplier needs fewer recursive hash/lookup obligations
or a qualified cheaper commitment/outer construction. More simultaneous CPU
proofs and larger caches have not demonstrated that multiplier. Preserve
full RAM/KIO/Wire closure, source authority, public statement/roster binding
and the documented security construction in any replacement.

The [final production-source gates](final-source-gates.json) build both native
and recursion CLIs, reject a physically corrupted new heavy leaf with
`ProofOfWork`, reject a missing final fold with `MissingRecursiveNodeProof`,
and refuse the retired CPU-lane selector. The original accepted D2 files stay
unchanged. The new executable also freshly accepts the retained original B2
heavy bundle with **126 native members and all 190 recursive nodes**, under
its original 4 GiB fixed-key admission. Both source modes and both native
profiles are thus exercised after the geometry repair. These checks establish
compatibility/refusal behavior, not a controlled receiver speed improvement.

The [current-source small-group repeat](final-small-group-repeat.json) freshly
produces and verifies **nine** complete small-block roots. A standalone GROUP2
repeat takes 21.555 / 22.734 / 22.440 s. In the subsequent balanced comparison
(three trials per variant), classic GROUP1 has a **21.466 s** median versus
structural GROUP2 **21.881 s**, with **2.859 / 2.878 s** fresh reception.
Every same-variant root matches its earlier accepted bytes. GROUP2 removes
active arithmetic rows 12,018,112 → 10,757,366 but both pad to **16,777,216**;
its root bytes fall 783,396 → 764,132 without a demonstrated wall gain.
GROUP1 stays the default and GROUP2 remains opt-in. The historical 18.840 s
qualification is valid but **does not establish a repeatable sub-19-second
median**. These tiny complete blocks do not predict heavy-block recursion cost.

After the physical controls, the final production executable also freshly
accepts **all 115 native members and 173 recursive nodes** of the new D2 heavy
root with independently rebuilt committed-source authority. Every retained
physical proof stays unchanged. The [final-source receipt](final-source-gates.json)
contains this complete positive case alongside the older B2 root and both
physical negatives.

The [CI audit](ci-review.json) keeps broader failures visible. OP Python, Kona,
fresh AIR export, prover and prover API lanes pass at the reviewed head.
Reviewed formal jobs hit HTTP 504 while downloading elan; Sail refuses on
circuit provenance drift. Aggregate adapters and workspace contracts have
remaining mismatches. A Linux circuit R0 digest failure is not reproduced in
isolated current/pre-window x86 macOS tests or the full current x86 macOS
package. The fixture digest helper now loads original QM31 storage directly
to avoid the known optimized aggregate-copy issue; no expected vector changes.
Fresh Linux CI is still required. The proof-wire API manifest is corrected,
but the full workspace checker remains red; no broad CI pass is claimed.
