# CPU-first OP continuation on Apple M5 Max

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
