# CUDA local-first qualification — 2026-09-29

Current status: native compilation is complete, and local canonical source admission
passes for all four PIEs (12/12 checks). NVIDIA constraint snapshots match an
independent evaluator at 368/368 boundary points; all 62 used preprocessed OODS
samples match pinned Rust. Full proof verification still rejects composition OODS
and the degree gate. No NVIDIA SN PIE benchmark is qualified. The pod is deleted,
with $0.3253894353 credit remaining. Entries below record the earlier iterations;
older balances and completion counts describe those sessions only.


The CUDA canonical path now accepts source inputs through the same pinned
Stwo-Cairo AIR and preprocessed-profile admission policy as CPU and Metal.
Local source/controller preparation passed for all four SN PIEs. Full CLI
semantic compilation passed on macOS and with an x86_64 Linux target. The
compact writer matches an independent Rust transport byte-for-byte (5 focused
tests passed, including its dependency checks). Source and ABI closure passed. The CUDA builder tests passed (22 cases, including the newly focused CLI case),
including rejection of the retired SN2 Cairo AOT selection. The local CLI gate
now also validates the actual archive-builder command, all 180 generated sources
and their manifest identities without invoking NVIDIA tools. The separate cache
checks and product-closure tests cover the native build and runtime policy.
Six benchmark receipt tests reject altered security, input/executable identities,
proof bytes, verifier pins, translation providers and fallback evidence.

CuMetal v0.6.0 pin and the tracked pointer-select patch translated 117/122
canonical generated kernels. Sequential retries with inline threshold 0 timed
out for EC op, Pedersen W18/W9, Poseidon and one EC AIR body. All three numerical
harnesses passed on the Apple GPU: QM31 powers, active feed counts and felt252
cube arithmetic (49 independent Python big-integer vectors). These are local
translation/arithmetic results; no NVIDIA proof or timing is qualified by them.
The retry receipt binds native source dependencies and CuMetal runtime identity.

| Benchmark | Planned resident arena bytes | NVIDIA proof qualified locally? |
|---|---:|---|
| SN PIE 1 | 112,813,606,208 | No |
| SN PIE 2 | 69,671,731,520 | No |
| SN PIE 3 | 111,643,512,768 | No |
| SN PIE 4 | 89,527,538,784 | No |

These are host plans, not observed GPU memory peaks. Three plans exceed an
80 GB H100. The active Cairo archive omits 271 legacy SN2 AIR bodies, selecting
48 common entries, 64 canonical witness entries and 68 parametric AIR bodies.

The bounded H200 session was deleted after native compilation stalled on two
large kernels. It generated and authenticated 168 completed cubins; those and
the compiled official Rust verifier are saved locally. No proof was executed or
qualified in that session. The wallet decrease after billing settled was about
$2.67; the last remaining balance is $8.83, and no pod is running.
Future qualification must first prove and independently verify a genuine small
canonical input, then all four canonical SN PIE proofs. Result receipts must bind
70 queries, 26 query PoW bits, 24 interaction PoW bits, blowup/fold step 1, final
degree bound 0, no lifting and channel salt 0. The official verifier pins remain
Stwo-Cairo 82f21252a68ec006d73e299f5bf1ce6d4db0ee78 and Stwo
7b211edde786775016ef3eecb837a6240d8fe792.

Adapted-input timings exclude PIE execution and queueing; GPU unit economics
cannot yet be inferred from them. Current production eligibility remains false.

The shared generic-EC deduction function compiled locally in 36.925 seconds
(where full inlining timed out at 90 and 180 seconds). Canonical witness codegen
v14 now uses that boundary only for programs that call generic EC; the manifest
and registry pin were updated together. Its partial EC kernel and all three
numerical harnesses pass with the current generated source identities. The
full CLI/archive plan passes locally at v14. Per-cubin caching now binds exact
source bytes, support headers, effective flags, toolchains and SM; three focused
cache tests cover reuse, invalidation and corruption rejection. Unchanged
in-session units are authenticated and retained for the next native build.

A single very large generated AIR body also exceeded the native assembly
optimization deadline. Bodies of at least 256 KiB now use ptxas optimization level
1, with the option included in their cache identity. Arithmetic is unchanged;
its proof acceptance and performance still require NVIDIA qualification.

Current local qualification is witness v15 / parametric AIR v3. The full matrix
translated 128/132 sources. CuMetal deadlines remain on the Pedersen W18/W9
aggregators, Poseidon aggregator and the largest generic EC AIR. All five
numerical checks passed: QM31 powers, active feeds, 49 felt252 cubes, 48 nonzero
felt252 inverses and 32 parametric AIR cases with imperative register rewrites
and boundary segment constants. The full CLI and actual archive plan compile on
macOS and x86_64 Linux. All four real SN PIE source/controller plans pass.

The largest AIR changed from 1,751 general extension multiplications to 472,
replacing 1,279 with scalar operations. Early accumulation preserves final
register values and coefficient order. An LLVM SM90 PTX experiment with pinned
NVIDIA libdevice compiled in 7.24 seconds to 13,262,422 bytes (previously about
20 MB); this is compiler evidence, not an assembled cubin or verified proof.
Per-cubin publication now retains successful units even when another compiler
fails; its focused regression restores a completed cubin after a failed peer.

Native compilation is being investigated locally using a CPU Linux environment.
No further GPU rental is active. Genuine NVIDIA proof acceptance, suite time and
observed memory still remain unqualified.

Witness v16 reuses one disjoint input/output scratch pair across serial
deductions instead of declaring hundreds of per-call arrays. Inputs are copied
before any output callbacks; results retain their original registers and store
schedule. EC-op translates in 32.40 seconds with all five Apple GPU numerical
checks passing. The historical Native source identities remain unchanged.
The complete v16 CLI/archive plan passes on macOS.

Real SM90 cubins are now compiled locally by NVIDIA CUDA 12.8.93 in an ARM64
Linux CPU container. Apple Container 1.5.0 runs an Ubuntu 24.04 VM with 8 CPUs
and 32 GiB RAM; it has no GPU passthrough and incurs no cloud charge. The native
bundle records each source, flags, compiler/toolkit identities and cubin digest.
The archive importer rejects incompatible source/ABI/SM, non-CUDA ELF, altered
artifacts, duplicate entries and unsafe filenames. Imported compiler identities
remain separate from the GPU host compiler's cache entries. All 44 focused build,
cache, importer, benchmark-receipt and closure tests pass.

Use `scripts/cuda_aot_local_native.py` with the Container CLI, mounted work root
and generated witness/eval directories to prepare the native bundle. Compilation
is bounded per unit, successful units publish immediately, and retries reuse
unchanged artifacts. `STWO_CUDA_AOT_CUBIN_IMPORT_ROOT` selects this bundle for
the normal archive builder. The local import plan validates the actual complete
180-source archive. Saved Linux verifier reuse requires an exact project-source
and binary digest match. Remote deadlines terminate complete process groups.

These checks do not establish NVIDIA proof acceptance or SN PIE proving speeds.
The next hardware gate is a canonical small proof accepted by both verifiers,
followed by all four canonical SN PIEs with proving time, host RSS and sampled
GPU memory. Memory receipts explicitly indicate missing/failed NVML samples.

Current native compilation is complete: all 64 witness v17 and 68 AIR v3
entries assembled into source-authenticated SM90 cubins using local NVIDIA
tools. Witness v17 splits long deduction chains into bounded device functions
with a compact carry bank derived from their actual scheduled reads/stores.
EC-op assembled in 47.34 seconds after v16 exceeded ten minutes.

Programs exceeding 8,192 AIR instructions use thread-private register banks.
Known base values remain literals; extension writes finish before replacing
aliased destinations. The largest body assembled in 487.88 seconds after the
previous register layout exhausted assembler memory. This establishes compile
readiness; its device memory and runtime trade-offs still need measurement.
Seven local numerical checks pass, including the 70-deduction row-chain carry
and bank-backed AIR with imperative base/extension rewrites and canonical root
order. The largest translated CuMetal source still exceeded its 180-second
translation deadline; the native cubin succeeded independently.

The native manifest and local partial receipt are recorded here. They explicitly
leave NVIDIA proof verification false. A bounded H200 session is next, starting
with the genuine canonical small proof and both verifiers before the four PIEs.

The first hardware proof admitted neither an invalid proof nor benchmark timing.
It exposed two controller integration gaps before trace generation: counters
were allocated at the live ID extent instead of the padded memory-table extent,
and gathers conflated producer column stride with active row count. Canonical
counter storage now follows table padding while descriptor ID bounds retain the
live domain; big-table instances bind their own counter slice. Multi-edge gather
metadata carries active rows independently of its physical stride, preserving
the 32-byte ABI and the historical zero-as-full-stride case.

`zig build test-cairo-cuda-local` now runs device-free source admission tests.
Seven focused admission tests pass, including all four genuine PIE plans, and
four multi-edge tests pass, including mixed physical strides with active counts
5 and 11. Gather extents are checked during source admission before GPU allocation.
The full-toolchain build graph and source/ABI closure pass. NVIDIA proof and
suite qualification remain pending.

The corrected NVIDIA path builds and executes through proof finalization, but
the small canonical proof is rejected with `InvalidFriDegree`. A byte-exact
pinned Rust prefix oracle confirms the interaction PoW but rejects both the
lookup balance and composition OODS equality. The degree failure is therefore
not sufficient evidence of an isolated FRI bug: witness/interaction parity is
the next diagnostic gate. The failure receipt is recorded in
`nvidia-v17-prefix-failure.json`; its elapsed time is an unaccepted diagnostic
run, not a prover benchmark. No PIE suite was launched.

The H200 pod is deleted after preserving the diagnostic transport, sidecars,
compiled executable and archive cache locally. Remaining credit at the final
check is $5.93 with zero hourly spend. Next, compare per-component base columns
and interaction claims using the same lookup challenge, fix the first mismatch,
then repeat accepted proof qualification before publishing any suite timing.

The follow-up component comparison replays the exact NVIDIA lookup challenge
through the pinned official Rust trace oracle. All 23 leading execution/BLAKE
interaction sums match; the first differing component is `blake_round_sigma`,
followed by memory and lookup tables. This evidence narrows the remaining
failure to table construction/routing and does not qualify a full proof.

Two concrete memory gaps are corrected: canonical AIR columns put multiplicity
first, while implicit interaction pointers put it last; only the pointer headers
are reordered between those contracts. Memory value writers now also send every
committed limb pair, including zero padding, to the shared `range_check_9_9`
feed scheduler. Capacity admission accepts the produced memory trace as its
resident source when an implicit writer has no subcomponent-word slab.
Eight device-free admission tests and Linux product semantic compilation pass.

The actual native memory writer executes via CuMetal and matches 38 pinned Rust
AIR columns (big and small, 16 rows each). Evidence and reproducible input values
are in `local-memory-base-parity-receipt.json` and
`memory-base-prefix-fixture.json`; this is Apple GPU translation evidence, not
NVIDIA proof qualification. `tests/cuda/cumetal/memory_base_execution.cu` accepts
`STWO_BIG_MEMORY_FIXTURE` and `STWO_SMALL_MEMORY_FIXTURE` include paths containing
`constexpr unsigned big_expected[]` / `small_expected[]`, respectively. Arrays
flatten each fixture component's `diagnostic_prefix_m31` column-major.

An explicit `STWO_CAIRO_CUDA_SOURCE_DIAGNOSTIC` directory retains relation sources
until terminal assembly, compares the real device memory/table columns with
Rust, and aborts without publishing proof or benchmark receipts. Ordinary
proving retains its original short source lifetimes. Failure sidecars now use
the source snapshot digest in their filenames to prevent reuse across fixes.
NVIDIA qualification is continuing on a bounded H200 reservation; its first
new attempt exposed the now-fixed memory capacity binding. All suite timings
remain gated on successful pinned official verification.

The terminal source comparison identified two additional integration defects.
Execution counters omitted the public-memory uses admitted by the statement;
adding those uses offline makes all 70 canonical memory columns match the Rust
checkpoint. The actual CUDA ingress now uploads those initial counts and leaves
them intact during counter clearing; execution contributions remain on-device.
Fixed-table multiplicities already matched Rust, but the BLAKE sigma preprocessed
values did not: compact commitment trees selected the prefix of the shared
twiddle cache rather than its canonical suffix. Forward and inverse bindings
now select that suffix. An independent regression compares both views with
separately computed smaller-domain twiddles. All ten local admission tests pass,
including all four PIE plans. These are diagnosis and local regression results;
normal NVIDIA proof acceptance and the four-PIE suite remain the next gate.

The next NVIDIA snapshot confirms all 70 memory columns and all memory
interaction sums now match the official Rust oracle. Twelve fixed-table sums
still differ. Base-domain reconstruction was incorrectly using the LDE staging
ABI, which deliberately caps coefficient input at half the output domain.
Ingress now copies the complete coefficient cohort into its already reserved
evaluation storage and runs a full forward transform. The normal extended-domain
commitment still uses LDE. A regression covers two complete columns, upper-half
coefficients and one-time materialization. The offline seed diagnosis is retained
in `public-memory-seed-diagnosis.json`; it never alters device snapshots or proofs.

NVIDIA v20 now matches all 46 interaction sums byte-for-byte with pinned Rust;
its interaction PoW and zero lookup balance pass the independent prefix oracle.
Actual sigma sequence inputs are again `0..15`. The remaining failure is
composition OODS equality and the final FRI degree gate, recorded in
`nvidia-v20-prefix-failure.json`. The executable, transports, device snapshots
and logs were downloaded before deleting the H200 pod. No suite timings were
accepted.

The local Rust trace oracle now supports `oods INPUT.json OUTPUT.json`, with
`STWO_CAIRO_TRACE_ORACLE_OODS_REPORT` pointing to the rejected prefix report.
It independently interpolates the official main and interaction traces and
evaluates the canonical sample masks. It also records an extra-double variant
strictly for diagnosis. This replay identifies an extra circle doubling in the
CUDA OODS fold schedule: coefficient logs were subtracted directly from LDE
height instead of the coefficient-degree height. The split composition should
have zero folds, not one. The schedule is corrected, with regression checks
and the existing SN2 topology test linked to the protocol degree. All twelve
local admission tests pass. `oods-fold-diagnosis.json` retains the v20 comparison;
the BLAKE producer rows can differ in order between writers, so those sample
differences alone do not establish invalid witness values. Full proof acceptance
still requires the normal pinned verifier gate.

The corrected SN2 OODS topology also passes its full source-plan test: all
6,110 sample folds agree with the protocol degree and their compact source
coefficients. Its updated identity is
`5dd63f98e8c486aceb426e1c721e7402c7ad833f2494daf14f0dafba7b113e45`.
The Rust oracle's six focused tests pass. A final H200 reservation has a hard
10:48 UTC termination on September 29, 2026 and stays within the remaining
authorized account credit. Canonical parameters and both verification gates
remain unchanged.


The final NVIDIA diagnostic captured three mask offsets, live extended parameters,
random powers, and accumulator values at eight boundary rows for all 46 components.
Independent M31/QM31 bytecode interpretation matches all **368/368** component
contributions. This is bounded failure localization, not full constraint or proof
qualification. The diagnostic always rejects proof publication and accepted benchmark
receipts. `nvidia-constraint-parity.json` records the actual source snapshot, values,
and limits; `compare_eval.py` reproduces the comparison from the retained archive.

The normal v21 proof still rejects composition OODS equality and the FRI degree gate,
despite correct lookup balance and all 46 claimed sums matching pinned Rust.
Composition transforms/assembly and preprocessed OODS require further localization.
No NVIDIA SN PIE suite result is qualified. The H200 pod was deleted after locally
verifying the retained archive; the account has $0.3253894353 credit remaining.


The optional pinned Rust preprocessed sampler now checks all 62 used columns,
including actual polynomial interpolation and canonical coefficient-degree lifting.
All 62 samples match the saved v21 CUDA transport. This check ran locally after
pod deletion. `nvidia-v21-oods-comparison.json` records sample-level evidence and
also preserves the BLAKE round/G differences: witness ordering remains a separate
consistency question, rather than an automatically attributed CUDA sampling bug.


The local production log-21 fused composition split (schedule 9/6/6) also matches
an independent scalar inverse transform for all **8,388,608 coefficient words**
across four coordinates. CuMetal legacy source lowering executed the three real
CUDA template kernels on the Apple GPU; no fallback/stub provenance appeared.
The default cumetal-ir backend rejects the helper/collective graph, so this
receipt explicitly names the legacy backend. It does not qualify an NVIDIA proof.
`tests/cuda/cumetal/composition_split_execution.cu` is the reproducible harness.

Remaining localization includes BLAKE main/interaction consistency (Rust row
ordering differs) and complete composition/quotient assembly. No full-proof
correctness claim follows from these arithmetic and transform spot checks.


All 678 resident descending constraint powers also match independent QM31
exponentiation from the pinned Rust transcript's composition challenge. This
rules out a challenge/power binding mismatch for the captured tiny run.
The local Rust oracle's six focused tests pass after enabling preprocessed OODS
sampling. Full normal proof verification and all four PIE benchmarks remain
unfinished; the saved artifacts and numerical checks are not accepted benchmarks.
