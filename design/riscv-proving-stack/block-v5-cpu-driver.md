# Block-v5 CPU driver

The production driver connects the real Ethereum/SHA runner to the native-v3
proof route, global sorted word memory, ROM, lookup providers and exact native
recursive forest. It returns success only after a fresh complete receiver reads
the staged policy, source files, manifests and proofs from disk.

## Lifetimes and planning

The first pass keeps one runner segment, native owner and public I/O alive.
Physical native, ordinary-memory and caller commitments are collected before
global admission. SHA, Keccak and signer caller counters and both memory
sidecars join the native counters in the same independently bounded group.
Only physical roots, admitted geometry, sparse ROM counts and byte censuses
survive the segment. Sorted memory events and completed group counters go to
disk; only one current lookup group stays resident.

After external sorting, the source writer checks the complete initial image,
untouched words, input, register endpoints and independently pinned final RW
root. Packed memory and range16 components choose their own sizes. Actual ROM,
memory, source and provider plans then determine native public admissions and
the complete, canonically ordered source seal.

The second runner pass recreates one segment. Native table/ROM projections,
ordinary memory and every caller companion are proved within that segment's
lifetime. They borrow immutable fixed/main trees; packed sidecars commit only
their extra witness tree. Recursive native leaves are staged before releasing
the segment. The exact pair/quartet forest uses the actual leaf count.

The complete bundle contains the native execution proofs and their recursive
forest, plus all caller, memory, ROM and lookup proofs required for fresh global
closure. The outer proof compresses the native forest; the enclosing complete
receiver verifies the other proof families and closes their relations.

## Durable reception

Every proof family has a typed, bounded loader. Independent geometry chooses
the codec; file hashes and proof claims cannot choose verifier policy. Loader
indices are single use, and genuine absent branches consume no proof file.
The public receiver policy is separately SHA-pinned and bound to the job,
source image, program, initial/final RW roots and security configuration.
Owning metadata decoding checks its allocation cap and complete consistency
before exposing any borrowed slices.

`ethereum_block_v5_cpu_produce.zig` and `ethereum_block_v5_cpu_verify.zig` use the
same complete detached receiver. The standalone verifier needs no execution
replay or producer-side receipts. Its eight public/file pins are supplied
separately from the bundle:

```text
stwo-ethereum-block-v5-cpu-produce ELF INPUT ORACLE CYCLES JOB_ID_HEX OUTPUT_DIR
stwo-ethereum-block-v5-cpu-verify POLICY_SHA BUNDLE_SHA FOREST_SHA JOB_ID SOURCE_IMAGE PROGRAM INITIAL_RW FINAL_RW INPUT BUNDLE_DIR
```

Both installed products use canonical 70-query/26-PoW security. The producer
uses a create-only output directory. Initial endpoint preflight is performed
once; `Source.initFromPlan` validates the source/job pins and reuses those host
proposals without treating them as proof authority.

## Qualification and measurement

The genuine mixed two-segment q8 diagnostic gate passed 10/10 tests with clean
allocator teardown. It executed setup, two SHA calls, one Keccak call and
terminal output publication; the complete bundle had 120 memory events and 17
base proof files. Fresh policy/base/source/recursive file reception succeeded.
This qualifies assembly, not canonical security or an Ethereum block.

Its in-process measured collection/proving/forest/verification durations were
1.052/9.258/18.548/2.197 seconds. Compilation is excluded from these timers;
the test is not an isolated performance comparison. Scoped evidence is recorded
in `block-v5-cpu-complete-mixed-q8.json` in the Ethereum delivery campaign.

The canonical **q70/26-PoW** complete gate passed **10/10** with clean allocator
teardown. The tiny real ELF diagnostic executed 17 guest cycles across three
segments, including the sparse caller at execution index 1, and produced 132
memory events and 21 base proof files. Fresh disk reception verified all proof
families, global closures and the exact three-leaf recursive forest.

Its measured collection/base-and-leaf proving/forest-and-staging/fresh complete
verification durations were **1.055/34.128/120.860/2.603 seconds**. These are
in-process stage timers, reported to millisecond precision, with compilation
excluded. No tracked allocation peak or process RSS was recorded for this test.
The result qualifies canonical assembly on this tiny ELF; it is neither a
mainnet performance result nor a self-contained single outer proof. The outer
proof compresses the native forest, while the complete receiver also needs the
other proof families. Scoped evidence is in
[block-v5-cpu-complete-mixed-q70.json](../../autoresearch/notes/2026-09-24-ethereum-block-delivery/block-v5-cpu-complete-mixed-q70.json),
with the actual log at `/tmp/block-v5-cpu-assembled-q70.log`.

The campaign's `run_block_v5_measurements.py` runs already-built producer and
verifier executables in separate processes. It records exact binary/ELF/input/
oracle hashes, canonical parameters, stage times, tracked allocation peaks and
process RSS. Preflight is separate; proof-generation time includes collection,
sorting, roots, all base proofs and recursion. Process RSS includes preflight
and excludes compilation. Spool, source, counter and proof-file disk bounds are
separate resource limits, rather than a claim about aggregate disk usage.

An isolated run of the same tiny 17-cycle, three-segment ELF passed canonical
production and complete verification in a separate fresh verifier process.
The wrapper checked identical complete public summaries and the requested job
identity. Proof generation took **81.636 seconds**, the producer pipeline
**81.933 seconds**, and fresh verification **0.314 seconds**. The producer's
`/usr/bin/time` wall time was **82.44 seconds**; the wrapper's launch-and-wait
wall time was **82.967 seconds**. Compilation was excluded.

Producer peak RSS was **10,785,488,896 bytes (10.045 GiB)**, its tracked
allocation peak **10,708,511,959 bytes**, and the recursive-stage tracked peak
**10,708,120,969 bytes**. The bundle contained **21 base proof files totaling
9,666,747 bytes** and **5 recursive proof files totaling 4,263,397 bytes**.
Source, policy, manifests and remaining staging files brought the durable
inventory to 34 regular files and 26,392,590 bytes, excluding the producer
report; this inventory is not peak disk usage.

These measurements qualify the installed all-family complete receiver on a
tiny real ELF, not Ethereum block performance or a self-contained single outer
proof. The fresh verifier used separately SHA-pinned producer-generated
policy; this run did not independently admit an Ethereum block or external
public-state policy. Exact binary and source hashes, nanosecond timers and
process logs are preserved in the durable
[measurement.json](../../autoresearch/notes/2026-09-24-ethereum-block-delivery/block-v5-canonical-mixed-isolated-v1/measurement.json),
with scope summarized in
[block-v5-cpu-complete-mixed-isolated-q70.json](../../autoresearch/notes/2026-09-24-ethereum-block-delivery/block-v5-cpu-complete-mixed-isolated-q70.json).

The first mainnet trial used a **2 Mi-cycle segment limit** and an
explicit **16 GiB native recursive setup-cache limit within the 40 GiB
aggregate host limit**. Exact preflight established 67 segments.
These settings belong to the subsequent producer revision, not the isolated
run's hashed executable. Complete mainnet proof production remains unqualified.

That first mainnet attempt stopped during collection with `CallRangeTooLarge`
after **370.04 seconds**, at **6,044,762,112 bytes peak RSS**. The caller witness
had selected legacy Keccak log16, whose 4,518-call ceiling was exceeded; this
was a geometry admission failure, not a memory-limit failure. No complete block
proof was produced. Its durable
[measurement](../../autoresearch/notes/2026-09-24-ethereum-block-delivery/block-v5-mainnet-24628607-2m-canonical-v1/measurement.json)
retains the failed-run identity and resources.

Caller protocol version 2 now selects the explicit `ethereum_v5` circuit
profile and binds it into the caller key and transcript, admitting canonical
Keccak geometry up to log18. The named canonical three-segment complete case
passed with fresh reception under this protocol; the enclosing test command
was interrupted during a later case, so it is not a suite pass. The subsequent
larger-domain gate passed **13/13**, followed by **14/14** on the selected-domain
revision: 4,519 real Keccak calls produced a log17
arithmetic proof and packed memory sidecar, both freshly verified with shared
roots, codec round-trip and legacy-key rejection. That larger gate is scoped
and does not establish global or complete block closure. Evidence and exact
scope are in
[block-v5-caller-protocol2-qualification.json](../../autoresearch/notes/2026-09-24-ethereum-block-delivery/block-v5-caller-protocol2-qualification.json).
The selected-domain revision recovers 32 state-bit columns for each Keccak
memory slot and none for pointer slot 0. It preserves the complete descriptor
and PCS sample masks, +27 output offset, full-domain degree checks and pinned
SHA fixed-selector logs. Fresh arithmetic and packed proofs passed the
unchanged point verifier; added parity checks cover nonbinary field inputs
and zero enablers. This qualifies the implementation revision without claiming
a measured speedup. The original geometry failure has a qualified correction;
the canonical mainnet-v2 run also stopped before proof production.
Both protocol-v2 products built successfully in ReleaseFast; the durable
[mainnet-v2 measurement](../../autoresearch/notes/2026-09-24-ethereum-block-delivery/block-v5-mainnet-24628607-2m-canonical-v2/measurement.json)
pins their binary hashes and excludes compilation. New producer reports record
`caller_protocol_version` and `caller_circuit_profile` alongside binary hashes.

Mainnet-v2 collected all **67 segments**, covering **139,214,856 guest cycles**
and **356,303,914 memory events**, formed **14 lookup groups**, and completed
external sorting. It then failed at the start of global source-root construction
with `InvalidV5InitialSourceLayout`. The isolated process took **1,173.87
seconds** and reached **9,642,622,976 bytes peak RSS (8.980 GiB)**. The wrapper
captured these resources automatically in the durable measurement. No complete
proof was produced and no fresh verifier process ran. This collection result
is not proof throughput. The shared layout correction now passes a pinned
real-ELF/input, one-instruction source-writer regression with full initial and
final roots, plus union-gap, program-overlap and resource-cap negatives; that
regression performs no STARK proving.

The latest canonical recovery gate passed **14/14**, including fresh all-family
Complete reception for the three-segment, 17-cycle ELF with 132 events and 21
base proof files. Collection/base-and-leaf proving/forest-and-staging/fresh
verification took **0.995/25.211/118.485/2.590 seconds**, using in-process
millisecond timers with compilation excluded. No proof-memory peak was
reported; these are not mainnet performance measurements. Production consuming
native rows, shared column transforms, tiny-log1 recovery and the 8-byte minimum
tower cache passed through the actual complete path.

The prior 26-case command had 25 passes and one canonical recovery failure,
now resolved by the 14-case gate; it must not be described as a 26-case suite
pass. Its meaningful named positives remain evidence for real pinned
source-image writing, 4,519-call fresh arithmetic and packed verification,
two real same-key cached native instances with fresh leaf files, and consuming
lease/security cleanup. Exact logs and revision scopes are in the protocol-v2
qualification record. Both v3 products built successfully in ReleaseFast.
The [mainnet-v3 measurement](../../autoresearch/notes/2026-09-24-ethereum-block-delivery/block-v5-mainnet-24628607-2m-canonical-v3/measurement.json)
records the canonical q70/26-PoW job with the same pinned guest, input
and oracle and 2 Mi-cycle segmentation. Collection and global admission
completed for all 67 executions, 85 memory instances and 622 base-proof
policies in 1,650.976 seconds. Nine executions published their base proofs and
recursive leaves. The user requested a stop during segment 10 sidecar proving;
the producer received SIGTERM. Its isolated process took 2,758.73 seconds and
reached 10,183,507,968 bytes peak RSS. These are partial-run resources, not
complete block performance. No complete proof, producer report or fresh-process
verifier result exists. The measurement preserves the wrapper's exit status and
explicitly records the user-requested termination. The remaining architectural
performance work is detailed in the campaign's
[roadmap](../../autoresearch/notes/2026-09-24-ethereum-block-delivery/block-v5-performance-roadmap-v1.md).

The measurement wrapper now extracts external `/usr/bin/time` wall and peak
RSS values for failed runs as well as successful producer and verifier
processes. Missing time summaries leave those values absent; resource data
never changes the proof-success status.
