# Ethereum block delivery — active campaign

The original objective and completion contract are in [PLAN.md](PLAN.md).
Full block proving is **not yet complete**; this directory distinguishes actual
block execution, individual segments, and synthetic authentication proofs.

A [canonical q70/PoW26 detached bundle fixture](block-v4-cpu-detached-bundle-real-io-q70.json)
now fresh-verifies the v4 memory/execution core and one-at-a-time recursive
leaf, parent and exact-root files for a guest with real public input/output.
It persists bundle metadata, then rehydrates from staged files under separately
SHA-pinned candidate/final manifests and recursion policy. Core-plus-leaf
generation took 105.111 s, forest proving 41.144 s, outer proving 62.869 s,
and the detached complete receiver 5.435 s. The first leaf has no precompile
calls; the terminal leaf has 51 Keccak accesses. Changed bundle, final-manifest
and recursion-policy hashes are rejected, and tracked allocations close to zero.
The enclosing build-and-test command took 402.31 s and reached 14.19 GB max
RSS; neither number isolates receiver resource use. The fixture generates its
own policy hashes before supplying them separately to the receiver. An
[installed CLI smoke](block-v4-cpu-cli-smoke-real-io-q70.json) now runs the
candidate roster, staged producer, and detached verifier as separate processes
on a one-segment real-I/O and Keccak job at q70/PoW26. The producer reported
`complete_block_verified=false` after 87.89 s and 14.24 GB peak RSS; the
detached verifier reported `true` after 0.97 s and 524 MB peak RSS. The smoke
driver recomputed and passed the candidate/final/policy/bundle SHA-256 pins,
and a changed bundle hash was rejected. Those pins still need independent
operator selection for production; the 218-segment mainnet block remains
unproved. The earlier [joined file-backed fixture](block-v4-cpu-file-complete-real-io-q70.json)
records the pre-detached run. The
[q8 staged-outer fixture](block-v4-cpu-staged-outer-real-io-q8.json) records
hash-pinned parent/outer file reload and tamper rejection.

A [read-only 218-key candidate roster](block-v4-candidate-roster-218-snapshot-result.json)
has completed for the proposed exact schedule: 4,592.79 s wall time,
10.21 GB tracked peak, and 218 distinct native key IDs. Its
[hash-pinned manifest](candidate-native-key-roster-v1/candidate-trusted-v1.json)
contains provisional zero outer/forest IDs and carries no proof authority.
The merged first-round geometry and full mainnet proof were not run after this
candidate; work now focuses on reusable keys and parallel proving.

A detached receiver audit found that rehydrated runner segments and staged
proof bytes were allocated through an arena, so per-segment frees had no
effect. They now use the bounded freeing host allocator; only small borrowed
bundle metadata and a capped table-proof set remain arena-backed. The same
hash-pinned q70 smoke bundle reopened and freshly verified after this change
with 523 MB process peak RSS. Producer and verifier reports now include
normalized process peak RSS on macOS and Linux; the verifier also reports
total command time. The [mainnet CLI cap audit](block-v4-cpu-mainnet-cli-audit-v1.json)
records remaining resource limits and the 218-segment scope.

Build/receiver usage and current qualification status: [COMMANDS.md](COMMANDS.md).

Active architectural direction: [BLOCK-COMPONENT-ARCHITECTURE.md](BLOCK-COMPONENT-ARCHITECTURE.md).
The user has prioritized separate memory/component proofs and actual-instance-count
aggregation over further tuning of the per-segment commitment path.

The latest exact-count CPU admission pass replayed all 139,214,856 mainnet
cycles in 218 proposed segments; every commitment component fits log24
(`exact-schedule-geometry-v1/qualification.json`). This is geometry with the
old per-leaf RW custody and will be rescheduled after its removal. A host-only
sorted-memory replay measured 356,303,914 accesses and 3,142,932 first-touch
keys in 74.49 s
with a 1.075 GB tracked peak (`exact-schedule-memory-roster-v1/qualification.json`).
The typed sorted-memory and byte-range proof passes a canonical q70/PoW26
small fixture, including fresh verification; a two-instance receipt test also
passes. An isolated proof of the real 51,929-row authentication memory trace
proves in 1.213–1.275 s across two samples, with a 264,044-byte proof and
438 MB tracked peak. Execution-to-memory and initial-state relations now
close in the canonical small v4 fixture described above. There is still no
complete mainnet block proof or block proving-time result.
One full log20 mainnet sorted-memory instance also fresh-verifies at q70/PoW26:
22.645 s proving, 406,342-byte Postcard STARK and 6.46 GB tracked peak.
This measures one of 340 planned memory instances, without the shared table
or execution/initial-state closure.

## Measurement contract

The CPU stream runner reports stage wall times, tracked peak allocations, root
proof size and cycle throughput. `run_block_measurements.py` wraps it with process
wall time, OS peak RSS/physical footprint, power status and hashes of the binary,
ELF, input, expected output and proof. Builds are outside the timed interval.
Only a successful verified root with matching identities and requested security
permits a successful measurement report. Pipeline time ends after fresh root
verification; process time also includes file I/O and teardown. Stage totals may
leave orchestration/cleanup overhead, which the wrapper reports separately.
Leaf proving and recursive witness preparation are currently one combined stage.
The stopped mainnet baseline also has `rss-samples.jsonl`, captured every five seconds
by `sample_block_memory.py` after attachment at five verified leaves. These
samples track RSS against completed leaf count, exclude earlier allocations,
and do not replace `/usr/bin/time` peak physical-footprint measurements.

The combined SHA profile is qualified through canonical leaf proofs, source
artifacts, recursive parents, and adjacent-segment full memory custody. Native
Rust SDK execution passes 44 independent digest vectors / 148 compressions.
The shared ELF-note refactor preserves the Ethereum guest binary byte-for-byte.

The 1,024-leaf mainnet baseline in
`measurements-mainnet-24628607-sha-canonical-262144` was deliberately stopped
after 20 verified leaves. It has **no complete block root**. Its tracked peak was
21,568,911,347 bytes (20.09 GiB). A full 512-leaf commitment census has now checked
all 139,214,856 cycles: ten leaves exceed log 24, with a maximum of 28,093,016 G
rows. Raising admission to log 25 allowed that largest leaf to start, but its
proof attempt exhausted the unchanged 48 GiB budget after 167.892 seconds.

Work-based schedules are now being qualified. The proposal allocates smaller
cycle budgets to the expensive memory regions and larger budgets elsewhere;
a complete fresh census and canonical full-custody proofs are required before
restarting full-block delivery. See [ZISK-SEGMENT-SIZING.md](ZISK-SEGMENT-SIZING.md),
[block-delivery-current-status.json](block-delivery-current-status.json), and
[PROGRESS.md](PROGRESS.md). These are sizing and partial-proof observations,
**not end-to-end block proving results**.

GPU integration boundaries and pinned peer findings are recorded in
[GPU-READINESS.md](GPU-READINESS.md); native versus guest-software operation
coverage is in [PRECOMPILE-INVENTORY.md](PRECOMPILE-INVENTORY.md).

## Full mainnet block execution

Pinned Ethereum mainnet block 24,628,607, 66 transactions. The rebuilt unmodified
stateless-validator-reth guest with native Keccak and signer recovery executed
253,646,998 instructions, 32,835 Keccak calls and 66 recoveries. Its 43-byte output
matches the independently executed host validator and pinned expected hash.

- Process wall: 80.17 seconds; runner elapsed: 79.52 seconds.
- Peak process footprint: 281,571,760 bytes (268.53 MiB).
- Bounded execution chunks: 262,144 instructions, 968 actual chunks.
- A balanced 1,024-leaf schedule fits the same bound without empty padding;
  larger per-leaf bounds reduce recursive work and are being qualified.
- This is execution only. No whole-block proof claim follows from this result.

Artifacts and hashes: `block-artifacts.json`, `execution.json`,
`execution-invocation.json`, `execution.log`, `fixture/`.

## Public-memory custody scaling fix

Previously, restoring public I/O into the continuation memory root performed a
separate old/new 30-level path for every word. The new canonical path partitions
explicit sorted public word edits into aligned, gap-free dyadic subtrees. It
independently derives both subtree digests from the admitted public words and
proves the remaining boundary paths. Both paths consume the same private sibling
sources. Full roots, word values, addresses and all unaffected memory remain
bound. Received subtree digests are never an admission authority.

The 675,173-word scaling test produces **17 ranges and 640 path hashes**, versus
40,510,380 path hashes previously. This is a structural count, not a standalone
end-to-end speedup. The test input starts at word index 1,024; exact range counts
for the guest depend on its admitted input address and any excluded boundaries.

Canonical 64-transaction authentication plus recursive wrapper:

| Metric | Previous balanced partitions | Public-subtree custody |
| --- | ---: | ---: |
| Verified root | Yes | Yes |
| Peak process GiB | 55.42 | 16.69 |
| Worker peak GiB | 47.85 | 16.60 |
| Retained preparation GiB | 11.20 | 4.00 |
| Parent proving seconds | 63.38 | 13.33 |
| Process wall seconds | 143.31 | 45.69 |

Both use q70/PoW26 and 16 CPU workers. These are single observations. The earlier
64 run briefly overlapped a stopped archive operation, so its wall time is not a
clean performance baseline. The process memory reduction is about 70%. The new
run uses the exact retained expanded guest and 64-transaction input from the
memory campaign. It is still authentication, not full Ethereum block execution.

## Verification

- `test-block-boundaries.log`: 25 tests, including balanced segment coverage,
  frontier rollback/rejection and public subtree hash/coverage/scaling checks.
- `test-subtree-integration.log`: 222 tests, including a real STARK path proof,
  false admitted-root rejection, altered public subtree rejection and custody
  binding to the execution span. Earlier failed log records only an expected
  error-name mismatch that was corrected.
- `test-stream-proof-retry.log`: actual four-leaf recursive stream, seven tests;
  this diagnostic q8/PoW0 test checks ownership and worker teardown, while the
  canonical authentication run qualifies q70/PoW26.
- `auth-64-subtrees.json`: independently verified canonical recursive root.

New custody identities and preprocessing geometry require new admitted keys.
The statement still binds the same full memory and public-I/O semantics. The
optimization applies to shared execution/recursion paths, not one guest.


## Follow-up: memory qualification at 16, 32 and 64 transactions

All three runs use the identical prover binary and expanded guest, accelerated
Keccak/recovery, 70 queries, 26 PoW bits, and independent recursive-root verification.
Raw evidence is in `auth-{16,32,64}-subtrees.{json,log,proof}` and the corresponding
invocation manifests. `memory-scaling-summary.json` records proof hashes and metrics.

| Transactions | Previous process peak GiB | Current process peak GiB | Current worker peak GiB | Process seconds |
| ---: | ---: | ---: | ---: | ---: |
| 16 | 23.15 | 16.14 | 16.02 | 36.21 |
| 32 | 31.19 | 16.82 | 16.59 | 41.07 |
| 64 | 55.42 | 16.69 | 16.60 | 45.69 |

Current process peaks are about 30%, 46% and 70% lower respectively. The original
16-transaction attempt failed at 55.68 GiB. These are single observations on AC
power, serialized under the build/proof lock; small non-monotonic process peaks
are not evidence of a guaranteed decreasing footprint. Historical 64 timing has
the interference qualification above. Authentication batch size is not segment
count: each of these runs contains one execution leaf plus its recursive wrapper.

The frontier ownership regression now exercises 16, 32, 64, 1,024 and 4,096
segments. After each insertion it checks retained node count equals the population
count of inserted leaves, all superseded owners are freed, and the complete root
can be transferred. `test-frontier-scaling.log`: 26 tests passed. This test uses
allocation-owning statement fixtures, not cryptographic proofs at those sizes.
The actual cryptographic streaming evidence remains the four-leaf diagnostic run.

Remaining limits: roughly 16 GiB is still a substantial per-proof working set;
this does not establish minimal memory, bounded bytes for arbitrary proof shapes,
or full-block proving. The earlier real 262,144-cycle block leaf failed lookup closure
(`UnclosedExecutionRelations`); the follow-up below resolves that failure.
The 1,048,576-cycle leaf still exceeds the commitment domain limit. Full-block
and arbitrary multi-segment memory qualification remain unfinished.

Reproduce new, non-overwriting runs with `run_auth_subtrees.py --batch 16`
(or 32/64) in a fresh evidence directory with the matching build and fixtures.


## Real block leaf: partial public-input closure fixed

`leaf-262k-inputfix.json` and its proof/log/invocation manifest qualify the first
262,144 cycles of the full 66-transaction mainnet validator. The canonical proof
was encoded, decoded and independently verified at70 queries/26 PoW bits:

- Process wall112.05s; prover phase67.73s.
- Process footprint41,505,803,688 bytes (38.66 GiB).
- Tracked allocation peak41,550,136,518 bytes under the48 GiB total limit.
- Proof2,232,549 bytes;729,419 program rows;88,687 memory boundary rows.
- **One segment verified; the complete block is not yet proven.**

The shared issue was emitting initial memory lookup tuples for every public input
word while omitting untouched input exit boundaries. Native and recursive closure
now derive input providers from the independently admitted final memory schedule.
Untouched input values stay bound by the public statement and public-custody
conversion into complete continuation roots. Admission rejects conflicting initial
input providers and clock-zero final input boundaries. Shared B3PI transcript
framing separates this authority from historical keys.

The leaf proof also releases duplicate fixed/main hash source columns once their
commitments and interactions are complete. This is shared by base and Ethereum
extension proofs, with reuse rejected after release. The next qualification frees
hash interaction source columns after their commitment as well.

`test-partial-input-consuming.log`:10 focused checks passed, including real
partial-input proofs with zero/nonzero words, independent verification, symbolic
recursive closure validation, missing-provider rejection through nonzero residual,
and safe consuming-column ownership. The initial before.log failed only due to
missing fixture input symbols; it is not a protocol regression result.


## Leaf interaction storage qualification completed

`leaf-262k-release.*`: canonical first full-validator leaf independently verifies,
262144 cycles,70 queries/26 PoW bits. Process footprint **36.53 GiB**, down from
38.66 GiB after the initial closure fix. Tracked peak39,267,758,574 bytes. Process
wall111.90s, prover67.39s. The proof is byte-for-byte identical to inputfix.proof:
SHA2564095aca10ee204276015887e842413663420b17859c113875e46f152349230d0.

`test-partial-input-release-all.log`:10 focused checks passed with source fixed,
main and interaction column release. `block-leaf-release-source.tar.gz` freezes
all Zig sources used by the direct build; `leaf-release-SHA256SUMS` pins archive,
binary, guest, input, verified proof, report and logs. No heavy jobs remain live:
sessions16139,78131,69553 all completed successfully.

Next scaling implementation is specified in MEMORY-NEXT.md: coupled entry/exit
multiproofs with shared unchanged frontier producers, and only accessed word
lookup boundaries. Current later segments classify the whole initial input as
ordinary memory; shrinking cycle budgets alone does not remove that cost.
This next change is **not implemented**. Full block aggregation and efficient
SHA/other precompile integration also remain unfinished. Goal remains active.


## Paired ordinary-memory paths and bounded windows

The paired-path change is implemented. Word-level lookup providers cover accessed
memory; full ordinary root projections remain intact. Both root paths consume the
same frontier producer identities, proving that untouched subtrees stay unchanged.
Missing public-custody sides have fixed-zero leaves. Plan identity is now
`v5.paired-memory`; old keys are incompatible. Root equality is mandatory for an
empty memory boundary schedule.

The full262,144-cycle first leaf verifies at35.21 GiB/108.80s. The second leaf of
that size fails `CommitmentTraceTooLarge` before large allocation. This cap remains
in place: large accessed sets still require bounded leaf scheduling.

Canonical32,768-cycle windows sampled after successive262,144-cycle warm-up
chunks (each independently verified,70 queries/26 PoW bits):

| Warm-up chunks | Global first cycle | Peak process GiB | Process seconds |
| ---: | ---: | ---: | ---: |
| 0 | 1 | 9.09 | 43.79 |
| 1 | 262145 | 9.09 | 44.40 |
| 15 | 3932161 | 9.13 | 46.05 |
| 63 | 16515073 | 1.25 | 38.76 |

These are isolated window proofs, NOT an aggregation of the intervening execution
or a full-block proof. The32k windows must not be compared as equal work to the
262k leaf. `paired-window-summary.json` pins exact metrics and proof hashes.

The canonical64-transaction authentication recursive root also verifies:
16.74 GiB process and58.22s (`auth-64-paired.*`). Earlier subtree custody was
16.69 GiB/45.69s. Memory is comparable; this is not a speed improvement. Different
proof/key geometry and PoW draws make single timings insufficient to attribute
that difference. The new paired path still hashes known-zero excluded-side leaves;
constant folding those public subtrees is a concrete next optimization.

Validation: `test-paired-memory.log`12 checks includes actual resumed proofs with
16 versus4096 untouched input bytes and identical hash-row counts, partial zero/
nonzero input, changed-frontier rejection, and recursive closure. Actual four-leaf
streaming root passed7 checks (`test-stream-paired-memory.log`). Updated geometry
accounting and component/storage/admission checks passed5 (`test-paired-assembly.log`).

## ROM validation cache: same proof, 2.50× faster window

Key preparation repeatedly reconstructed the full decoded-ROM Merkle root. A
bounded eight-entry process-local cache now hashes every current leaf byte and the
claimed root on every lookup, reusing only a prior successful validation of that
exact content. It uses neither pointer identity nor caller-supplied valid flags.
Invalid roots/content never enter the cache. It allocates no unbounded storage and
changes no transcript, commitment or key identity.

The same32,768-cycle first window verifies in17.51s rather than43.79s. Tracked peak
is identical at9,870,675,414 bytes; process footprint remains9.09 GiB. Proof bytes
are identical, SHA2567a24a6c2d46f840e6147c45ca233d3ad31d9b3324048b3f9d4843de816d3d8c7.
Evidence: `leaf-cached-window-0-32768-262144.*`; root/content mutation and eviction
checks passed in `test-program-cache.log`. `paired-plan-before-cache.zig` retains
the sole production-source difference for the uncached comparison.


## Known-zero paths and streaming root delivery

Commitment plan v6 folds excluded public-memory zero leaves and wholly known-zero
computed subtrees into canonical constant digests. Frontier nodes are never
folded: both memory paths retain the shared frontier lookup binding. Core roots
are unchanged; old plan keys must be rederived. Focused proof tests passed12
(`test-constant-dense.log`), assembly tests passed5 (`test-constant-assembly.log`).
Canonical64-transaction authentication with a recursive wrapper verified at
46.83s process wall time and16.81GiB peak footprint (`auth-64-constant.*`), versus
58.22s for the previous paired-path observation. This is not a memory reduction
against the earlier subtree implementation; single timing observations include
proof-of-work variance.

Streaming folders can now retain and transfer ownership of the final encoded
root artifact. Reverification requires an externally supplied admission and key
identity, not a key selected from the artifact. Real four-leaf diagnostic proof
and serialization/reverification passed7 tests (`test-stream-root-artifact.log`).
This does not constitute a full Ethereum block proof.


## Memory scaling after per-cohort source release

The consuming parent prover now frees each source-column cohort immediately
following its interaction generation. Other cohorts remain live until their own
last reader. Reusable borrowed preparations remain unchanged; partial cleanup is
idempotent. This is a general parent-prover lifetime change, not workload-specific.

Canonical CPU authentication plus recursive wrapper, q70/PoW26,16workers, AC power;
one observation per size:

| Transactions | Process peak GiB | Worker allocation peak GiB | Wall seconds |
| --- | ---: | ---: | ---: |
| 16 | 15.75 | 16.02 | 38.43 |
| 32 | 16.59 | 16.59 | 41.93 |
| 64 | 16.47 | 16.60 | 47.85 |

All three proofs independently verified. The64-transaction proof is byte-identical
to auth-64-constant.proof. Ownership cleanup passed1 focused test in
`test-cohort-storage-qualified.log`; the earlier similarly named log selected0
tests and is not qualification. Actual four-leaf streaming recursion and retained
root verification passed7 tests in `test-stream-cohort.log`.

The worker's tracked high-water allocation remains essentially unchanged. Lower
process footprint must not be mistaken for a comparable reduction in allocated
bytes: these measure different things. Source lifetimes improve, but later core
proof allocations still set a substantial peak. The earlier public-subtree change
provided the main16/32/64 scaling improvement from23.15/31.19/55.42GiB.

These transaction batches each have ONE execution segment plus a recursive
wrapper. They do not measure16/32/64 recursive tree levels or full block proving.
The streaming frontier's ownership tests reach4096slots; only the four-leaf
integration is a real cryptographic tree test here. Neither establishes GPU VRAM.
Raw reports, proofs, invocation identities and summary are `auth-*-cohort.*` and
`cohort-scaling-summary.json`; scripts retain the exact invocations.


## Complete-execution streaming command (qualification in progress)

`src/frontends/riscv/ethereum_block_stream.zig` connects bounded preflight,
balanced replay, Ethereum execution proofs, native recursive wrappers, streaming
folds and a saved/reverified root. Current build: `python3 .../build_stream_policy.py` (output `block-stream-policy`).
Invocation:

```
block-stream-policy ELF INPUT ORACLE MAX_SEGMENT_CYCLES PROOF REPORT canonical [paired]
```

`diagnostic` selects q8/PoW0 and is explicitly marked noncanonical in the report;
`canonical` selects q70/PoW26 for both execution and every recursive level.
Reports include complete-job statement, derived admission, source/input/output and
proof hashes, times, segment count and shared allocation peak. The admission
manifest must be independently pinned by a receiver; a manifest supplied alongside
a proof does not establish its own trust. Files are created exclusively after
complete proof verification. An incomplete run writes no success report.

Preflight keeps endpoint values, not endpoint traces. Replay checks exact indices,
cycle budgets, completion position and oracle output, proves each leaf, and folds
only adjacent authenticated spans. A shared48GiB routed allocation budget covers
all work. The frontier retains at most one verified subtree per height.
This command is implemented; full66-transaction block proof qualification is still
outstanding. Small complete-guest qualification results will be recorded below.


### Streaming complete-guest qualification

The expanded one-transaction authentication ELF executes21,635cycles. Unlike the
single-wrapper batch measurements above, this command proves every segment of a
replayed complete guest and all recursive levels, then decodes and reverifies the
saved root. Results (`stream-qualified-summary.json`):

| Profile | Actual execution leaves | Tracked peak GiB | Process peak GiB | Proving flow seconds |
| --- | ---: | ---: | ---: | ---: |
| diagnostic q8/PoW0 | 8 | 4.05 | 3.46 | 64.26 |
| canonical q70/PoW26 | 2 | 19.77 | 15.53 | 70.35 |

Endpoint source-validation, wrong side/count/program rejection and an actual
Ethereum adjacent-segment proof passed8 tests (`test-stream-endpoints.log`).
The canonical16-leaf run is now in progress; do not infer its result from these
smaller runs. No full66-transaction block proof has completed.

Full-block execution can optionally record a PC histogram without retaining any
prior trace: `block-execute-profile ELF INPUT ORACLE REPORT 262144 PC_COUNTS`.
Every base instruction is counted and total count plus native precompile calls
must equal executed cycles. `symbolize_execution.py` checks the ELF hash and maps
counts to containing function symbols; these are instruction counts, not inclusive
call costs, host precompile costs or predicted proving times.


### Canonical16-leaf completion and pairing trade-off

The original streaming command completed16real execution leaves and all4recursive
levels at q70/PoW26, including decoding and independently verifying its saved root.
Time618.47s; tracked allocation peak19.49GiB; process footprint15.33GiB.
This covers the complete21,635-cycle one-transaction guest, not16transactions and
not the66-transaction block. Compared with2leaves, memory did not grow materially.

Direct pair preparation was also implemented and verified: two execution proofs
can feed their first recursive parent directly, eliminating single-leaf wrappers.
For2leaves, flow time70.35→59.12s, but process peak15.53→29.62GiB and tracked
peak19.77→30.52GiB. Both proofs bind the identical complete-execution statement.
Because memory is the priority, direct pairing is NOT the default. The unified
coordinator accepts an optional final `paired` argument for explicit experiments.
Default uses one leaf per preparation. The final default-policy regression passed in69.06s with15.53GiB process peak;
its proof is BYTE-IDENTICAL to the original unpaired canonical proof. Evidence:
stream-policy-auth1-canonical-16384.*.

### Shared decoded-program root cache

Root computation and validation now share the8-entry content-addressed cache in
`air/program/blake3_root_cache.zig`; the former prover-only cache moved there.
Every lookup hashes current leaf contents and compares any claimed root. Mutations,
wrong roots and eviction remain checked.3focused tests passed.

A same-binary q70/PoW26 real block-leaf comparison, first32768cycles:
16.57s uncached root computation vs15.45s cached; tracked peak9.19GiB unchanged.
Proof bytes are IDENTICAL. The research control
`STWO_RISCV_UNCACHED_PROGRAM_ROOT` bypasses computation reuse only; proof admission
and root validation remain mandatory. Single observations, not statistical medians.
Details: program-root-cache-summary.json and leaf-root-cache-window-* artifacts.

### Full-block instruction profile and SHA foundation

Profiled all253,646,998cycles and verified the43-byte oracle. Every base instruction
plus native Keccak/recovery call is accounted for. Containing-symbol counts:
k25640.85%, memcpy18.96%, SHA256compression4.48%.66transaction recovery calls already
use the proved native path.12Revm EVM recovery calls remain software; the
supplied-public-key verification callback has0entries. These are guest instruction
counts, not host precompile time or direct STARK timing estimates.

General SHA compression semantics now live in sha256_compression.zig, shared with
the old fixed-pair candidate. Arbitrary chaining-state and padding-boundary tests
passed2; fixed-pair AIR/caller regressions passed25. Production SHA dispatch and
efficient typed AIR are NOT integrated. See SHA-NEXT.md and EVM-RECOVERY-NEXT.md.


Current implementation source is frozen in `stream-memory-profile-source.tar.gz`.
`stream-unpaired-source.tar.gz` reproduces the original16-leaf command using the
previous frozen cohort source plus hash-verified stream/endpoint additions. The
exact experimental direct-pair driver is retained in stream-paired-driver.zig.source.
Historical binaries and proofs are preserved; current build scripts emit distinct
names. `stream-memory-profile-SHA256SUMS` binds the source snapshots, completed
proofs/reports/logs, profiler output and current scripts. EVM acceleration described
in EVM-RECOVERY-NEXT.md remains a design for the next implementation, not active.

### Persistent metadata and recursive-plan lifetimes

The native recursive parent now keeps content-derived BLAKE3 digests and lengths
for fixed-row validation instead of retaining another full metadata copy. Each
current preparation still owns its rows until interaction generation finishes.
The independent fixed commitment is unchanged; the digest is computed internally
and is never accepted from the caller as proof authority.

Canonical transaction-authentication qualification (CPU, q70/PoW26):

| Transactions | Previous worker peak GiB | New worker peak GiB | Previous process peak GiB | New process peak GiB | New total seconds |
|---:|---:|---:|---:|---:|---:|
| 16 | 16.02 | 14.52 | 15.75 | 14.76 | 40.01 |
| 32 | 16.59 | 15.10 | 16.59 | 15.50 | 44.29 |
| 64 | 16.60 | 15.10 | 16.47 | 15.36 | 49.85 |

All three proofs independently verify and are **byte-identical** to their earlier
cohort-release counterparts. Each run authenticates Ethereum transactions in one
execution leaf plus one recursive parent; these are not full block proofs or
16/32/64-leaf aggregation trees. Timing increased from 37.78/41.88/47.80 s; this
change prioritizes memory, and is not claimed as a speed improvement. Worker
allocation accounting and macOS physical footprint are different measurements.
Sources and manifests: `memory-lifetimes-summary.json`,
`auth-{16,32,64}-memory-lifetimes*`, `summarize_memory_lifetimes.py`.

The streaming folder additionally evicts incompatible cached plans before
independent key derivation and replacement, preventing old fixed commitments
from overlapping new ones. Matching structures remain reusable. General worker
APIs retain their failure-atomic replacement semantics. Stream qualification is
pending; do not infer a measured aggregation benefit from the table above.

The complete canonical **16-leaf** stream subsequently passed: tracked peak
**19.49 → 18.06 GiB**, process footprint **15.33 → 14.40 GiB**, elapsed time
**618.47 → 678.91 s**. The saved root was decoded and independently verified,
and is byte-identical to the earlier root. This covers all 21,635 cycles of the
one-transaction authentication guest, across four aggregation levels. It is
separate from the 16/32/64-transaction table and is not a full Ethereum block.
See `stream-lifetimes-summary.json` and `MEMORY-LIFETIMES.md`.

### EVM recovery and guest memcpy execution qualification

The real 66-transaction block (24,628,607) now executes in **139,213,662 guest
cycles / 39.92 seconds**, versus 253,646,998 / 79.52 seconds previously. This is
execution, not proof-generation time. Every run matches the exact 43-byte oracle.

| Guest variant | Cycles | Native recoveries | Execution seconds |
|---|---:|---:|---:|
| Original | 253,646,998 | 66 | 79.52 |
| EVM recovery adapter | 141,105,392 | 78 | 43.40 |
| Adapter + shared memcpy, final ABI | 139,213,662 | 78 | 39.92 |

The software collector observed 12 valid EVM recoveries. Its optional footer
contains success-selection bits, not trusted public keys or results. Positive
selections invoke the existing successful-recovery native operation; a false
success must fail execution/proving. Unhinted/negative cases use Revm software.
High-s EVM signatures are normalized with the corresponding parity change.
The canonical SSZ prefix and normal output stay unchanged. Collector output is
not a proof or a new cryptographic authority. Native call count is now 66
transaction recoveries plus 12 EVM recoveries; Keccak calls remain 32,835.

The shared RV32 memcpy uses ordinary guest instructions with bounded aligned
loads/stores and exact byte tails. ELF symbols confirm it replaces compiler
builtins memcpy. It adds only a small cycle improvement here; the main win is
EVM recovery. Host differential/boundary tests passed earlier, and the final C
ABI signature removes the runtime-symbol warning. Actual proving qualification
of this new guest path is still pending. See `evm-execution-summary.json` and
per-run input/ELF manifests.

The first real accelerated EVM recovery has now also passed canonical **segment
proving**: segment 1680, global cycles 55,050,241 through 55,083,008, containing
native recovery 67 at cycle 55,074,081 and seven Keccak calls. The encoded proof
was decoded and independently verified at 70 queries / 26 PoW bits. Witness
construction took 5.72 s, proving 5.78 s, and tracked peak was 3.83 GiB.
Replay to reach that segment took 83.87 s and is reported separately. This is
one real block segment, not a complete block or a newly qualified recursive root.
Evidence: `evm-first-recovery-leaf.json`, its invocation manifest and proof,
plus `evm-recovery-locations.json`.

### Recursive recovery capture and packed SHA arithmetic

The real EVM recovery segment also passed a native recursive **capture** proof at
70 queries / 26 PoW bits. Parent preparation took **11.25 s**, parent proving
**16.30 s**, and the worker peak was **14.38 GiB**. The 983,225-byte saved parent
proof was decoded and independently verified after releasing its proving worker.
This verifies the admitted execution capture; it does not attach Span custody or
claim a complete block root. See `evm-recursive-summary.json`.

Packed SHA arithmetic is now implemented and tested, but remains inactive in
production until caller, memory, constant, and inter-round wiring are complete:

| Operation | Main arithmetic columns | Direct constraints | Lookup events |
|---|---:|---:|---:|
| SHA round (next a/e) | 164 | 40 | 126 |
| Message expansion | 88 | 28 | 60 |
| Feed-forward addition | 16 | 4 | 8 |

Typed constraints and witness emission share `sha256_word_program.zig`.
Arithmetic uses byte lookup bounds and 16-bit additions/rotation equations, all
strictly below M31. Exact semantic digests and geometry are pinned. Tests cover
boundary/random inputs, all compression rounds and expansion steps, mutated
scratch coordinates, and out-of-range bytes, using the actual shared lookup-table
membership implementation. Masked input changes are checked against the scalar
reference rather than incorrectly assuming that SHA is injective in every input.
These are arithmetic/lookup-membership checks, not a production SHA STARK proof.
Final evidence: `test-sha-packed-tables.log` (two substantive tests passed).

## Current recursion memory qualification (2026-09-25)

CPU native recursion now retains coefficients for large commitment columns, hashes incoming LDE batches incrementally, evaluates composition in bounded cosets, and regenerates openings in bounded parallel batches. Recursive row assembly releases copied sources before arithmetic lowering. Proof parameters and proof bytes are unchanged.

| Authentication transactions | Worker peak GiB | Process peak GiB | End-to-end seconds |
| --- | ---: | ---: | ---: |
| 16 | 9.281 | 9.625 | 44.331 |
| 32 | 9.584 | 10.009 | 49.465 |
| 64 | 9.584 | 9.858 | 52.797 |

These are canonical q70/26, precompile-enabled authentication guests with one leaf and one recursive parent. All three artifacts verify and exactly match the prior proof bytes. Single observations on AC power; worker and process counters have different scopes. The complete 16-leaf tree also verifies with the same root proof bytes: tracked peak fell 18.06 → 10.09 GiB (44.1%), physical peak 14.40 → 9.30 GiB (35.4%); runtime rose 678.91 → 794.60 seconds (17.0%). The complete 32-leaf/63-job tree freshly verifies at 10.091 GiB tracked peak and 9.272 GiB physical peak, taking 1562.10 seconds. Tracked peak grows only 0.00624% from 16 leaves, with the same complete execution statement.

[Implementation, validation, memory definitions and raw artifacts](MEMORY-POLYNOMIALS.md).

## Complete 64-leaf memory qualification

The canonical q70/26 authentication tree freshly verifies at 64 leaves / 127 proof jobs / six aggregation levels: 10.091 GiB tracked peak, 9.279 GiB physical process peak, 3137.641s total. Tracked memory grows only 0.00818% from 16 to 64 leaves (under 1 MiB), with matching complete execution/ELF/input/output identities. This is the same guest split into more leaves, not a full Ethereum block. The 16-leaf improvement over baseline remains 44.1% tracked / 35.4% physical, with 17.0% more CPU time. See [MEMORY-POLYNOMIALS.md](MEMORY-POLYNOMIALS.md) and `memory-scaling-qualified-summary.json`; regenerate all three results with `summarize_memory_scaling.py --include-64`.

## Current SHA integration foundation

All focused Zig gates and Rust framing tests pass; native RV32 ABI compilation passes. Canonical standalone memory-call proof: 25.513s; compression proof: 4.856s. Production VM SHA activation remains unfinished. See [SHA-MEMORY.md](SHA-MEMORY.md) for scope and evidence.

## SHA-capable guest execution

Explicit ELF profile 4 (capabilities 14, ABI 1) now executes SHA/Keccak through the canonical segmented and one-shot session. Both clock frames, malformed admission rejection and old-profile isolation pass: `test-sha-profile-5.log`, 20 tests. Combined leaf proof wiring and recursive guest qualification remain incomplete. See [SHA-MEMORY.md](SHA-MEMORY.md).


## Qualified stage measurement check

The new CPU measurement path passed on the existing authentication fixture:
21,635 executed cycles, one execution leaf and its recursive wrapper, canonical
70 queries / 26 PoW bits, AC power before and after. This is **not a full Ethereum
block benchmark**. The root was freshly verified and every workload/artifact
hash matched the invocation.

| Metric | Measurement |
| --- | ---: |
| Process wall | 41.912504 s |
| Prover pipeline | 41.205360 s |
| Tracked allocation peak | 10,010,117,687 bytes (9.323 GiB) |
| OS physical footprint peak | 10,138,544,520 bytes (9.442 GiB) |
| Proof size | 981,446 bytes |

| Stage | Wall time |
| --- | ---: |
| preflight | 0.009538 s |
| replay execution | 0.003700 s |
| witness preparation | 1.512627 s |
| verifier preparation | 0.669343 s |
| leaf proof and recursive witness | 17.040524 s |
| recursive proving and aggregation | 21.952648 s |
| final root verification | 0.015759 s |

Evidence: [measurement.json](measurements-auth1-canonical-stages/measurement.json),
[proof report](measurements-auth1-canonical-stages/proof-report.json), and
[process log](measurements-auth1-canonical-stages/run.log). No speedup is claimed
from this instrumentation run. Transaction/gas throughput for the mainnet block
will be derived only after its complete root is verified.


## Canonical combined SHA leaf and source artifact qualified

`test-sha-combined-leaf-5.log`: all nine focused tests pass. Both full-table and
compact-provider versions of the admitted SHA → Keccak → SHA guest produce a
canonical **70-query / 26-PoW** STARK through the shared extension pipeline.
The original witness and prepared key are released before verification. The
strict combined proof codec round-trips; a modified SHA claim is rejected.
A separate key is derived from decoded metadata. The full source-bound artifact
then independently authenticates the supplied ELF/input, decodes its manifest,
derives another key and freshly verifies the proof.

| Provider mode | Inner proof bytes | Qualification elapsed |
| --- | ---: | ---: |
| Full tables | 4,108,400 | 4.647371334 s |
| Compact | 4,031,494 | 2.980226500 s |

These timings include witness/key preparation, artifact serialization, negative
claim verification and repeated positive verification. They are correctness-gate
timings, not an isolated prover benchmark or a full Ethereum block measurement.

The new B3ES profile uses allocator-aware admission and prepared-key identity,
832-byte extension metadata that binds all five SHA semantic/geometry descriptors,
and a disjoint B3SVART1 source envelope. SHA coefficient derivation is charged to
the caller's allocator. Compact transcript mixing now completes allocating
admission once before changing the channel; a capped allocator test verifies that
mixing does not allocate a second admission pass after channel mutation.

Existing Ethereum and guest-Poseidon full proofs, outer artifacts and recursive
replay checks passed in `test-sha-combined-leaf-4.log`. That entire invocation
failed because its SHA fixture lacked release ABI symbols. The production source
validator correctly rejected it; the fixture now uses the complete release ABI.
`-5.log` qualifies the corrected SHA fixtures. The earlier challenge-adapter type
mismatch was fixed by retaining each profile's fixed draw count at replay.

Source archive and exact hashes: `sha-combined-leaf-qualification.json` and
`sha-combined-leaf-source.tar.gz`. Combined SHA recursion remains unqualified;
the Ethereum guest SHA SDK provider, full mainnet block root, and GPU qualification
remain pending. The recursion handoff above lists the required symbolic challenge,
claim routing and geometry changes.


## SHA recursion, custody and default EVM provider qualification

Canonical combined SHA recursion is now qualified. The closed capture mapping,
profile-aware transcript replay, native public compensation and DEEP geometry
support the explicit SHA profile. Challenge replay retains the SHAW domain frame;
only SHA's internal wire relation is replaced with its separate symbolic pair.
The recursive composition recorder replays the fourteen Ethereum components and
all five SHA typed AIRs using the native verifier's authenticated programs. Its
constraint census covers all nineteen components. SHA claims remain circuit
inputs bound to the transcript, and changed claims are rejected.

`test-sha-recursive-parent-1.log`: all eight tests pass. A canonical SHA/Keccak
leaf produced a canonical recursive parent, serialized it, released the worker
and rows, and freshly verified the parent. Parent path: 48.822127125 seconds,
including 8.880612500 seconds preparation and 33.239605583 seconds proving;
979,542-byte parent artifact; tracked worker peak 9,818,400,272 bytes.
This worker peak excludes separately retained preparation allocations.

`test-sha-recursive-segments-1.log`: all eleven tests pass. Two adjacent SHA-profile
segments (SHA, then Keccak/SHA) prove full memory custody, aggregate, serialize,
and freshly verify a complete root at **70 queries / 26 PoW bits**. Elapsed:
121.026120416 seconds; parent artifact: 1,015,674 bytes; tracked worker peak:
19,183,383,520 bytes, excluding 9,104,411,864 retained preparation bytes. This is
a paired two-leaf qualification fixture, not a mainnet block timing or a claim
that the earlier unpaired streaming footprint increased. Existing Ethereum
boundary aggregation and guest-Poseidon proof/replay regressions also pass.

The shared segment-pair API now selects base, Ethereum or Ethereum/SHA by explicit
execution profile. The block stream and bounded preflight use that same profile
selection. There is no alternate SHA proof engine. The ISA activation marker is
true for this explicit capability; runner markers reference that single constant.
Older executable profiles continue to reject the SHA instruction.

The Rust Ethereum guest now defaults to a `sha256-precompile` feature and overrides
revm's `Crypto::sha256` through the shared allocation-free SDK. Its ELF note selects
profile 4 / capabilities 14 / ABI 1 at the same time. `--no-default-features` retains
the prior explicit profile for comparisons. Other SHA2 uses outside that EVM
provider are not automatically redirected. All three independent host framing
and alignment tests pass, and the default RV32 guest builds. A build-time check
now compares the emitted capability note with the canonical semantic digest.
The initial guest artifact was correctly rejected for a mis-transcribed digest;
`ethereum-block-sha-default-v2.elf` contains the corrected, checked note. Earlier
failed build/execution logs are retained as failed attempts.

The corrected guest executes mainnet block 24,628,607 (66 transactions) and matches
the existing expected output: 139,214,856 cycles, 32,835 Keccak calls, 78 recoveries,
**zero EVM SHA compression calls**, 40.089439375 seconds runner elapsed,
40.156780125 seconds process wall, and 256,713,536 bytes peak physical footprint.
This establishes guest integration compatibility, not a SHA speedup or native SDK
runtime-vector coverage. The previous guest executed 139,213,662 cycles in
39.916791458 seconds; these single runs are not a controlled performance comparison.

A full canonical block proof has started in
`measurements-mainnet-24628607-sha-canonical-4194304`, using the new profile-aware
stream binary and a 4,194,304-cycle upper bound. Its successful root has **not**
yet been observed. Power status is recorded by the measurement harness; this run
started on battery at 100%. Full block proof and GPU qualification remain pending.
The next SDK gate should execute native Rust SHA framing against known vectors;
the chosen mainnet fixture does not exercise that callback.

Exact sources and hashes: `sha-recursive-delivery-qualification.json` and
`sha-recursive-delivery-source.tar.gz`.


### SHA preflight profile correction

The initial full block proof attempt above **failed** after 1.23 seconds with
`InvalidPrecompileEncoding`; no proof was produced. Preflight execution selected
the SHA profile correctly, but its program commitment still used the old Ethereum
decode authority. That authority is now passed through both endpoint commitments.
The strict replay check supports the same two explicitly admitted profiles.
The terminal-publication regression now runs for both profiles, including an
unexecuted SHA instruction in the declared program, and all 15 focused checks pass.
Source archive and hashes: `sha-preflight-profile-fix-qualification.json`.
The failed run and its measurement are retained. Full block proof timing and memory
remain unqualified until a successful independently verified root is produced.


### Native Rust SHA SDK execution qualified

`sha-native-vectors-v1/qualification.json` records 44 native RV32 digest vectors:
offsets 0–3 and lengths 0, 1, 55, 56, 63, 64, 65, 127, 128, 129 and 1024 bytes.
All outputs match independent Python hashlib SHA-256, with exactly 148 admitted
compression instructions, 38,367 guest cycles, and no Keccak or recovery calls.
This covers padding boundaries and the direct aligned / copied unaligned block
paths using the actual SDK assembly instruction. It is an execution qualification,
not a proof timing. The test executable and Ethereum guest share the capability
note in `ethereum_admission_v1.rs`; the duplicate note was removed from main.rs.
`sha-native-sdk-vectors-source.tar.gz` preserves the sources. This closes the native
SDK vector gap above; the pinned mainnet fixture itself still has zero SHA calls.


### Full block proof partition qualification remains pending

The corrected preflight completes all 139,214,856 cycles in 10.049406584 seconds
with the 4,194,304-cycle counting limit, checks the expected output, and plans 64
leaves. The first witness then fails `CommitmentTraceTooLarge`: the supported
commitment AIR log-size cap is 24. This cap was retained. Failed invocation:
`measurements-mainnet-24628607-sha-canonical-4194304-v2/measurement.json`.
A smaller 262,144-cycle partition is now under measurement with witness-stage
profiling enabled. There is still no successful full-block root or block proof
throughput claim. The repeated SHA guest build after extracting the shared ELF
note passes (`build-sha-ethereum-guest-v3.log`, ELF/build manifest v3).

### Segment sizing and ZisK architecture audit

See [ZISK-SEGMENT-SIZING.md](ZISK-SEGMENT-SIZING.md) for measured 128/256/512-leaf commitment sizes and the pinned ZisK source comparison. The previous 1024-leaf job was stopped deliberately after 20 verified leaves; it did not complete a block root. The log-25 admission extension passes its allocation-free boundary test and builds, but full-custody qualification of the larger terminal leaf remains in progress. ZisK’s separate sorted-memory proofs and component-specific size selection are architectural opportunities, not measured speedup claims.

### Separate sorted-memory CPU proof, first mainnet instance

The frozen 218-segment SHA fixture replayed and sorted 356,303,914 real memory
events. Its **first** independently sized log-20 instance (1,048,576 rows)
produced a request-only STARK and passed fresh CPU verification at 70 FRI
queries and 26 PoW bits. Replay/sort took 63.492 seconds; fixed/main commitment
2.278 seconds; proving 22.645 seconds; and verification 0.381 seconds. The
Postcard STARK was 406,342 bytes and tracked peak live memory was 6.464 GB
(6.02 GiB). This is a single sample with PoW search variance. It excludes the
shared byte-range table proof, execution transition proof, authenticated
initial-value providers, and the remaining sorted-memory instances, so it is
**not** a complete block proof or a total-time estimate. Exact configuration,
source/input hashes, and raw nanosecond results are in
[`exact-schedule-memory-roster-v1/first-log20-memory-proof-v2-q70-pow26.json`](exact-schedule-memory-roster-v1/first-log20-memory-proof-v2-q70-pow26.json).

The block-v2 memory producer now has a bounded two-pass path. It first
commits each sorted instance and accumulates byte-table counters in exact,
field-safe shards, retaining only public claims, first roots, and the shard
counters. After the full root roster is sealed, it reopens the same sorted run,
rebuilds and compares each root, and proves one instance at a time. Proof files
are staged; a scoped `memory-range.complete.v2` marker appears only after all
memory and shared-table proofs pass fresh verification and their link/range
claims close. The marker does not assert execution or initial-state closure.

### Public initial-RW fallback on the mainnet roster

A fresh SHA-profile ELF/input session independently derived the initial
continuation RW root. A verifier-visible complete nonzero image (666,708 words,
5.3 MB) rehashed to that root, and an ordered 31.4 MB roster checked all
3,142,932 first touches: 3,142,901 RW/input, including 2,484,479 implicit
zeros, and 31 registers. There were no program first touches. Root, merge,
source classification, register values, and the positive initial relation
claims took **0.226 seconds** with **118.9 MB tracked peak**; fresh session
setup took 0.250 seconds. The roster is directly bound to SourceSeal v3 before
challenge draw. A focused 2+1-instance receiver test freshly verifies
serialized sorted-memory and shared-table STARKs, then closes their initial
claim with this public source. The mainnet measurement itself is a scoped
host-visible fallback, with benchmark-only non-source seal fields; it does not
verify the whole block or execution relation. Exact claims and source hashes
are in [the fallback result](exact-schedule-memory-roster-v1/public-rw-fallback-v2.json).
The receiver contract and exact recursive-root layout are tracked in
[BLOCK-ARCHITECTURE-V3.md](BLOCK-ARCHITECTURE-V3.md) and
[exact-root-v2.md](exact-root-v2.md).

### Block-v4 CPU assembly with real public I/O

A small terminal Ethereum-SHA-profile segment now runs through the reusable
CPU batch assembler and passes fresh block-v4 core verification with a
four-byte public input, four-byte public output, output-length and halt stores,
and one Keccak call. At diagnostic q8/PoW0 it closed all 70 execution/sorted
memory transitions, including 51 external caller accesses, in **5.416 s**
assembly/proving/verification wall time with **520.4 MB tracked peak**. The
STARK/native-artifact byte arrays total **1,651,532 B**, excluding separate
claims/statement metadata. Verifier-visible source files add **2,040 B** for
the initialized nonzero image (including Keccak state) and **590 B** for 59
first-touch records. This scoped core run excludes recursive leaf and outer
proofs and does not measure a mainnet block. [The result JSON](block-v4-cpu-real-io-small-q8.json)
records exact metrics, source hashes, and qualification limits.

### Signer and Keccak shared-memory core

A one-segment Ethereum-SHA-profile guest with real secp256k1 recovery and
Keccak calls passed fresh diagnostic q8/PoW0 block-v4 core verification.
Its 103 sorted-memory events comprised 9 opcode accesses, 43 signer caller
accesses and 51 Keccak caller accesses. The receiver checked the native proof,
both execution sidecars, sorted memory, initial values, separate byte tables,
and global transition closure; removing the extension proof was rejected.
This qualifies the shared core for signer memory effects but does not include
recursion or a canonical-security claim. [The result JSON](block-v4-signer-keccak-core-q8.json)
records the scope and exact event counts.

The same signer/Keccak core also produced a freshly verified diagnostic
recursive leaf (151,867 B) and exact singleton outer proof (132,954 B) at
q8/PoW0. Their proving stages took 5.966 s and 2.444 s, with a 3.755 GB
tracked recursion peak. [The recursive result](block-v4-signer-keccak-recursive-q8.json)
remains diagnostic; the canonical complete receiver requires q70/PoW26.

The signer/Keccak guest subsequently passed that canonical q70/PoW26 complete
receiver, returning `complete_block_verified` for all 103 memory events. Its
recursive leaf and exact outer proofs were 978,396 B and 930,940 B; their
proving stages took 33.804 s and 13.722 s, with a 13.734 GB tracked recursion
peak. The measured stages exclude core proving and verification, and the guest
is still one small segment rather than an Ethereum block. [The canonical
result](block-v4-signer-keccak-complete-q70.json) records the scope and limits.

### Two-pass block-v4 streaming core

The two-segment real-I/O q8/PoW0 fixture now passes with a two-pass producer
and a fresh incremental core receiver. It has 70 memory events, including 51
Keccak caller accesses, and clean receiver allocator teardown. Streaming
production took **7.507 s**; fresh core verification took **4.508 s**.
The receiver allocator's **356.8 MB** peak excludes staged proof buffers
allocated by the producer, so it is not a process peak. A third pinned guest
replay reconstructs each native verifier one segment at a time. This bounds
retained verifier state but is not succinct verification. The result is a
small diagnostic core qualification, not a recursive receipt or full block.
[Scoped result and limits](block-v4-cpu-streaming-incremental-real-io-q8.json).

The joined diagnostic q8 receiver subsequently passed on the same real-I/O
shape, fresh-verifying two recursive leaves, a dyadic parent and an exact
outer root after incremental core closure. Wrong outer-key and forest pins
were rejected. Staged production took **7.627 s**, recursive proof generation
**33.908 s**, and fresh complete verification **5.180 s**. Its recursive
proofs still came from a bounded in-memory fixture, and test pins came from
those proofs; the staged recursive producer and independently pinned CLI are
separate work. [Scoped complete result](block-v4-cpu-streaming-complete-real-io-q8.json).

The same two-segment real-I/O shape passed the **canonical q70/PoW26** complete
receiver with clean teardown. Its 70 events include 51 Keccak caller accesses
in the terminal leaf and no external calls in the first. Staged core
production took **10.148 s**, recursive proof generation **167.262 s**, and
fresh complete verification **5.600 s**. Recursive proofs still came from
the bounded in-memory fixture and its expected outer/forest pins were derived
there; [the canonical result](block-v4-cpu-streaming-complete-real-io-q70.json)
does not measure a full block or production pin policy.

The separate staged q8 recursion path now also passes on two real-I/O
segments: it proves hash-pinned leaf files one at a time, one dyadic parent
(140,292 B, 7.421 s), and one exact outer proof (135,976 B, 8.510 s).
Parent and outer file tampering are rejected on reload, and allocator teardown
is clean. These files remain provisional until a separately pinned canonical
file-backed receiver admits them. [Staged result](block-v4-cpu-staged-outer-real-io-q8.json).
