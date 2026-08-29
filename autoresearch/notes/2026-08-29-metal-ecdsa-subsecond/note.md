# Metal ECDSA sub-second autoresearch campaign

- Date: 2026-08-29
- Starting commit: `d3e88a653d03fc7e708cf345a33481d26b8410c6`
- Host: Apple M5 Max, arm64 macOS, Zig 0.15.2
- Primary boundary: the upstream EthProofs CSP `proof_duration`, which times
  execution, witness generation, and cryptographic proving while excluding
  preparation and verification
- Regression guardrail: the complete secure ECDSA/32 request, including
  in-process verification and request overhead
- Stretch target: less than 1.000 second without benchmark-specific behavior or
  changes to proof/security/statement/transcript semantics

## Initial design brief

Workload and target devices: the ordinary secure RISC-V CSP ECDSA/32 request on
Apple M5 Max, with every retained change applicable to the general prover or a
well-defined class of components.

Unit of work and equivalence oracle: one verified 5,425,005-step execution with
94 proof components. The decoded proof, statement digest, transcript state,
execution result, and verifier verdict must remain bit-exact.

Measurement boundary and baseline: ReleaseFast CSP `bench`, reverse-balanced
A/B where practical. The retained prior candidate measures about 3.270 seconds
per verified request: 0.329 seconds execution, 0.367 seconds witness, 2.398
seconds proving, and 0.128 seconds verification.

Measured bottleneck: the prior Metal trace attributes about 0.756 seconds to GPU
execution (Merkle commitments 0.417 s, circle LDE 0.137 s, PoW 0.085 s, lookup
evaluation 0.074 s, base-polynomial evaluation 0.018 s). Therefore shader-only
tuning cannot reach one second; the campaign must also reduce host fallback,
memory traffic, submission/wait boundaries, or dependent CPU phases.

Required features and fallback: authenticated AOT Metal kernels on supported
Apple GPUs; unchanged CPU/reference paths and fail-closed capability admission.

Resource and scheduling hypothesis: ECDSA exposes the largest component roster
and host fallback surface. The first target is to identify proof-time CPU work
that can be expressed through existing prepared-domain/component authorities,
then move or fuse it without changing work. Merkle pass/byte reduction is the
second target. Persistent arenas and existing command ownership remain the
only resource-lifetime authority.

Expected falsifier: if host samples show no dominant transferable fallback and
GPU trace remains below one quarter of request latency, sub-second latency is
not attainable by safe Metal backend implementation changes alone. Retain only
changes whose complete CSP result moves outside noise and whose proofs remain
exact across a second workload.

## Results

### Baseline attribution

A 21-sample current-product run measured 4.012031 seconds median on the live
host, with mean execution/witness/proving/verification partitions of
0.417750/0.511033/2.884541/0.149770 seconds. This run is a local optimization
baseline rather than a release result; the previous reverse-balanced retained
candidate remains 3.269912 seconds.

The selected lookup layout is already the default in current source. All 94
opcode semantic and 94 opcode lookup components execute through resident Metal
polynomial programs. A profiled proof exposed the remaining 11 infrastructure
components (registry 188--198) as a 128.49 ms host graph; Poseidon infrastructure
was the 73.64 ms critical path. Eliminating that graph alone cannot reach the
target.

The retained command profile instead attributes 210.79 ms and 172.12 ms GPU
time to the main and interaction Merkle commitments. Their leaf kernel uses a
runtime BLAKE2s sigma table even though every round and message index is fixed.
An isolated eight-block compression experiment over 1,048,576 independent
threads measured:

| implementation | median GPU time | minimum GPU time |
|---|---:|---:|
| runtime round/sigma indexing | 2.921 ms | 2.920 ms |
| explicitly unrolled constant indices | 1.220 ms | 1.218 ms |

The 58.2% isolated reduction is large enough to justify a production experiment.
The transformation preserves the BLAKE2s algorithm and applies to every Metal
Merkle leaf/parent, FRI leaf, and proof-of-work compression; no workload shape
or ECDSA identity enters the rule.

The authenticated core AOT gate accepted all 136 exact kernel exports with
zero function constants and AOT/JIT parity. A reverse-balanced B/A/A/B CSP run
with three verified samples per leg then measured:

| workload | baseline median | candidate median | reduction |
|---|---:|---:|---:|
| ECDSA/32 | 3.628815 s | 3.263359 s | 10.1% |
| Keccak/128 | 0.913702 s | 0.835285 s | 8.6% |

Across the ECDSA legs, mean proving time fell from 2.598145 to 2.284142 seconds
(12.1%). All four ECDSA artifacts decoded to the same 3,304,541-byte proof with
SHA-256 `eaa345bdb4435f12c1da4d914e700fdff6b50f0d94b4f6c02ffddf0c2633782d`;
the statement and transcript digests were also identical. All four Keccak
artifacts likewise decoded to one 827,978-byte proof with SHA-256
`b060b18a76d3ec5611ec79ddf58e15a1827e30584c21aaa05fb35d46a83063a8`.

The candidate Metal command profile attributes the end-to-end change to the
intended kernels. Total measured GPU command time was 522.45 ms. Merkle commit
fell from the retained 415.10 ms profile to 189.24 ms, while proof-of-work fell
from 85.27 to 31.49 ms. Circle LDE (180.39 ms), lookup evaluation (74.15 ms),
and base polynomial evaluation (18.45 ms) remained essentially independent of
the BLAKE2s transformation.

Packing two or four independent hashes into one thread was rejected. For the
same total isolated work, `uint2`-style ownership took 1.535 ms and four-hash
ownership took 2.798 ms, versus 1.220 ms with one hash per thread. The wider
forms lose occupancy and instruction-level scheduling freedom on this GPU.

This experiment is retained. The next general target is submission and memory
ownership: the heterogeneous one-submit circle-LDE-plus-Merkle path is capped
at 1 GiB even on high-memory GPUs, so the two largest ECDSA commitments miss it
and issue 40 separate circle-LDE command buffers.

### Rejected: whole-tree heterogeneous commitment epoch

The existing heterogeneous one-submit path was experimentally extended to the
ECDSA main-tree shape (4,444 mixed-log columns and 299,448,320 base words). The
experiment required both high-memory-device arena admission and a dense
same-log evaluation layout so later proof-resident base/lookup batches retained
their consecutive-column contract. Its real-device correctness gates passed,
and the complete secure proof remained byte-identical.

Command profiling rejected the design. Although command buffers fell from 66
to 56, measured GPU time rose from 522.45 ms to 693.35 ms and host wait time
rose from 720.1 ms to 856.4 ms. The combined main epoch alone took 335.20 ms
and created 372 encoders; its sparse RFFT layers cost about 141.29 ms, sparse
IFFT layers 66.39 ms, and the leaf hash 93.22 ms. The existing per-log path's
specialized kernels and smaller working sets are materially faster than placing
the full mixed-log tree in one giant arena. The experiment was reverted in
full. Future submission reduction must preserve the efficient per-log kernels
or introduce asynchronous ownership; it must not equate fewer command buffers
with less work.

### Rejected: packed parallel selected-layout interaction generation

The authenticated lookup-V2 path was temporarily connected to the existing
packed, chunk-parallel opcode interaction executor for shards at log size 12 or
larger. A differential gate proved that singleton/pair physical batches,
claims, and committed columns remained byte-exact. The full ECDSA comparison,
however, moved only from 3.110144 to 3.089540 seconds median (0.66%), with
witness materialization changing from 423.60 to 417.04 ms. Extending the rule
to every shard measured 3.105858 versus 3.112264 seconds and slightly regressed
witness time. These effects are below a convincing end-to-end signal for the
added executor surface, so the change was reverted.

### Rejected: cached lifted-row metadata in Merkle leaves

Because commitment columns are sorted by log size, the Metal leaf kernel can
reuse one lifted row index across a same-log run. An experiment also placed the
uniform offset/log metadata in Metal's constant address space. Authenticated
AOT compilation and the complete proof succeeded, but the decisive command
profile was flat: Merkle GPU time was 188.18 ms versus the retained 189.24 ms,
while unrelated circle-LDE variability was larger than the apparent saving.
The source was restored. BLAKE2s compression itself, not the three-instruction
lifted-index calculation, remains the leaf bottleneck.

### Retained: partitioned resident Poseidon infrastructure and packed QM31 transpose

The largest remaining infrastructure fallback was the memory-commitment
Poseidon component. Its relation contains 433 direct constraints plus the
LogUp relation. Compiling all direct constraints into one Metal kernel was
rejected: the kernel increased the base batch from 18.45 ms to 50.22 ms and
the lookup batch from 74.15 ms to 85.67 ms. The oversized kernel lost enough
occupancy to consume most of the host work it removed.

The retained design partitions the same canonical constraint order into four
content-addressed direct programs and one lookup program. A general
`base_lookup_polynomial_v1` capability carries exact, non-overlapping
constraint ranges; the Metal accumulator maps each range to its original
random-coefficient slice. Admission requires complete coverage. Components
below 2^16 evaluation rows stay on the host because the five resident
dispatches do not amortize below that measured crossover. This is a domain-size
policy, not an ECDSA or program-identity special case.

In parallel, the packed QM31 batch-inversion path was optimized in the shared
field frontend. Four QM31 values are now loaded and stored with vector
transpose shuffles instead of sixteen scalar field accesses. A 131,072-element
microbenchmark measured 1,554,833 ns versus 1,294,459 ns median, a 16.7%
reduction, with an identical checksum. The production ReleaseFast field suite
passes all 17 tests, including packed QM31 inversion parity.

The split authenticated product exposes 141 exact native kernels, zero
function constants, and AOT/JIT parity. Its ECDSA profile reports 98 resident
base programs, 95 resident lookup programs, zero declines, a 29.66 ms base
batch, and a 74.87 ms lookup batch. Total Metal command time is 527.32 ms,
essentially unchanged from the prior 522.45 ms profile; the speedup comes from
removing host relation evaluation rather than adding hidden GPU work.

A live reverse-balanced B/A/A/B comparison, three retained samples per leg,
measured:

| workload | retained baseline median | candidate median | reduction |
|---|---:|---:|---:|
| ECDSA/32 | 2.956851 s | 2.300073 s | 22.2% |
| Keccak/128 | 0.616474 s | 0.591357 s | 4.1% |

ECDSA mean proving time fell from 2.129604 s to 1.475089 s. Relative to the
start-of-round 3.628815 s ECDSA baseline, the two retained tranches together
reach 2.300073 s, a 36.6% reduction. The small Poseidon2/8 guard remains flat:
0.631493 s baseline versus 0.633862 s after size-gated admission. Its mixed
component correctly stays on the host.

Every ECDSA artifact decoded to the same 3,304,541-byte proof with SHA-256
`eaa345bdb4435f12c1da4d914e700fdff6b50f0d94b4f6c02ffddf0c2633782d`.
Keccak/128 and Poseidon2/8 likewise retained exact decoded proof identities
`b060b18a76d3ec5611ec79ddf58e15a1827e30584c21aaa05fb35d46a83063a8`
and `700032ac33f87d529cf0298fc647457b2729f2c7ad3297b66b5bebcb41db258c`.
Statement and transcript identities matched in every arm, and all stdout/stderr
evidence files were empty.

Retention gates: generated polynomial source is byte-identical to the AOT
generator output; shader manifest/runtime registry 3/3; prepared hash component
gate green; ReleaseFast field suite 17/17; real secure ECDSA, Keccak, and
Poseidon proofs verified; source conformance reports no new violations; and
`git diff --check` is green.

### Rejected: comptime opcode-family dispatch

A post-retention host sample placed typed opcode lookup construction at the top
of the active CPU stacks. A narrow experiment replaced the existing reviewed
runtime family selection with an inline switch so every family constructor had
a compile-time-selected call edge. The focused lookup gate passed, but a live
reverse-balanced ECDSA comparison measured 2.313517 seconds for the retained
binary and 2.309513 seconds for the candidate, only 0.17%. Candidate proving
time was slightly worse (1.473744 versus 1.469178 seconds). The proof,
statement, and transcript remained exact and all diagnostic streams were
empty.

The dispatch itself is therefore not the bottleneck and the experiment was
reverted. Sampling instead shows the same typed relation entries being
materialized from committed opcode columns during Tree 1 and reconstructed
again for Tree 2. The next frontend experiment must remove or amortize that
duplicate row work; adding another family switch specialization is not
justified.

### Frontend follow-up: measured rejections and next architecture

A complete all-family microbenchmark compared the typed direct opcode lookup
builders with the existing hash-consed scalar lookup DAG. The DAG was slower in
15 of 17 families: representative candidate/baseline ratios were 1.157 for
base-ALU-register, 1.715 for register shifts, 1.944 for `mulh`, and 2.216 for
division. Only `jal` (0.989) and `fence` (0.835) improved. All 197 differential
checks passed, but scalar DAG replay is not a viable replacement for direct
typed construction. The large Tree-2 shards already use the packed,
chunk-parallel DAG, where hash-consing is amortized across four lanes; this
finding specifically rules out extending it to scalar Tree-1 ingestion.

The retained product was also swept at 4/8/12/16/18 host workers with one
warmup and three verified ECDSA samples. Median request times were
3.2673/2.6176/2.4254/2.3225/2.3179 seconds respectively. Eighteen workers is
therefore still the best total-latency setting on this 18-logical-core host;
reducing the default to relieve contention is not an optimization.

Two data-path experiments then targeted sampled frontend work:

- A packed dense lookup-counter merge removed scalar field additions from the
  worker reduction. The full main-trace ReleaseFast suite passed 318/318, but a
  six-sample reverse-balanced proof comparison measured 2.27469 seconds
  retained versus 2.26886 seconds candidate (-0.26%). Candidate proving was
  slightly worse (1.44554 versus 1.44301 seconds). The change was reverted.
- Pre-broadcasting all packed relation challenges once per shard passed the
  ReleaseFast interaction suite, but a six-sample reverse-balanced comparison
  measured 2.25746 seconds retained versus 2.26671 seconds candidate (+0.41%).
  Challenge broadcast and relation dispatch are below the end-to-end noise
  floor, so the change was reverted.

Finally, keeping four LogUp numerators packed through the post-inversion
fraction multiply produced a strong isolated result: 131,072 full-extension
products fell from 1,063,041 ns to 529,875 ns (2.0x), with an identical
checksum. The complete proof nevertheless measured 2.40379 seconds retained
versus 2.40777 seconds candidate (+0.17%), and proving was flat at
1.52715/1.52745 seconds. This transformation was also reverted: fraction
multiplication is too small a share of the request to justify another data
layout.

Every rejected proof arm retained decoded proof SHA-256
`eaa345bdb4435f12c1da4d914e700fdff6b50f0d94b4f6c02ffddf0c2633782d`,
statement `1449ccca36b95b3ea979c7f567b14720c229f51310836ed093deda2f5d719268`,
and transcript
`79ff8e7d790b605f392176a22fbf3d09d3d82f461b8b530f5b9bc56b59bd481f`.
All diagnostic stdout/stderr files were empty.

These experiments sharpen the next typed-AIR direction. The useful unit is not
a field operation, switch, or counter loop; it is the duplicated materialized
row. Tree 1 currently constructs typed lookup entries to register source
counters, then Tree 2 reconstructs the same semantics from committed columns.
A future retained improvement should publish a reusable, ownership-safe row or
prepared-shard authority that both consumers can read without duplicating
witness state or weakening commitment-derived verification. That requires a
cohesive frontend design and workload-spanning benchmarks, rather than another
local hot-loop substitution.

### Research DevEx observation

Each one-file frontend experiment required a monolithic ReleaseFast product
relink after the focused gate. The last two links took about 14 minutes each,
while the decisive four-leg proof A/B took under one minute. The development
gate cache correctly reuses narrow test results, but the installed product is a
single root compilation unit and source changes invalidate that unit. The next
DevEx optimization should split stable product/frontend/backend modules into
separately cacheable artifacts or provide a benchmark-only product graph that
links the same release code without rebuilding unrelated AOT/product closure.
This is now a larger iteration cost than the benchmark itself.

To shorten the next Metal loop, this round adds
`zig build metal-circle-lde-bench -Doptimize=ReleaseFast`. The small installed
tool drives the production circle-LDE runtime directly with configurable column
count, domain log size, and repetitions; it reports median/minimum GPU time and
an output checksum. Building it takes seconds rather than relinking the entire
RISC-V product. Its first controlled sweep on 64 columns at base log 18 measured
4.0705 ms at 256 threads per radix group, 5.4514 ms at 128 (+33.9%), and
4.1455 ms at 512 (+1.8%). The existing 256-thread choice is retained. This
falsified a scheduler experiment without another product build and leaves a
reusable, general circle-transform tuning harness in the repository.

The harness then tested porting the combined-commit scheduler's existing
four-/three-/two-layer radix modes into the generic circle-LDE path. At large
isolated geometries this reduced median GPU time from 4.0801 to 3.5055 ms at
base log 18 (-14.1%) and from 4.7756 to 4.1610 ms at base log 20 (-12.9%);
base log 16 required the established two-layer path. A domain-gated production
candidate was therefore built and proved. The full reverse-balanced ECDSA
result rejected it: 2.30853 seconds retained versus 2.32788 seconds candidate
(+0.84%), with proving effectively flat at 1.46783/1.46742 seconds. The decoded
proof, statement, and transcript remained exact. The scheduler changes were
reverted; the benchmark remains because it correctly distinguishes isolated
transform work from system-level value.

### Rejected: activate the planned Tree-1/Tree-2 authority in the product

The existing planned main-trace path writes commitment storage directly and
retains opcode, clock, and counter authority for Tree 2. Focused ReleaseFast
main-trace and full integration gates passed after routing the ordinary product
through that explicit execution API, so the experiment reached a real secure
Metal proof rather than stopping at a unit surrogate.

The official CSP boundary was corrected before scoring this experiment. The
upstream harness times the full `prove(prepared)` call, which maps here to
execution + witness generation + cryptographic proving; verification is a
separate metric. The retained reverse-balanced baseline is therefore
2.149402 seconds on this host, not the roughly 1.47-second cryptographic
subphase. Its six-sample complete-request guardrail is 2.308526 seconds.

A fresh reverse-balanced B/A/A/B comparison decisively rejected activating the
planned path:

| path | CSP `proof_duration` | complete request | peak memory |
|---|---:|---:|---:|
| retained legacy | 2.119948 s | 2.285485 s | 8.22 GB mean |
| planned Tree-1/Tree-2 | 2.372238 s | 2.529968 s | 8.41 GB mean |

The planned route regressed the official score by 11.9% and the complete
request by 10.7%. It reported no separate witness interval because the work is
absorbed into the planned proving path, but total proof work grew by about
252 ms rather than disappearing. Statement
`1449ccca36b95b3ea979c7f567b14720c229f51310836ed093deda2f5d719268`
and transcript
`79ff8e7d790b605f392176a22fbf3d09d3d82f461b8b530f5b9bc56b59bd481f`
remained exact. The product-routing experiment was reverted completely.

This falsifies direct activation, not reuse-aware materialization itself. A
future attempt must preserve the legacy scheduler's low overhead and transfer
only a narrowly owned prepared shard or row authority across the Tree-1/Tree-2
boundary; rebuilding the entire proof-scoped execution regime costs more than
the duplicate copy/reconstruction it removes.

Activating only the planned Tree-2 executor was also rejected. Its focused
production-shaped synthetic benchmark was healthy—N=4 was 3.98x faster than
serial and N=1 was within 4.6%—but its allocation, preparation, graph, and
publication overhead dominated inside the real proof. A second B/A/A/B run
measured 2.317521 seconds CSP duration for planned Tree 2 versus 2.121053
seconds retained (+9.3%); complete requests were 2.473382 versus 2.280381
seconds (+8.5%). Witness generation itself stayed effectively flat near
346 ms, while the proving interval grew by about 198 ms. The one-source change
was reverted. Both results show that a reusable authority must be a cheap data
handoff inside the legacy schedule, not another general task-graph epoch.

### Retained: Mersenne-field inverse addition chain

Whole-process sampling placed `M31.powPMinus2` among the hottest arithmetic
symbols across interaction generation, composition, and FRI. The original
fixed exponentiation for `p-2 = 2^31-3` used the ordinary bit schedule: 30
squarings plus 29 general field multiplies. The retained chain constructs
`2^k-1` blocks at k=2/4/8/16/24/28/29, then performs the final two squarings
and multiply. It preserves the 30 mathematically required squarings while
reducing general multiplies to eight.

A same-binary ReleaseFast microbenchmark over 262,144 independently generated
nonzero elements measured 17,570,250 ns for the old chain and 9,947,292 ns for
the new chain, a 43.4% reduction. The complete randomized field suite remained
green.

The end-to-end effect is smaller because inversion is only one CPU slice. An
initial six-sample-per-side B/A/A/B ECDSA screen measured 2.108515 seconds CSP
duration candidate versus 2.121102 seconds baseline (-0.59%), and 2.267150
versus 2.281494 seconds complete request (-0.63%). A higher-sample confirmation
under a strong monotonic thermal drift measured 2.154548 versus 2.157597
seconds (-0.14%) and 2.311612 versus 2.319881 seconds (-0.36%). Keccak/128 was
neutral within 0.1% (0.522405 versus 0.522044 seconds CSP duration), establishing
that the chain does not specialize ECDSA geometry. The ECDSA proof freshly
verified with the exact statement and transcript identities above.

### Retained: device-resident queried-value gather

The next host sample attributed 235 samples to the random queried-value reads
in lifted Merkle decommitment. The committed evaluation columns were still
resident in the Metal tree, but the generic decommitter reread every opening
from multi-gigabyte host column arenas before asking Metal only for sibling
hashes.

The retained path adds one bounded gather kernel over the immutable resident
column arena. A tree authenticates the complete caller column set against its
retained host-pointer/length/offset map, uploads only query positions and
metadata, and returns a flat column-major opening buffer. Trees without a
resident column map keep the prior host fallback; an advertised map mismatch
fails closed. Combined circle-LDE commitments now retain exact per-column map
entries rather than one coarse backing span. The proof object, query ordering,
hash-witness construction, and verifier path are unchanged.

A new `test-metal-resident-decommit` development target covers both mixed-log
ordinary commitments and the combined circle-LDE tree, including caller-order
permutations and a different-pointer/same-bytes rejection. This target reruns
in roughly 3--7 seconds from the shared gate cache; it replaced the 15-minute
79-test Metal loop during development. The authenticated AOT bundle accepts
142 exact exports, zero function constants, and AOT/JIT parity.

A three-sample reverse-balanced ECDSA screen measured 2.022812 seconds CSP
duration candidate versus 2.125852 seconds retained (-4.85%). A five-sample
confirmation measured:

| workload | retained CSP duration | resident-gather CSP duration | change |
|---|---:|---:|---:|
| ECDSA/32 | 2.153263 s | 2.060225 s | -4.32% |
| Keccak/128 | 0.532644 s | 0.532716 s | +0.01% |

The complete ECDSA request fell from 2.311489 to 2.222649 seconds (-3.84%).
The candidate command profile contains four resident gather commands totaling
0.588 ms GPU time and 3.305 ms host wait, replacing the sampled host random
reads. Total command GPU time was 493.564 ms over 70 commands, with zero
errors. Keccak's proof-duration result is neutral; its complete-request mean
was 0.43% slower, within the larger verifier/request noise that the official
CSP boundary intentionally excludes.

Every ECDSA arm decoded to the same 3,304,541-byte proof with SHA-256
`eaa345bdb4435f12c1da4d914e700fdff6b50f0d94b4f6c02ffddf0c2633782d`.
Every Keccak arm decoded to the same 827,978-byte proof with SHA-256
`b060b18a76d3ec5611ec79ddf58e15a1827e30584c21aaa05fb35d46a83063a8`.
The ECDSA candidate passed a fresh-process verifier with the unchanged
statement and transcript identities above.

### Retained: commitment-scoped circle-LDE command batching

The post-gather profile contained 40 independent generic circle-LDE command
buffers. Their kernels were already specialized per log-size group, but each
group still paid a submission and completion fence before the next independent
group could be encoded. A first experiment submitted every group separately
and delayed only the waits. Two reverse-balanced confirmations were neutral
against the retained product, so that weaker queued-command variant was not
retained.

The retained design instead gives each generic polynomial commitment one
explicit circle-LDE batch owner. Page-aligned no-copy groups keep their existing
buffer geometry and tuned kernels but encode into a single command buffer;
groups requiring host copyback retain the synchronous path. The prover closes
the batch before consuming any transformed column. An unfinished error path
releases an uncommitted command before its borrowed arenas unwind. No shader,
transform schedule, column layout, proof, transcript, or work receipt changes.

Across two complementary three-way reverse-balanced experiments, the pooled
means were:

| implementation | ECDSA CSP `proof_duration` | complete request |
|---|---:|---:|
| retained resident gather | 2.071718 s | 2.240445 s |
| queued commands / one fence | 2.060517 s | 2.207672 s |
| one command per commitment | 2.058643 s | 2.216234 s |

The single-command path improves the official ECDSA boundary by 0.63% and the
complete request by 1.08% versus the retained baseline. It is only 0.09% faster
than the queued-command experiment at the CSP boundary; the queued variant is
0.39% faster on the noisier complete-request guardrail, while the retained path
has the smaller submission surface. A Keccak/128
B/C/C/B guard measured 0.509543 s retained versus 0.502968 s candidate (-1.29%);
complete requests were 0.579876/0.569975 s (-1.71%).

The new profile has 35 command buffers instead of 70 while preserving all 366
encoder boundaries. Four commitment-scoped circle commands account for 178.39
ms GPU and 229.64 ms host wait; total command wait is 682.00 ms. This is a
submission/fence improvement, not a claim that the transform kernels are
saturated: circle LDE and Merkle now remain the two largest device phases.

A focused actual-device gate places two independent direct LDE operations in
one command and compares coefficients, extended evaluations, and execution
receipts byte-for-byte with the synchronous route. The complete ECDSA proof
freshly verifies, decodes to SHA-256
`eaa345bdb4435f12c1da4d914e700fdff6b50f0d94b4f6c02ffddf0c2633782d`,
and retains the statement/transcript identities above. All Keccak arms decode
to `b060b18a76d3ec5611ec79ddf58e15a1827e30584c21aaa05fb35d46a83063a8`.

### Rejected: implicit LDE-to-Merkle overlap through aliased host pages

An overlap prototype submitted the commitment-scoped LDE command without a
host wait, retained a type-erased completion token with the transformed column
storage, and waited only after the subsequent Merkle commitment. Both a broad
version and a conservative version restricted to page-aligned arenas of at
least 1 MiB failed the proof with `ConstraintsNotSatisfied`.

The failed trace made the ownership error concrete. The two large deferred
circle commands took 160.90 ms and 165.60 ms, versus 178.39 ms total for all
four circle commands in the retained synchronous profile, while the following
Merkle commands ran concurrently. Creating distinct no-copy `MTLBuffer`
objects over the same unified-memory pages does not give Metal a resource
dependency between those command buffers; the reader and writer raced despite
aliasing the same physical storage.

A sound future overlap must express an actual device dependency: use the same
Metal resource object, place both phases in one command buffer, or signal/wait
an explicit shared event. The generic deferred-completion prototype was
therefore reverted in full rather than retained as a fragile platform
heuristic.

### Retained: caller-owned opcode source-entry reconstruction

A whole-process sample after the resident-gather and command-batching changes
showed opcode source ingestion as the hottest active frontend stack. The
write-through generator reconstructed each row's relation entries through a
large by-value `List` return even though the opcode authority already exposes
`fromMainInto` specifically for caller-owned storage. Sampled copies appeared
as 456 `memmove` leaf samples alongside 1,003 `fromMain` samples.

Both generated-row registration and the strict scanned-source fallback now
fill a caller-owned `List`. The relation constructor, entry order, table-index
validation, counters, committed columns, and proof are unchanged; only the
redundant return-value copy is removed.

A three-sample-per-leg reverse-balanced ECDSA screen measured:

| implementation | witness | CSP `proof_duration` | complete request |
|---|---:|---:|---:|
| retained command batching | 0.379035 s | 2.039852 s | 2.192187 s |
| caller-owned source entries | 0.363105 s | 2.024116 s | 2.173981 s |

This reduces witness time by 4.20%, the official CSP boundary by 0.77%, and
the complete request by 0.83%. Two complementary Keccak/128 guards (20 samples
per implementation in total) were neutral within noise: 0.515420 versus
0.516750 seconds CSP duration and 0.584343 versus 0.586984 seconds complete
request. The ECDSA proof remained 3,304,541 bytes with SHA-256
`eaa345bdb4435f12c1da4d914e700fdff6b50f0d94b4f6c02ffddf0c2633782d`
and passed a fresh-process secure verifier with the unchanged statement and
transcript identities.
