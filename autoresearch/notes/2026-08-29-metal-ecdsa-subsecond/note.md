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

### Retained: base-numerator interaction arithmetic

The post-source-ingest sample still spent substantial CPU time in opcode and
preprocessed-table interaction generation. Two numerator shapes were carrying
base-field values through unnecessary secure-field construction/multiply
paths:

- the MUL/MULH/DIV opcode families use physical singleton batches, so their
  post-inversion numerator is one M31 scalar rather than a general QM31;
- every preprocessed lookup-table multiplicity is an M31 scalar, while the
  denominator inverse is QM31.

The retained implementation uses `QM31.mulM31` in both cases. It does not
change batching, denominator construction, inversion order, prefix order, or
the committed interaction columns. A production-shaped lookup-table timing
improved from 11.039 ms to 7.776 ms (-29.6%). The packed singleton opcode
timing improved by 1.3--1.9%, depending on mean versus median. Focused Debug
and ReleaseFast gates cover paired, singleton, and wide opcode families plus
all six table interactions; their reusable roots avoid rebuilding the full
frontend during subsequent arithmetic experiments.

Two complementary five-sample-per-leg ECDSA B/C/C/B and C/B/B/C runs pooled
to:

| implementation | execution | witness | proving | CSP `proof_duration` | complete request |
|---|---:|---:|---:|---:|---:|
| caller-owned source entries | 0.328207 s | 0.377029 s | 1.384078 s | 2.089314 s | 2.246633 s |
| base-numerator arithmetic | 0.328874 s | 0.377201 s | 1.369599 s | 2.075674 s | 2.227825 s |

This is a 0.65% reduction at the official CSP boundary and a 0.84% complete
request reduction. Keccak/128 was neutral across two complementary 28-sample
cohorts: 0.521241 versus 0.521447 seconds (+0.04%). The retained product SHA is
`3d7c02b3a64eb03e9f9da854cee2ec0f534f616e3ccd783358ffdee5c2019763`.
Fresh-process verification passed for both workloads. All ECDSA arms decoded
to the unchanged 3,304,541-byte proof SHA
`eaa345bdb4435f12c1da4d914e700fdff6b50f0d94b4f6c02ffddf0c2633782d`;
all Keccak arms decoded to the unchanged 827,978-byte proof SHA
`b060b18a76d3ec5611ec79ddf58e15a1827e30584c21aaa05fb35d46a83063a8`.

### Rejected: broader packed and direct-event lookup rewrites

Three larger rewrites did not survive focused measurement and were reverted:

- packing four independent table terms into QM31 lanes made the production
  table loop slower;
- a four-term packed dot product in opcode denominator construction regressed
  the load/store interaction timing by about 1.4%;
- reconstructing BASE_ALU_REG table requests directly from its typed relation
  events looked attractive in the process sample, but the exact row-level
  benchmark measured 128.39 ns per row versus 87.37 ns for the retained
  committed-column authority (+47%). A whole-proof screen was correspondingly
  neutral. The direct path and its temporary timing test were removed in full.

The last result is useful architecture evidence: the committed-column builder
is already well scalarized and cache-hot. A future single-source fusion must
share the witness writer's decoded row before either product is materialized;
building a second typed event structure beside it is not reuse.

### Retained: density-aware opcode polynomial evaluation

The next process sample identified the packed opcode lookup polynomial DAG as
the largest remaining frontend stack. Its old evaluator walked every symbolic
node and tested a reachability byte on every packed row. Program density is
bimodal: most opcode families retain nearly every node, while `shifts_imm`,
`load_store`, and `div` omit 35%, 30%, and 24% respectively.

The retained plan resolves that static choice once per family. DAGs at least
7/8 dense use a branch-free sequential walk; sparser DAGs use a compact
topological index list. The symbolic program, dependency order, packed field
operations, relation construction, batch inversion, prefix order, and proof
remain unchanged. A same-binary ReleaseFast ABBA microbenchmark improved every
material family except one small noisy case: BASE_ALU_REG 20.82 ms to 18.53 ms,
LOAD_STORE 40.84 ms to 28.95 ms, and DIV 112.21 ms to 100.36 ms over 400,000
evaluations. Exact packed/scalar parity remains covered for every opcode family;
the focused final gate receipt is
`.git/typed-air-zig-gates/runs/1788051495229640000-82777.json`.

Two complementary five-sample-per-leg ECDSA cohorts measured:

| implementation | execution | witness | proving | CSP `proof_duration` | complete request |
|---|---:|---:|---:|---:|---:|
| base-numerator arithmetic | 0.326908 s | 0.377036 s | 1.372504 s | 2.076449 s | 2.227324 s |
| density-aware evaluation | 0.328827 s | 0.376752 s | 1.363559 s | 2.069138 s | 2.221093 s |

This is a 0.35% CSP reduction and a 0.65% proving reduction. The corresponding
two complementary Keccak/128 cohorts, 28 samples per implementation, were flat:
0.524230 versus 0.524444 seconds CSP duration (+0.04%). The candidate product
SHA is `e3d8b48c71e43dad4e6412cfbdfd2578ae7d330e0b30267d91c9e939ec9b7c5a`.
Fresh-process verification reproduced the unchanged ECDSA and Keccak proof,
statement, and transcript identities recorded above.

### Retained: challenge-prepared opcode relation programs

The density-aware evaluator made relation-denominator construction the next
measurable opcode-interaction cost. Each packed row was still switching on the
relation domain and splatting the same verifier challenge powers and relation
constant for every lookup. The retained implementation validates every
program/domain arity once, packs the challenges once per interaction trace,
and evaluates a compact immutable entry/power program shared by all row
workers. It preserves lookup order, numerator indices, denominator arithmetic,
batch inversion, prefix order, interaction columns, and transcript. Runtime
bounds remain fail-closed and focused allocation-failure coverage proves both
preparation allocations roll back.

A same-binary microbenchmark over 80,000 complete entry-set evaluations found
the compact representation materially cheaper than the already packed
domain-switch path: BASE_ALU_REG improved from 20.34 ms to 14.93 ms,
BASE_ALU_IMM from 19.49 ms to 12.50 ms, LOAD_STORE from 18.07 ms to 12.40 ms,
and DIV from 17.41 ms to 16.87 ms. The small FENCE family fell from 17.27 ms
to 1.92 ms because the hot loop no longer carries the full relation switch.
The research timing harness was removed before the production gate.

Two complementary five-sample-per-leg ECDSA cohorts pooled to:

| implementation | execution | witness | proving | CSP `proof_duration` | complete request |
|---|---:|---:|---:|---:|---:|
| density-aware evaluation | 0.326167 s | 0.344720 s | 1.368971 s | 2.039857 s | 2.187726 s |
| prepared relation program | 0.327144 s | 0.346607 s | 1.361839 s | 2.035590 s | 2.189903 s |

This reduces the official CSP boundary by 0.21% and proving by 0.52%; the
complete request is flat within noise (+0.10%). Two complementary
seven-sample-per-leg Keccak/128 cohorts were also positive: 0.513051 seconds
to 0.512169 seconds CSP duration (-0.17%), with complete request essentially
unchanged (0.582951/0.582911 seconds).

The focused ReleaseFast gate receipt is
`.git/typed-air-zig-gates/runs/1788053072991698000-85647.json`; the product
receipt is `.git/typed-air-zig-gates/runs/1788053165551431000-85833.json` and
the retained product SHA-256 is
`6f275ad64905eb2734a6a142e4f4c3be7240270550a2c1695ea5391e90e7c48e`.
Fresh-process verification reproduced the unchanged ECDSA proof SHA
`eaa345bdb4435f12c1da4d914e700fdff6b50f0d94b4f6c02ffddf0c2633782d`
and Keccak proof SHA
`b060b18a76d3ec5611ec79ddf58e15a1827e30584c21aaa05fb35d46a83063a8`.
The balanced evidence roots are
`/private/tmp/stwo-metal-ecdsa-subsecond-20260829/evidence/opcode-relations-{bccb,cbbc}-v1`
and their `opcode-relations-keccak-*` counterparts.

### Retained: base-field table denominator arithmetic

The six preprocessed lookup tables contain only M31 tuple values, but their
interaction generator constructed a generic secure-field `Entry` for every
row and evaluated each challenge term with a full QM31-by-QM31 multiply. The
retained generated-table path now uses each relation's typed `combineBase`
operation, so every challenge term is QM31-by-M31. The public generic `Entry`
path is deliberately unchanged and remains the independent oracle for all six
schemas; tests compare the optimized denominator to it, including boundary and
duplicate rows, and malformed arity still rejects before generation.

A temporary same-binary ReleaseFast timing over 100,000 denominators per table
measured these representative pairs before the research harness was removed:

| table | generic secure path | base-field path |
|---|---:|---:|
| bitwise | 4.434 ms | 0.439 ms |
| range-check-20 | 3.096 ms | 0.595 ms |
| range-check-8-8-4 | 3.904 ms | 0.566 ms |
| range-check-M31 | 2.889 ms | 0.425 ms |

Two complementary five-sample-per-leg ECDSA cohorts pooled to:

| implementation | execution | witness | proving | CSP `proof_duration` | complete request |
|---|---:|---:|---:|---:|---:|
| prepared opcode relations | 0.328422 s | 0.369900 s | 1.372882 s | 2.071204 s | 2.226088 s |
| base-field table denominators | 0.329403 s | 0.367199 s | 1.358220 s | 2.054823 s | 2.212794 s |

The official ECDSA boundary improves by 0.79%, proving by 1.07%, witness by
0.73%, and complete request by 0.60%. Keccak/128 also improves across two
complementary seven-sample-per-leg cohorts: 0.519795 to 0.514962 seconds CSP
duration (-0.93%) and 0.590432 to 0.584425 seconds complete request (-1.02%).

The final lookup-table gate receipt is
`.git/typed-air-zig-gates/runs/1788055516788181000-91096.json`; the product
receipt is `.git/typed-air-zig-gates/runs/1788055536594089000-91163.json` and
the retained product SHA-256 is
`866487cf4422c18dc03c31cdcfb4d968ac3d9d08ad265813a94ae8a1af37928a`.
Fresh verification reproduced the unchanged ECDSA and Keccak proof, statement,
and transcript identities. Evidence roots are
`/private/tmp/stwo-metal-ecdsa-subsecond-20260829/evidence/table-base-denominator-{bccb,cbbc}-v1`
and their `table-base-denominator-keccak-*` counterparts.

### Rejected: compact runtime-DAG replay for lookup counters

The post-table profile still showed typed lookup reconstruction beneath the
opcode-column writer. A reuse prototype evaluated the already-authenticated
lookup polynomial DAG directly over committed M31 values and registered its
table-domain roots, avoiding the second typed `List` construction. It produced
byte-identical counters and passed source-scan and main-trace parity gates, but
the exact BASE_ALU_REG registration benchmark rejected it before a product
build: 200,000 canonical typed registrations took 20.446 ms versus 22.502 ms
for runtime-DAG replay (+10.0%). Dynamic node dispatch costs more here than the
compiler-specialized typed constructor. The entire production/test prototype
and timing harness were removed; a worthwhile fusion must share the writer's
already-decoded intermediates rather than replay either representation.

### Rejected: reuse the global interaction trace as numerator scratch

Opcode interaction generation allocates a chunk-local numerator array before
batch inversion. A second reuse prototype removed that allocation and staged
the numerators directly in their eventual slots in the global interaction
trace, then overwrote each slot with the final numerator/denominator term.
Although the focused ReleaseFast gate passed, complementary whole-proof orders
rejected it: pooled ECDSA CSP rose from 2.056561 s to 2.062768 s (+0.30%),
proving rose from 1.357935 s to 1.364516 s (+0.49%), and verified-request time
rose from 2.212464 s to 2.217736 s (+0.24%). The saved allocation did not repay
the poorer locality from writing the much larger global trace during the packed
evaluation pass. The implementation was reverted; evidence is retained under
`/private/tmp/stwo-metal-ecdsa-subsecond-20260829/evidence/opcode-numerator-scratch-{bccb,cbbc}-v1`.

### Rejected: zero-copy BaseScalar tuple views

Source ingestion copied each at-most-four-limb `BaseScalar` tuple into M31
before table indexing. A layout-certified slice view removed that copy and its
focused ReleaseFast gate passed. A 4,000,000-call microbenchmark was only
slightly favorable and noisy, so the candidate was taken through complementary
whole-proof orders. Pooled ECDSA results rejected it: CSP rose from 2.059555 s
to 2.062444 s (+0.14%), proving rose from 1.363103 s to 1.363802 s (+0.05%),
and complete request rose from 2.212916 s to 2.217346 s (+0.20%). The compiler
already scalarizes this tiny copy well enough that removing it does not move the
proof. The change and its permanent test were removed. Evidence is retained at
`/private/tmp/stwo-metal-ecdsa-subsecond-20260829/evidence/base-scalar-view-{bccb,cbbc}-v1`.

### Rejected: sparse table-entry registration plans

The generated counter path scans the complete relation list even though only
the six fixed-table domains contribute. A reviewed per-family index plan was
cross-checked against all 17 shipped constructors, then used to gather only
table entries and skip inactive tuples before indexing. The exact focused gate
passed, but the paired 400,000-row registration microbenchmark rejected it
before a product build: after warmup the sequential dense loop was about
29.3 ms while indexed sparse gathers were about 31.8 ms (roughly 8–9% slower).
The original list is tiny, contiguous, and branch-predictable; indirect gathers
lose more locality than they save. The plan, benchmark authority, and tests were
removed.

### Saturation check: packed QM31 inversion width

`batchInverseQM31Packed` remained a large leaf in the post-table sample, so its
8-, 16-, and 32-element independent-chain schedules were compared directly on
32,768-element inputs in alternating orders. Results were noisy under dynamic
frequency scaling, but the median 32-wide run was about 1.20 ms versus roughly
1.40 ms for both 8 and 16 lanes. The current dispatcher already selects width
32 for these aligned interaction domains. No source change was retained; this
hotspot needs a different multiplication/inversion algorithm, not another
chain-width retune.

### Retained: base-field lookup-table composition

After the ECDSA lookup-counter path saturated, a Keccak/128 process sample made
the next general bottleneck unambiguous: lookup-table prepared-domain AIR
evaluation and its generic LogUp constraint dominated the runnable CPU leaves.
The table tuple polynomials evaluate in M31 even on the doubled composition
domain, but the prepared evaluator promoted every coordinate to QM31 before
combining it with the secure relation challenges.

The retained evaluator keeps those tuple coordinates in M31 and uses each
relation's existing `combineBase` authority. The signed multiplicity and
`is_first` values are promoted only once, while current/previous interaction
values, claim, and the exact singleton LogUp transition remain unchanged. A
six-kind differential test compares the new path to the canonical secure-field
evaluator; the product proof and fresh verifier preserve the exact decoded
proof, statement, and transcript identities.

Two complementary seven-sample-per-leg Keccak/128 cohorts pooled to:

| implementation | execution | witness | proving | CSP `proof_duration` | complete request |
|---|---:|---:|---:|---:|---:|
| base-field table denominators | 0.001991 s | 0.063886 s | 0.450227 s | 0.516104 s | 0.585038 s |
| base-field prepared evaluator | 0.001992 s | 0.064340 s | 0.366067 s | 0.432399 s | 0.501062 s |

That is -18.69% proving, -16.22% CSP duration, and -14.35% complete request.
The ECDSA guardrail also retained across complementary five-sample cohorts:

| implementation | execution | witness | proving | CSP `proof_duration` | complete request |
|---|---:|---:|---:|---:|---:|
| base-field table denominators | 0.329840 s | 0.365884 s | 1.378186 s | 2.073910 s | 2.230492 s |
| base-field prepared evaluator | 0.330583 s | 0.364341 s | 1.317397 s | 2.012321 s | 2.168232 s |

ECDSA improves by 4.41% proving, 2.97% CSP duration, and 2.79% complete
request. The focused gate receipt is
`.git/typed-air-zig-gates/runs/1788059720969564000-98249.json`; the product
receipt is `.git/typed-air-zig-gates/runs/1788059741917006000-98304.json`, and
the product SHA-256 is
`d96b45cedf4d77747f224b659c198c49b0eaf333698164405b91d536eb302609`.
Evidence roots are
`/private/tmp/stwo-metal-ecdsa-subsecond-20260829/evidence/table-base-prepared-{keccak,ecdsa}-{bccb,cbbc}-v1`.
The fresh receipts bind decoded proof SHA-256 `b060b18a...063a8` for Keccak
and `eaa345bd...3782d` for ECDSA, with empty verifier stderr.

### Rejected: algebraically reduced singleton LogUp rows

The post-composition profile still showed the generic two-fraction LogUp
constraint as a large leaf even though lookup tables always use
`RowPair.single` (`n2 = 0`, `d2 = 1`). A candidate reduced the prepared-domain
identity directly to `delta * denominator + signed_multiplicity` and retained
base operands for the boundary selector. The all-six-table differential gate
passed, but whole-proof code generation regressed. The first complementary
seven-sample-per-leg Keccak/128 run measured +1.25% CSP and +1.20% complete
request. A second independent complementary run with ten samples per leg
confirmed +0.91% proving, +0.43% CSP, and +0.22% complete request. The source
change was reverted. Rejected evidence is retained under
`/private/tmp/stwo-metal-ecdsa-subsecond-20260829/evidence/table-singleton-reduced-keccak-{bccb,cbbc}-{v1,v2}`;
the rejected product is retained only for diagnosis at
`/private/tmp/stwo-metal-ecdsa-subsecond-20260829/builds/table-singleton-reduced-v1`.

### Retained: topology-balanced lookup-table chunks

After base-field composition, `TableChunk.generate` became the largest
interaction-generation leaf. Fixed 4096-row chunks created 256 tasks and 256
serial field inversions for a 2^20 table even though the bounded pool has only
18 workers. A temporary real-generator microprobe swept fixed 8192/16384-row
chunks and topology-derived one/two/three/four-wave schedules. The warmed
2^20-table medians were approximately 10.07 ms for the original geometry,
9.28 ms for fixed 8192, 8.96 ms for fixed 16384, 8.3 ms for one wave, 6.3 ms
for two waves, 8.3 ms for three waves, and 7.0 ms for four waves.

The retained policy derives two balanced chunks per available worker with the
original 4096-row cache floor. It therefore scales with pool topology and table
size rather than recognizing a benchmark: on 18 workers the six fixed tables
use 36 tasks for logs 18--20, 16 tasks for log 16, and 8 tasks for log 15.
Sequential and receipt-bearing exact-work generation retain their original
4096-row authority. The permanent geometry test pins the cache floor, large
table division, and one-worker behavior. The post-change Keccak sample reduced
`TableChunk.generate` from 2360 to 1222 sampled stacks.

Two complementary seven-sample-per-leg Keccak/128 cohorts pooled to:

| implementation | execution | witness | proving | CSP `proof_duration` | complete request |
|---|---:|---:|---:|---:|---:|
| fixed 4096-row chunks | 0.001986 s | 0.065048 s | 0.363704 s | 0.430738 s | 0.499189 s |
| topology-balanced chunks | 0.001985 s | 0.062792 s | 0.355889 s | 0.420666 s | 0.488336 s |

That is -3.47% witness, -2.15% proving, -2.34% CSP duration, and -2.17%
complete request. Complementary five-sample-per-leg ECDSA cohorts retained the
guardrail:

| implementation | execution | witness | proving | CSP `proof_duration` | complete request |
|---|---:|---:|---:|---:|---:|
| fixed 4096-row chunks | 0.335058 s | 0.365448 s | 1.330081 s | 2.030587 s | 2.190792 s |
| topology-balanced chunks | 0.334286 s | 0.367086 s | 1.316278 s | 2.017649 s | 2.180200 s |

ECDSA improves by 1.04% proving, 0.64% CSP duration, and 0.48% complete
request. Peak footprint was flat to slightly lower (-0.12% Keccak, -0.04%
ECDSA); process cycles fell 10.19% and 1.44% respectively, while observational
energy was -0.40% and +1.26%. The focused gate receipt is
`.git/typed-air-zig-gates/runs/1788061779276105000-2634.json`; the product
receipt is `.git/typed-air-zig-gates/runs/1788061805061073000-2700.json`, and
the product SHA-256 is
`db2265abc5d79c4cb848872388b029f92c0f754183491e66dca73697d5af073d`.
Evidence roots are
`/private/tmp/stwo-metal-ecdsa-subsecond-20260829/evidence/table-adaptive-chunks-{keccak,ecdsa}-{bccb,cbbc}-v1`.
Fresh verification preserves decoded proof SHA-256 `b060b18a...063a8` for
Keccak and `eaa345bd...3782d` for ECDSA, exact statement/transcript identities,
one canonical receipt line, and empty verifier stderr.

### Rejected: topology-balanced opcode-interaction chunks

The post-table ECDSA sample moved the dominant runnable leaf to
`OpcodeChunk.generate` (4032 sampled stacks), followed by its packed batch
inverse (1574). The opcode generator also used fixed 4096-row chunks, so a
candidate applied the same topology-derived two-wave policy while aligning
every boundary to the four-row packed width and carrying the exact dynamic
chunk size through prefix-offset placement. Packed/scalar parity, boundary,
and rollback tests passed in ReleaseFast.

Unlike fixed tables, opcode chunks perform substantial per-row typed-program
evaluation and have multiple batch planes, so reducing task count did not repay
the loss of fine-grained balance. The first complementary five-sample-per-leg
ECDSA run was mixed (-0.20% CSP, +0.20% complete request). A second independent
ten-sample-per-leg run rejected it: proving +0.79%, CSP +0.56%, and complete
request +1.02%. The implementation and permanent test were reverted. Evidence
is retained under
`/private/tmp/stwo-metal-ecdsa-subsecond-20260829/evidence/opcode-adaptive-chunks-ecdsa-{bccb,cbbc}-{v1,v2}`.
The rejected product gate receipt is
`.git/typed-air-zig-gates/runs/1788062906242110000-4596.json`, with diagnostic
product SHA-256
`01f6846b7e66ba01e9b4f16fc2b3d7f8fc35a0f8bc31517f2b916a7f42e924a1`.

The retained table-scheduler product's unsampled 11-request post-change ECDSA
diagnostic reached 0.324346 s execution, 0.368565 s witness, 1.279401 s proving,
and 1.972313 s CSP `proof_duration` (2.120920 s complete request). This is the
first local mean CSP observation below two seconds in this campaign, but it is
a diagnostic, not a claim of the still-unmet one-second target. The opcode
profile shows the next campaign must reduce packed row evaluation or its batch
inverse algorithm; chunk-count retuning is saturated on this host.

### Rejected: packed opcode-interaction finalization

The next candidate kept the existing opcode task topology and replaced the
scalar post-inversion QM31 multiply/store loop with four-lane `PackedQM31`
operations. ReleaseFast packed/scalar parity passed, and complementary ECDSA
orders both improved. Across twenty samples per arm, proving moved from
1.330456 s to 1.323677 s (-0.51%), CSP `proof_duration` from 2.041793 s to
2.033042 s (-0.43%), and complete request from 2.202524 s to 2.193795 s
(-0.40%).

The independent Keccak/128 guardrail rejected the change. Across twenty-eight
samples per arm, proving regressed from 0.370269 s to 0.372440 s (+0.59%), CSP
duration from 0.436088 s to 0.439300 s (+0.74%), and complete request from
0.505761 s to 0.508667 s (+0.57%); both complementary orderings pointed in the
same direction. The implementation was reverted rather than retaining a broad
regression for the narrow ECDSA gain. Evidence is retained under
`/private/tmp/stwo-metal-ecdsa-subsecond-20260829/evidence/opcode-packed-finalize-{ecdsa-v1,keccak-v2}`.
The diagnostic product SHA-256 is
`edeea657d5ef2528d74e7bafd3b4aa849d14dc49fbf47465a7b4510b7178b4cd`;
its product gate receipt is
`.git/typed-air-zig-gates/runs/1788063982239251000-6429.json`, and the focused
parity receipt is
`.git/typed-air-zig-gates/runs/1788063936550685000-6326.json`.

### Retained: zero-copy Keccak caller linkage

The compact Keccak-f AIR initially proved only the permutation and its public
packed input/output.  The production execution profile additionally requires
the CUSTOM-0 program row, register-state transition, pointer read, fifty
in-place memory transitions, access-clock gaps, and address-span checks to
cancel against the ordinary RISC-V proof.

The retained caller authority is embedded in the same 29-row paired Keccak
component rather than introducing another commitment domain.  One 64-column
metadata block is reused on row group zero for the first call and row group
one for the optional second call.  Most importantly, memory tuples are built
directly from the permutation trace's existing 1,600 boolean state cells at
the input row and offset +27 output row.  A rejected intermediate shape stored
400 duplicate input/output byte columns; the zero-copy shape removes those
columns and their 400 binding constraints entirely.

| ReleaseFast one-call isolated proof | permutation-only | linked zero-copy caller |
|---|---:|---:|
| main columns | 2,140 | 2,204 |
| interaction columns | 3,844 | 4,164 |
| witness | 10.458 ms | 9.094 ms |
| preprocessed commitment | 78.659 ms | 79.921 ms |
| main commitment | 31.565 ms | 32.879 ms |
| interaction generation | 8.406 ms | 9.391 ms |
| interaction commitment | 52.651 ms | 59.125 ms |
| prove | 206.215 ms | 222.937 ms |
| fresh verify | 161.244 ms | 172.603 ms |
| prove path total | 387.954 ms | 413.347 ms |
| prove plus fresh verify | 549.198 ms | 585.950 ms |

The 6.7% complete-proof overhead closes the caller constraint surface while
remaining comfortably subsecond.  Direct mutation tests cover state bytes and
pointer alignment; interaction mutations cover clock authority; the complete
2,082-event multiset closes with chi/xor tables and a record-derived public
core boundary.  The ReleaseFast proof and fresh verifier gate is
`.git/typed-air-zig-gates/runs/1788096195395319000-78371.json`.

This isolated gate deliberately supplies the base-relation counterpart as
public data.  Product integration must replace that boundary with cancellation
against the committed program/register/memory/range components before the
Keccak profile is exposed by the ordinary proof artifact route.

### Problem match: proof-oriented secp256k1 arithmetic

Task and required semantics: prove Ethereum-compatible secp256k1 signature
verification and public-key recovery, including canonical 256-bit inputs,
curve membership, the scalar relation, caller memory/state transitions, and
the Keccak address projection.  Invalid inputs must fail closed; host hints are
witnesses, never authorities.

Inputs, measured scale/provenance, encoding, and computational model: the
current CSP guest verifies one 32-byte digest, one 65-byte uncompressed key,
and one 64-byte `(r,s)` signature by executing about 5.4 million RV32 rows.
Ethereum `ECRECOVER` consumes four 32-byte words `(digest,v,r,s)`.  The proof
field has characteristic `2^31-1`; proof cost is dominated by committed cells,
lookup events, constraint evaluation, and commitment domains rather than the
host's native secp instruction count.

Constraints, promises, invariants, and exploitable structure: secp256k1 uses
the 256-bit prime `2^256-2^32-977`, has cofactor one, and admits the efficient
endomorphism used by libsecp256k1.  Every public field/scalar value is
canonical.  Main-trace values are committed before randomized non-native
identities are challenged.  CPU and Metal must share the identical trace and
transcript; no relaxed arithmetic or benchmark-specific constants are allowed.

Candidate matches:

| candidate | relationship | proof cost/fit | evidence | decision |
|---|---|---|---|---|
| 32 byte limbs + coefficient carries | exact radix-256 integer identity | zero-copy ABI, all coefficient bounds stay below M31 | derived | selected |
| 16-bit limbs | exact only with extra anti-wrap machinery | fewer limbs, but convolution coefficients exceed M31 | derived | rejected |
| affine slope trace | exact short-Weierstrass group law | 4--5 modular products per step; inverse is one witnessed product | EFD formulas, derived | selected baseline |
| Jacobian/projective trace | exact group law | avoids host inversions but costs roughly 8--12 products per step | EFD formulas | fallback |
| independent scalar multiplications | exact | duplicates doublings and additions | standard baseline | rejected |
| Straus/Shamir joint multiplication with wNAF | exact | one doubling chain and sparse additions | libsecp256k1 | selected |
| Pippenger | exact | optimized for many points; libsecp256k1 crosses over near 88 points | libsecp256k1 | rejected for two-point ECDSA |

Chosen canonical problem and exact variant: non-native modular multiplication
over radix-256 integers plus a two-point simultaneous scalar multiplication on
the secp256k1 short-Weierstrass group.  The first transfer is the reusable
modular-product authority.  For committed digit polynomials `A,B,Q,R,C`, it
checks

`A(x)B(x) - R(x) - Q(x)P(x) - (x-256)C(x) = 0`

at a transcript challenge in QM31.  Carry limbs and all byte limbs are tightly
range checked; therefore the coefficient identity cannot hide an M31 wrap.
The degree is at most 62, giving a Schwartz--Zippel error below roughly
`62/(2^31-1)^4` in addition to the surrounding proof soundness.

Project -> canonical mapping and solution recovery: input/output memory bytes
map directly to radix-256 limbs.  The witness supplies quotient, signed carry,
and canonical-result addition witnesses.  Point operations consume these
modular-product rows through relations.  The eventual ECDSA verifier proves
the simultaneous multiplication relation; `ECRECOVER` proves the equivalent
recovery relation and hashes the authenticated recovered key through the
existing Keccak authority.

Complexity/limits and prior implementations: one modular multiplication uses
32-byte operands/result/quotient, 62 signed carries, one degree-62 randomized
identity, and byte/boolean range checks.  The Explicit-Formulas Database
publishes and symbolically checks Jacobian, mixed, affine, and doubling
formulas (`https://hyperelliptic.org/EFD/oldefd/jacobian.html`).  Bitcoin
Core's MIT-licensed libsecp256k1 uses Strauss wNAF for small MSMs, scalar
endomorphism splitting, and switches to Pippenger only at much larger point
counts (`https://github.com/bitcoin-core/secp256k1/blob/master/src/ecmult_impl.h`).
Consensys gnark's ECRECOVER circuit independently demonstrates the
hint-then-constrain structure and the required range/failure checks
(`https://github.com/Consensys/gnark/blob/master/std/evmprecompiles/01-ecrecover.go`).

Selected transfer, integration boundary, and rejected alternatives: transfer
the byte-limb non-native identity first, then an affine joint-wNAF trace, and
only then the caller/profile boundary.  Keep witness generation backend
neutral; Metal acceleration starts at bulk column filling, interaction
generation, and commitments using existing resident/AOT infrastructure.
Projective formulas remain a measured fallback if sequential host inversions
dominate.  A secp-only execution profile is rejected because Ethereum proofs
must compose secp and Keccak in one admitted profile.

End-to-end prediction, crossover, and falsifier: replacing 5.4 million RV32
rows with roughly 2,000--4,000 modular-product rows should remove orders of
magnitude of execution/witness work and target a subsecond complete proof.
The design is falsified if the first complete component exceeds the software
guest's committed-cell count or if range/interaction commitments dominate
enough that a 16-bit or projective alternative wins in paired measurement.

Correctness and benchmark plan: differential-test every modular product
against `u512` arithmetic over boundary and randomized inputs; mutate every
witness family; independently verify the polynomial identity at multiple
challenges; compare point/scalar outputs with Zig's `std.crypto.ecc.Secp256k1`
and the existing k256 guest corpus; run isolated ReleaseFast proof/fresh-verify
before product integration; then measure CPU and Metal end-to-end with exact
proof/statement/transcript parity.

Open uncertainty: the optimal affine window and whether GLV pays for its
additional scalar constraints remain measurement questions.  The first field
authority deliberately does not commit either choice.

### Retained: byte-limb field AIR and GLV joint multiplication

The first implementation checkpoint keeps the radix-256 representation all
the way from guest memory into the proof.  A modular-product row has 318 main
columns, 69 degree-at-most-three constraints, and 142 shared
`range_check_8_8` requests.  Its only secure constraint is the challenged
degree-62 carry-polynomial identity; exact integer and randomized oracles cover
both the base-field prime and scalar order.  The linear-operation row is
smaller: 199 columns, 172 constraints, and 64 byte-pair range requests for
modular add, subtract, and one-step reduction.  Both layouts reject mutations
to every witness family and have M31/QM31 point-evaluation parity.

Host generation is not the bottleneck.  A live-source `stwo-prof` isolate
measured complete quotient/carry/canonical modular-product witness generation
at 1.711 microseconds per row (42,470 instructions, 7,799 cycles, IPC 5.446).
At the pinned CSP signature's final 1,039 product rows, generic `u512`
division contributes only about 1.8 milliseconds to witness construction, so
a specialized secp reduction kernel is deliberately deferred.

The affine verifier initially used width-five joint wNAF and recorded 1,636
products, 2,351 linear operations, and 347 point transitions.  Retaining both
scalar-split equations and the variable-point endomorphism in the tape reduced
that exact signature to 1,039 products, 1,516 linear operations, and 228 point
transitions: 36.5%, 35.5%, and 34.3% fewer proof rows respectively.  Twelve
deterministic randomized cases match Zig's independent secp256k1 group oracle.

An ABBA live-source counter comparison measured the complete joint
multiplication/tape builder as follows:

| implementation | ns/op | instructions/op | cycles/op |
|---|---:|---:|---:|
| joint width-5 wNAF | 5,700,406 | baseline | baseline |
| GLV + joint width-5 wNAF | 4,671,771 | 0.8294x | 0.8199x |

The wall-time ratio is 0.8181 with 95% CI `[0.794593, 0.820251]`.  This is a
general two-point secp256k1 optimization, not a CSP fixture specialization.
The next proof checkpoint must bind the point/scalar program and its primitive
row multiset before any end-to-end speed claim is made.

### Retained: complete typed ECDSA proof below one second

The second checkpoint closes the complete GLV tape in one STARK.  Ten typed
components prove base- and scalar-field products and linear operations, affine
point transitions, both GLV splits, the 128-row joint scalar program, signed
tables, the ECDSA transaction, and the shared byte table.  Every primitive
product, linear, point, split, and scalar-program tape record is consumed
exactly once.  The verifier reconstructs only the public ECDSA counterpart and
replays the transcript in a fresh verifier scheme.

The first closed proof used 6,464 interaction columns.  Inspection showed that
the high-level point, split, table, scalar, and ECDSA rows were range-checking
bytes already authenticated by their primitive product/linear relations.  The
retained custody model leaves all primitive byte checks intact, retains checks
for the scalar program's 64 bytes of private recurrence state, and directly
checks the 160 public ECDSA bytes.  All other copied values are authenticated
through exact relation custody.  This removes 1,056 duplicate range batches
and reduces the interaction tree to 2,240 columns, a 65.3% reduction, without
changing the arithmetic program or public statement.

| ReleaseFast complete typed ECDSA proof | initial closed proof | delegated range custody |
|---|---:|---:|
| witness and bundle materialization | 25.188 ms | 23.304 ms |
| preprocessed commitment | 15.480 ms | 16.866 ms |
| main commitment | 246.242 ms | 245.359 ms |
| interaction generation | 30.812 ms | 19.625 ms |
| interaction commitment | 408.123 ms | 292.971 ms |
| quotient/FRI proof after commitments | 449.894 ms | 330.561 ms |
| **proof production total** | **1,175.739 ms** | **928.686 ms** |
| fresh verification | 262.811 ms | 155.715 ms |
| prove plus fresh verify | 1,438.550 ms | 1,084.401 ms |

The retained proof-production improvement is 21.0%, and the complete typed
proof now crosses the subsecond target without benchmark-specific constants.
The focused Debug closure receipt is
`.git/typed-air-zig-gates/runs/1788104767279320000-94212.json`; the retained
ReleaseFast proof/fresh-verifier receipt is
`.git/typed-air-zig-gates/runs/1788104781874948000-94257.json`.

### Retained: production commitment suite and Metal parity

The first closed proof deliberately used the recursion Poseidon commitment
suite because it was the shortest route to a fresh-verifier soundness gate.
That is not the production RISC-V commitment protocol.  The proof harness is
now backend-generic and instantiates the ordinary Blake-based RISC-V prover
engine unchanged on CPU and Metal.  Both backends prove the same ten-component
trace, public ECDSA counterpart, interaction closure, transcript, and fresh
verifier statement.

| ReleaseFast production-suite phase | CPU | Metal |
|---|---:|---:|
| witness and bundle materialization | 23.028 ms | 14.687 ms |
| preprocessed commitment | 1.928 ms | 8.866 ms |
| main commitment | 49.360 ms | 9.497 ms |
| interaction generation | 21.171 ms | 22.238 ms |
| interaction commitment | 32.493 ms | 8.120 ms |
| quotient/FRI proof after commitments | 323.617 ms | 303.442 ms |
| **proof production total** | **451.597 ms** | **366.850 ms** |
| fresh verification | 151.885 ms | 168.351 ms |
| prove plus fresh verify | 603.482 ms | 535.201 ms |

The production-suite result is 77.1% below the retained 1.972313-second
software CSP proof duration on CPU and 81.4% below it on Metal.  Metal records
32 authenticated device dispatches and three CPU fallbacks.  The retained CPU
receipt is `.git/typed-air-zig-gates/runs/1788106051566937000-96379.json`; the
real-device Metal AOT receipt is
`.git/typed-air-zig-gates/runs/1788106085386971000-96448.json`.

These timings are intentionally scoped to the typed ECDSA provider proof with
the public relation counterpart supplied directly.  They are not yet the
end-to-end CSP guest/caller benchmark: caller instruction retirement, memory
custody, failure semantics, and the final product route still have to be
composed before replacing the retained CSP row.  The sub-500-millisecond proof
target is therefore a demonstrated provider floor, not an end-to-end claim.
