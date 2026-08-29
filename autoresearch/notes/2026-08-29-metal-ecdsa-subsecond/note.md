# Metal ECDSA sub-second autoresearch campaign

- Date: 2026-08-29
- Starting commit: `d3e88a653d03fc7e708cf345a33481d26b8410c6`
- Host: Apple M5 Max, arm64 macOS, Zig 0.15.2
- Primary boundary: complete secure ECDSA/32 CSP request, including execution,
  witness generation, proving, and in-process verification
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
