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
