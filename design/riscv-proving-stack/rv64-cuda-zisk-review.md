# CUDA source review and resulting RV64 changes

Reviewed 2026-11-02. Sources are revision-pinned below. These are engineering
observations from public source, not reproduced throughput numbers or a
same-security comparison with ZisK. No external implementation was copied.

## Source map

ProofMan commit `27b2fc20d52d8b8899291505c27e156c7cd8ef9c` contains the current
CUDA prover code under `pil2-stark/`. The separate `pil2-stark` repository at
`a 5a26e6b815821ef76aba8585e7e8fb9049e6d35` has no `.cu`/`.cuh` files in the
inspected recursive tree; studying it alone would miss the active GPU work.
ProofMan pins its SPPARK submodule to `a 0c37757c9320823a0cba5922a7f5401599062e8`.
The organization's SPPARK default head was also inspected at
`17278d74295392f9813f009300b257a688422b7a`; its polynomial evaluation file has
the same blob as the pinned submodule revision. SPPARK is Supranational code
maintained in a ZisK organization fork, not wholly original ZisK work.

| Pinned source | Observation | Application here |
|---|---|---|
| [Blake2b benchmark device header](https://github.com/0xPolygonHermez/pil2-proofman/blob/27b2fc20d52d8b8899291505c27e156c7cd8ef9c/pil2-stark/src/goldilocks/benchs/blake2b_device.cuh) | IV and permutation schedule are device `constexpr`; constant indices keep messages in registers | Make our existing Blake2s schedule immutable under native CUDA; keep CuMetal's existing storage path |
| [Blake3 benchmark device header](https://github.com/0xPolygonHermez/pil2-proofman/blob/27b2fc20d52d8b8899291505c27e156c7cd8ef9c/pil2-stark/src/goldilocks/benchs/blake3_device.cuh) | Compile-time schedule and unrolling remove runtime message indexing | Confirm compiler storage rather than add a new hash/framing implementation |
| [NTT implementation](https://github.com/0xPolygonHermez/pil2-proofman/blob/27b2fc20d52d8b8899291505c27e156c7cd8ef9c/pil2-stark/src/goldilocks/src/ntt_goldilocks.cu) | Register-resident mixed-radix work uses shuffles, shared exchange for wider stages and padded exchange strides to address bank conflicts | Keep bounded sumcheck tails in shared memory; use a bijective row XOR swizzle for adjacent-pair access |
| [Trace layout](https://github.com/0xPolygonHermez/pil2-proofman/blob/27b2fc20d52d8b8899291505c27e156c7cd8ef9c/pil2-stark/src/goldilocks/src/goldilocks_trace_layout.cuh) | Flat column-major layout is carried through producers, NTT and consumers | Preserve existing coordinate-major device planes; swizzle only block-private shared rows |
| [Stream commit](https://github.com/0xPolygonHermez/pil2-proofman/blob/27b2fc20d52d8b8899291505c27e156c7cd8ef9c/pil2-stark/src/goldilocks/src/stream_commit.cu) | Tiled transpose coalesces ingress; descriptor/state lifetime belongs to each slot, avoiding shared mutable constant metadata | Copy bounded tail descriptors into launch arguments; validate all jobs before launch, without global metadata/cache state |
| [SPPARK polynomial evaluation](https://github.com/0xPolygonHermez/sppark/blob/a 0c37757c9320823a0cba5922a7f5401599062e8/polynomial/evaluate.cuh) | Evaluation batching, field-size-specific block sizes and small-grid specialization balance resources | Separate large multi-block reductions from bounded tail kernels; batch independent tails into one block per job |

`proofman_sumcheck.cu` was inspected too: despite the filename, it is an
optional diagnostic checksum probe with allocation/readback/synchronization,
not the cryptographic LogUp sumcheck algorithm. It is not a model for our
resident numerical hot path.

## Implemented mechanisms and limits

The tail holds up to 256 fractions, one round state and one record in 16,848
shared bytes. One to eight independent jobs map to distinct blocks. The
ordinary initial sum and large multi-block path remain available. All ten
ranges per job are checked against every prior range in the packet, up to 80;
read-only sharing is legal and any mutable overlap rejects the entire packet.
One job's sticky failure cannot stop another block or leave stale challenges.

A block-private row permutation `row ^ (row >> 5)` preserves every power-of-two
prefix and is bijective. For the four adjacent-pair load patterns, active lanes
within a warp address distinct banks in the32-bank/u32 model; a linear table
has two-way conflicts for full warps of those accesses. Coalesced global ingress
and public plane layout are unchanged. Exhaustive prefix/bank tests cover the
entire supported256-row domain. Added integer indexing work still needs actual
profiling; no measured bank-conflict or latency reduction is asserted.

The immutable schedule fixes an observed compiler problem in the shared
Blake2s implementation, without changing compression, framing or protocol:
an isolated sm120 word-hash kernel goes from 168 registers/64 stack bytes to 48
registers/zero stack bytes. Complete RV64 round/tail resource results are
recorded in the qualification report; they must not be confused with the
isolated hash's48-register result. GPU speedup remains unmeasured.

Making the IV immutable as well increased Ada tail register use from 168 to 252, so that change was reverted. The schedule-only change remains.

A separate fixed-framing hash experiment produced the same resource use as
the generic implementation, and forcing out-of-line round control introduced
spills without reducing its register maximum. Neither experiment was retained.
Changing proof fields, importing ZisK's Goldilocks protocol, assuming peer
VRAM or enabling graph capture without lifetime custody was also outside this
change. Production and same-security complete-block qualification stay closed.


The changed shared header also changes the authenticated source closure of the
existing `state_machine_statement` AOT entry. Its source body and kernel symbol
are unchanged; the manifest identity/cache key and filename are regenerated.
The prior identity matches the unchanged parent header, and the new identity
passes the existing closure verifier. Canonical witness generation is still
required before building the full native AOT catalog; the official build plan
and six AOT identity tests pass with that generated fixture. This does not
claim a complete native archive or hardware proof was built.
