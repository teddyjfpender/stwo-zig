# Ethereum GPU readiness audit

CPU block delivery remains incomplete until the live mainnet stream produces and
freshly verifies its complete root. No GPU run was performed for this audit.
The user's current measurement scope is CPU; NVIDIA measurements remain deferred.

## Pinned peer code and applicable design

ZisK: `5c5f81c96929abed88894473ec6060b1b545b5c5`.
Proofman: `d485fac207679076958b502554fb595568c2f954`.
CuMetal checkout: `e74b377942f9d2db0f2dde14c5a1b51a9c678692`.

The inspected Proofman implementation is
[pil2-stark/src/goldilocks/src/stream_commit.cuh](https://github.com/0xPolygonHermez/pil2-proofman/blob/d485fac207679076958b502554fb595568c2f954/pil2-stark/src/goldilocks/src/stream_commit.cuh)
and its `.cu` implementation. It unpacks a column group, extends that group in
place, and absorbs it into carried BLAKE3 state. A caller-owned slot holds the
working buffers, and the dead data region is reused for tree reduction. Packed
uploads use 32 MiB blocks. The call synchronizes before returning the slot.
This version limits the streamed row width to 256 Goldilocks columns and uses a
specialized at-most-two-chunk BLAKE3 construction. These are explicit bounds,
not a general arbitrary-width STARK commitment kernel.

Our existing `src/backends/metal/runtime/blake3_streaming_leaves.zig` already
implements bounded row tiles with a 64 MiB scratch budget, two pending staging
slots, and compact column groups. `commit_backend.zig` exposes this through
`tryCommitStreamingMerkle`. Replacing that route with a second imported hash
implementation would duplicate existing machinery. The useful next comparison
is complete commitment time, peak live buffers, and transfers for identical
Stwo columns under the synchronous and overlapping schedules.

The field and commitment contracts differ: Proofman's Goldilocks NTT and LE64
row packing cannot substitute for M31 circle transforms and Stwo's lifted-column
commitment serialization. Retain native Stwo transforms, lifting order, hash
framing, and independently verified roots. Port scheduling or buffer-lifetime
ideas only after a byte-identical root comparison. No peer code was copied by
this audit.

## CuMetal evaluation

[CuMetal](https://github.com/Lulzx/cuda-metal) is a source translation route for a
tested CUDA subset. Its README explicitly excludes multi-GPU and peer access,
and lists incomplete cooperative-grid, dynamic-launch and graph support. This
makes bounded ordinary kernels candidates; it does not qualify ZisK's complete
multi-device runtime on Apple hardware.

This repository already has `scripts/cuda_cumetal_build.py` and a pinned provider
contract in `src/backends/cuda/cumetal/frontend_support.json`. That contract pins
a different CuMetal revision (`e88dd103bddaff9a134913dec4bd8439817d160c`) plus a
compatibility-patch digest. Do not silently substitute the research checkout.
Native wide-Fibonacci qualification in that file does not cover RISC-V: its
RISC-V entry explicitly has **zero AOT entries** and execution **unavailable**.
The missing work is the authenticated RISC-V AOT set, resident executor binding,
and independent proof parity. None was enabled by this audit.

## Concrete next gates

1. Finish the current canonical CPU mainnet proof and preserve its workload,
   proof and independently admitted verifier identity as the comparison anchor.
2. Wire the combined SHA profile's five typed components into the authenticated
   GPU catalog; qualify direct caller/register/memory relations and changed-claim
   rejection, not just SHA compression output.
3. Run the same leaf through CPU and Metal, independently verify both, and
   account for all preparation, transfer, commitment, proof and teardown time.
4. Qualify the same full-custody recursive parent and adjacent-segment fold on
   the GPU backend before claiming block-recursion support.
5. Measure retained buffers and allocation peaks across a growing frontier.
   CPU physical footprint is not a GPU VRAM requirement; Apple shared memory
   also requires accounting for retained host and device allocations together.
6. Only then benchmark CuMetal against the existing Metal implementation on
   applicable identical M31/BLAKE3 operations. A CUDA compile or host stub is
   insufficient evidence of device execution or performance.

The normal `stwo-ethereum-block-proof` product still exposes the earlier
materialize/replay commands. The canonical full BLAKE3 stream currently builds
through `build_stream_memory_lifetimes.py`; normal product wiring has been added for `stwo-ethereum-block-stream` and
`stwo-ethereum-block-verify`, with their first build queued behind the live run. A standalone receiver source
has now been added in `src/frontends/riscv/ethereum_block_verify.zig`; its build
and artifact qualification are queued behind the isolated CPU run. It is not yet
a qualified receiver command. This audit
must not be read as a production-release qualification.
