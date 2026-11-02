# Shared sumcheck tails and immutable Blake2s schedule

Continuation of PR311 at771334a9, stacked on PR310. The resident numerical
capability now supports bounded shared-memory tails and packets of up to eight
independent ready jobs. It remains a single-oracle numerical capability, not a
complete Ethereum GPU prover or a production/security promotion.

## Implemented and compiled

A 64-thread block owns up to 256 fractions in shared memory, plus its state,
current record and deterministic reduction scratch (16,848 shared bytes).
Every remaining sum/round/fold stays inside the block. Only compact records,
final state and the final two fractions/mask leave it. From 256 rows, baseline
sum/round/fold/gather dispatches fall from 22 to 1 (16 to 1 versus fold/sum fusion),
excluding preceding init/Eq work. This is a dispatch count, not a speedup.
An XOR row swizzle is bijective, preserves power-of-two prefixes and has
conflict-free adjacent-pair accesses in the32-bank/u32 model; exhaustive tests
cover all supported indices. Real bank-conflict behavior still needs profiling.

One packet maps one independent transcript to each block, allowing1..8 jobs
with heterogeneous dimensions/cursors on one context/lane. Native preflight
checks all 80 possible ranges before dispatch, including cross-job aliases.
Source/terminal ranges stay disjoint; device credits remain borrowed until
joined success/abort. No global grid barrier, hot allocation/transfer/sync,
mutable metadata cache or graph capture is introduced. Tail policy defaults
zero/off pending real-device crossover measurements.

The shared Blake2s permutation schedule becomes constexpr in native CUDA.
Its CuMetal declaration, IV storage, compression and protocol framing remain
unchanged. The exact same isolated hash probe compiles from 168 to 48 registers
and 64 to 0 stack bytes on sm120. Actual round kernels improve from 233 to 192
registers on sm89 and 255 to 168 on sm120; the sm120 stack goes64 to 0 bytes.
Ada retains192 stack bytes. The tail uses 168 registers on each architecture,
with 192 stack bytes on sm89 and zero on sm120. No reported spills. These are
compiler results, not hardware throughput or occupancy measurements.

## Evidence

- 29 integration tests and 168 CUDA-backend host tests pass in each of
 ReleaseSafe/ReleaseFast, including the actual native-context C-ABI seam.
- Complete proof/transcript/state/terminal arithmetic agrees with the native
 prover for 14 cases/62 rounds per route: baseline, fold/sum fusion and five
 tail thresholds. Host replay does not emulate CUDA barriers or reductions.
- 129 standard Blake2s suffix lengths cover empty and block-boundary framing;
 the independent Python field oracle passes 4196 cases.
- ASan/UBSan host replay covers 22 size/base cases through 4096 rows and five
 tail cutoffs; a separate deferred-read owner test covers temporary uploads
 and exception teardown. Leak scanning alone is unavailable in this runner.
- Actual native tail packet preflight runs without a device, using a fake
 registry: it rejects late aliases/short ranges/cursor errors before any
 mutation, while permitting shared read-only ranges.
- 16 CUDA source/architecture compile units pass across sm89/sm120, including
 commitment, transcript, PoW and decommit consumers of the changed header.
 Both fat-binary drivers compile/link with format warnings treated as errors.
- The existing statement AOT source body/symbol is unchanged, but its header-
 bound identity/cache filename is regenerated. The official build plan passes
 with canonical generated witness sources and six AOT identity tests pass.
 A complete native archive is not claimed built.

The full-round driver compares eight strategies and interior handoffs. The
batch driver sweeps 1/2/4/8 jobs and checks padded outputs, source immutability,
canaries, failure isolation and sequential/batched timings. A failed standalone
round clears records before reading scratch; its initcheck case deliberately
uses uninitialized unused scratch. These device checks are compiled, not run:
both drivers return77 because no NVIDIA device/driver is attached.

Source hashes, test/compiler logs, driver exits, package findings and compiler
version bind this snapshot. Earlier report directories remain historical.
The integration package checks pass. The CUDA backend package audit retains
five inherited API-ledger/import findings in untouched files; whole-source
checks retain inherited findings outside touched files. Broad repository CI
is not claimed green. Local hook feedback is bypassed for those pre-existing
failures; no hosted gate or identity verifier is bypassed.

Before promotion require actual2/4x4090/5090 runs, memcheck/racecheck/synccheck/
initcheck, Nsight shape sweeps, pinned Rust oracle, authenticated witness/PCS
binding, mixed-instance GKR and complete-block receiver acceptance. No GPU
speedup, utilization, TPS or competitive lead is claimed.

See the design and revision-pinned ZisK review under
`design/riscv-proving-stack/rv64-cuda-{tail,zisk-review}.md` and reproducible
hardware commands in `tests/cuda/rv64/README.md`.
