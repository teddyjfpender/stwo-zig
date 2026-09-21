# RV32 Ethereum execution and minimal-trace campaign

- Date: 2026-08-30
- Starting commit: `434cce33`
- Host: Apple M5 Max, arm64 macOS, Zig 0.15.2
- Workload: projected Ethereum mainnet block 24,628,607
- Boundary: exact resumable execution first; joined proof remains a separate gate

## Problem

The first complete Keccak-native Stwo run retired 1,630,632,307 cycles in 389
leaf-local segments and took 251.39 seconds. It produced the correct 43-byte
output and exact segment continuity, but only 6.49 million guest cycles/second.
Sampling showed that execution semantics were not the dominant cost: the
runner rebuilt and sorted a million-word initialized-memory union at every
segment entry and exit, then serially retained the full typed witness.

This workload still used software transaction signer recovery. Its cycle count
is therefore not implementation-normalized with ZisK and must not be used as a
proof-throughput comparison.

## Accepted boundary optimizations

| experiment | wall time | speedup | exactness |
| --- | ---: | ---: | --- |
| complete run after compact union | 251.39 s | baseline | valid V3 receipt |
| canonical inventory + leaf-local first-access baseline | 133.08 s | 1.889x | byte-identical journal |
| combined Keccak + signer recovery, same boundary path | 70.49 s | 3.566x | valid V3 receipt; exact output |

The complete journals are both 795,194 bytes and have SHA-256
`7b071f128e05bb0cb650e9b083005ba9d79a95fb4bcdf0d432f7aad3b63e8024`.
Final CPU, RW-memory, and output identities match exactly. A representative
first-leaf comparison for the preceding compact-union change was 12.85 s to
1.32 s (9.73x), also byte-identical.

The retained implementation:

1. keeps an append-only canonical initialized-word inventory;
2. sorts and merges only newly initialized and newly accessed addresses;
3. uses the leaf-local tracker's first-access values as the exact segment-entry
   state, avoiding a redundant full RW-memory copy; and
4. leaves global-continuous baseline behavior unchanged.

## Native recovery checkpoint

The first full combined-profile run is retained at
`/private/tmp/stwo-ethereum-combined-full.C7RVe6/bundle`. Independent replay of
its V3 receipt is green. It retired 880,760,229 cycles in 210 leaf-local
segments: 880,727,328 ordinary core rows and 32,901 authenticated external
rows. Wall time was 70.49 seconds (54.25 user, 16.55 system), or 12.495 million
guest cycles/second. The output SHA-256 remains exactly
`730396807814bc71f14405b3ecf27237778a5359732001b32c93692c3275a8c5`.

Relative to the software-recovery run, the native boundary removes
749,872,078 RV32 cycles (45.99%) and total wall time is 71.96% lower. This is
an execution/trace receipt, not a proof receipt; the current V2 segment
statement still rejects the aggregate global clock above its single-proof
limit. Separate Keccak and recovery dynamic counts are deliberately pending a
versioned manifest projection rather than inferred from the 66-row delta.

## End-to-end proof completion boundary

The proving campaign has two separately named completion milestones:

1. **Verified segment collection.** Every leaf-local segment is proved and
   freshly verified; adjacent CPU/memory/clock statements close exactly; the
   first entry and terminal output bind the pinned block statement; and one
   immutable manifest binds the complete ordered leaf set. This is the closest
   local comparison to the retained ZisK run, which verified its inner proofs
   but explicitly wrote no final aggregate proof.
2. **Single recursive root.** A balanced temporal tree recursively verifies the
   complete leaf collection and emits one fresh-verifiable root proof whose
   public statement binds the same ordered coverage root and terminal output.

A combined-profile smoke or one verified segment is an integration gate, not
an Ethereum-block proof. Conversely, the verified segment collection is a real
cryptographic proof bundle even before succinct aggregation; it must not be
labeled a single final proof. Timing reports keep execution, witness, direct
segment proving, segment verification, recursive proving, and final-root
verification disjoint.

## Remaining hot path

A ten-second ReleaseFast statistical sample captured 8,325 main-thread
samples. The largest top-of-stack buckets were `retireOne` (2,290, 27.5%),
array growth `memmove` (1,955, 23.5%), initialized-word hash membership (573,
6.9%), and memory-clock hash lookup (253, 3.0%). This rules out more boundary
sorting as the main next target.

Two bounded changes follow directly from that evidence:

1. reserve the known leaf's dense trace and three-per-core-retirement access
   envelope once, before the first architectural mutation; and
2. keep a sparse one-bit-per-word presence page beside sparse memory pages so
   load/store retirement does an indexed presence read while the hash map is
   retained only as the canonical iterable inventory.

Both remain proof-semantics neutral. The larger gain still requires the
minimal-capture/parallel-replay split below.

The diagnostic `riscv-trace-dump` executable also used Zig's general-purpose
debug allocator even though both production RISC-V products use
`std.heap.smp_allocator`. The campaign now aligns the diagnostic with the
production allocator. Any measured delta is reported as measurement/runtime
plumbing, not an AIR or proof-speed improvement.

## Why this does not reach the target

The current runner still fetches, decodes, retires, records clocked register and
memory transitions, appends a full `TraceRow`, and materializes the complete
memory boundary in one sequential pass. Larger leaves are not a solution: a
16M-row experiment exceeded 2 GiB RSS and slowed sharply before it was stopped.

The next target is at least 120 million guest cycles/second on this host, which
would make the same pre-precompile cycle count roughly a 13-second execution.
The combined Ethereum recovery boundary should separately remove most of the
software secp256k1 cycle count.

## Two-phase architecture

ZisK's primary implementation uses an AOT-translated minimal-trace executor and
parallel memoryless witness re-execution. The relevant sources are
`rom-setup`, `emulator-asm`, `common/src/emu_minimal_trace.rs`, and
`emulator/src/emu.rs` in
[`0xPolygonHermez/zisk`](https://github.com/0xPolygonHermez/zisk).
The explanatory references supplied during this campaign are
[`Deconstructing the 1.5 GHz zkVM`](https://hackmd.io/@0xdeveloperuche/rkd1vBsElx)
and [`Beyond ZisK`](https://hackmd.io/@0xdeveloperuche/S1sZEi7Lxl).

The Stwo-specific design must be vertically integrated with the typed AIR:

1. **Sequential execution:** translate admitted RV32 basic blocks to a bounded
   native/threaded executor. Emit only ordered memory-read words, full CPU
   checkpoints, completion data, and authenticated Keccak/recovery events.
2. **Parallel replay:** start each leaf from its checkpoint and consume its
   memory-read/event tape without loading the original memory. Reuse the
   existing generated retirement authorities to fill full typed witnesses.
3. **Memory proof:** bind every replayed read/write transition to the admitted
   initial/final memory commitment and require exact tape exhaustion.
4. **Custody:** bind program/ELF identity, profile, chunk order, cycle range,
   checkpoint adjacency, tape digests, precompile tapes, and final output.
5. **Differential gate:** require identical final CPU/memory/output and full
   typed rows versus the current interpreter across every opcode, continuation,
   precompile, malformed tape, omission, duplication, and reordering mutation.

The AOT/minimal tape is an untrusted witness generator. Only successful typed
replay plus the existing proof/verifier path can promote its result. This keeps
the accelerator general and prevents a second proof semantics authority.

## Phase-1B minimal-capture checkpoint

The first ReleaseFast interpreter-based minimal capture executes a 65,532-cycle
representative RV32 loop against an authenticated 3.35 MB dense ROM. It reuses
the production decode cache and the pinned typed scalar retirement authorities,
but constructs neither `TraceRow` nor `StateChainTracker` records during the
sequential pass.

| phase | evidence | throughput |
| --- | --- | ---: |
| minimal sequential capture | warm diagnostic; source-drift receipt | 163.80M cycles/s |
| minimal sequential capture | final isolated 12/12 GREEN filter | 74.49M cycles/s |
| full typed replay, before bounded reserve | warm diagnostic | 16.53M cycles/s |
| full typed replay, after bounded reserve | comparable full-suite style | 25.80M cycles/s |
| full typed replay, final isolated filter | 12/12 GREEN | 15.04M cycles/s |

The warm capture/replay gap is 9.91x, while the isolated measurements show that
this microbenchmark is sensitive to process and host state. Calling the existing
bounded leaf-capacity admission before replay improved the comparable replay
sample from 16.53M to 25.80M cycles/s (+56%), but the isolated filter did not
reproduce that absolute rate. A mixed 25-cycle differential leaf spanning all
17 ordinary opcode families has exact CPU, trace-row, state-chain, and touched
memory parity with the existing runner. The ReleaseFast test completed, but its
development gate receipt was correctly marked source-drift because another
lane changed the shared checkout during measurement; the numeric checkpoint is
therefore diagnostic. The final isolated filter is retained under gate receipt
`1788117345147360000-26115` and passed 12/12.

The earlier 11.95-second/eight-worker and 8.72-second/sixteen-worker projections
used the warm 163.80M capture sample and must not be promoted. Using the final
isolated 74.49M capture rate places a hard sequential floor of 11.82 seconds for
the measured 880,760,229-cycle workload before replay and integration. The
execution research tranche stops here by direction; parallel efficiency,
cryptographic event replay, memory-boundary authentication, and proof-row
publication remain open measurements after the end-to-end proof path is green.

## Problem-match brief

**Task and required semantics.** Execute one admitted deterministic RV32IM
program from an authenticated entry state, retain enough information to
reconstruct every typed AIR row, and produce the same terminal CPU, memory,
public output, statement, and proof as the existing interpreter. The output is
an exact witness, not an approximation; malformed, omitted, duplicated, or
reordered tape data must fail closed.

**Inputs, scale, and model.** The measured combined Ethereum run is
880,760,229 guest cycles split across 210 leaves, with sparse word-addressed
memory and ordered Keccak/recovery events. The relevant cost model is work/span
plus memory traffic: sequential capture latency, parallel replay throughput,
tape bytes, peak RSS, and end-to-end proof latency. The baseline captures full
rows and state-chain accesses sequentially at 12.495 million cycles/second.

**Constraints and exploitable structure.** Program execution is deterministic;
instruction words come from committed ROM; each leaf has an exact entry CPU;
memory observations and precompile events are totally ordered; typed retirement
authorities already define all 46 ordinary opcodes; and separate leaves can be
replayed independently once their checkpoints and read/event tape slices are
authenticated. Addresses and decoded instructions must be derived during
replay rather than supplied by an untrusted tape.

| candidate | relationship | expected work/span | fit and principal risk |
| --- | --- | --- | --- |
| Optimize the existing full interpreter | exact baseline | one sequential full-witness pass | Low integration risk, but the measured `retireOne`/row/access publication span remains; implausible route to 10x. |
| N independent whole-program executions | relaxation of parallel replay | N times execution work | Easy partitioning, but duplicates computation and complicates deterministic external-event custody; rejected. |
| Sequential minimal trace + memoryless leaf replay | exact decomposition | O(T) light capture + O(T/W) witness replay | Matches the deterministic checkpoint/read-stream structure and existing typed authorities; selected. |
| AOT/native basic-block capture | implementation refinement of selected decomposition | lower constant in sequential O(T) capture | Highest eventual ceiling, but larger code-generation and audit surface; defer until interpreter-based minimal capture is proof-equivalent. |

**Chosen canonical problem and mapping.** This is deterministic execution-log
checkpointing followed by embarrassingly parallel trace reconstruction. A
Stwo leaf checkpoint maps to a replay initial state; the ordered old-word tape
maps to memory observations; committed ROM supplies instructions and addresses;
typed retirement supplies transition and witness semantics; and leaf order plus
entry/exit memory commitments recovers the global execution. ZisK uses the same
high-level decomposition in its assembly executor/minimal trace and parallel
witness generation. Its official proving flow also distinguishes execution
trace generation, state-machine witness generation, polynomial commitments,
and proof construction, which is the timing partition used for the eventual
comparison.

**Prior implementations and evidence.** Primary implementation evidence is the
Apache/MIT-licensed [`0xPolygonHermez/zisk`](https://github.com/0xPolygonHermez/zisk)
repository, particularly its emulator, assembly executor, ROM setup, and
minimal-trace types. The official
[`ZisK quickstart`](https://0xpolygonhermez.github.io/zisk/getting_started/quickstart.html)
defines the end-to-end proof stages, while its
[`hints documentation`](https://0xpolygonhermez.github.io/zisk/getting_started/hints_stream.html)
requires deterministic ordered hint generation and proof-side verification.
The two supplied explanatory articles are useful architecture guides, but the
local pinned ZisK source and official docs remain the authority.

**Selected transfer and rejected alternatives.** Transfer the decomposition,
not ZisK's ISA, witness format, or repeated whole-program worker strategy. The
first implementation uses one sequential interpreter capture that emits CPU
checkpoints, exact old words, completion, and semantic external events; workers
then invoke the existing Stwo typed retirement authorities. AOT/basic-block
translation is a later interchangeable capture producer. Larger dense leaves
were rejected after the 16M-row experiment exceeded 2 GiB and slowed sharply.

**Prediction, crossover, and falsifier.** With capture throughput `Rc`, replay
throughput `Rr` per worker, and `W` workers, the first-order rate is
`1 / (1/Rc + 1/(W*Rr))`. At `Rc=120M`, `Rr=12.5M`, and `W=16`, the prediction is
75M cycles/second, or about 11.7 seconds for the current combined workload;
sub-10 seconds requires 88.1M end-to-end cycles/second. At the same replay
rate, that in turn requires roughly 158M cycles/second from sequential capture,
so interpreter capture is a milestone and AOT remains the likely final step.
The design is
falsified if authenticated tape production remains dominated by the same full
row/access machinery, if replay parallel efficiency is below 70%, if tape/RSS
scales like the full witness, or if any proof/transcript differs from the
reference path.

**Correctness and benchmark plan.** Differentially compare every opcode
family, repeated-address load/store behavior, continuations, Keccak/recovery
events, CPU/memory/output, typed rows, state-chain accesses, statement,
transcript, and proof. Reject tape mutations and non-adjacent leaves. Measure
capture and replay separately at 1/2/4/8/max workers, then run the pinned block
through fresh proof and verification. Compare Stwo and ZisK on the same block,
input/output, security mode, and local hardware, reporting execution, witness,
commit/prove, verify, steps, rows/cells/components, proof bytes, and peak RSS as
separate columns.

**Open uncertainty.** The interpreter-based minimal capture's attainable rate,
replay scaling under memory bandwidth, authenticated memory-boundary cost, and
the exact local ZisK end-to-end macOS proof support remain measured questions;
none is promoted from an execution-only result.

## First joined Ethereum proof profile

The first joined base + Keccak + signer-recovery CPU proof was intentionally
started in Debug as a correctness gate. A live two-second sample taken after
the test had reached proof construction placed every main-thread sample in the
lazy FRI quotient path:

`FriProver.commitLazy -> LazyQuotientProvider.computeAllWithTileSink ->
quotient_tile_executor.accumulateTile -> accumulateLiftedRuns`.

The process was using one CPU core at roughly 100% with about 961 MB resident,
while every visible `Thread.Pool` worker was sleeping. This is diagnostic
evidence, not a ReleaseFast benchmark, but it is sufficiently unambiguous to
define the first proof-throughput experiment: bind a strict multi-worker proof
execution authority around the whole transaction (not only Tree 2), retain
proof/transcript identity, and measure the quotient/FRI phase at 1/2/4/8/max
workers. The sample is retained at
`/private/tmp/ethereum-leaf-debug.sample.txt` for this run.

The correctness gate still comes first. No timing from the Debug smoke will be
used as a headline result, and no parallel change is accepted without a fresh
verification and byte-stable public statement/transcript.
