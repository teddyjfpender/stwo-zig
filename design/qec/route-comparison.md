# iadd256 proof-route comparison

This is an architecture experiment for the public, SHA-256-pinned KMX fixture
defined in [benchmark-contract.md](benchmark-contract.md). The first measured
rung is **one repetition of one complete 64-shot batch**, not the upstream
8,000-repetition, 9,024-shot benchmark. The routes currently have
different proof boundaries, so the numbers below are resource observations,
not a speed ranking.

| Route | Verified proof boundary | Security | One-batch result | Peak host memory | Main scaling limit |
| --- | --- | --- | --- | --- | --- |
| RV32 guest | Hashes supplied KMX bytes, derives SHAKE inputs, executes every fixed gate, checks the result and returns the public commitment | 70 FRI queries, 26 PoW bits | 10,748,299 RV32 steps; 7.581 s prove, 0.256 s verify | 16.24 GB | 16,777,216-step native cap; later batches replay an ever-longer SHAKE prefix |
| Cairo executable | Executes fixed gates and an independent addition check on host-derived public SHAKE inputs; all 512 result words are public | 70 FRI queries, 26 PoW bits; official Rust verifier accepted proof | 36,935,007 Cairo steps; 17.024 s prove, 0.010 s Zig verify | 29.46 GB | The direct proof has 513 output cells and cannot itself enter the two-cell leaf wrapper |
| Cairo bootloader leaf | Fixed Cairo1 task checks all 512 input and output words; pinned bootloader binds its program hash and two result cells before circuit wrapping | 70 FRI queries, 26 PoW bits for Cairo and circuit; two distinct leaves independently verified | Batches 0/1: 27.18/23.35 s Cairo prove plus 12.79/13.49 s wrap; their fold took 8.26 s | 40.12/41.82 GB leaf peaks; 13.81 GB fold peak | Only two of 141 batches and one repetition; fixed public KMX and host SHAKE remain outside the proof |
| Direct gate AIR | Constrains all CX/CCX transitions and 512 terminal bits for 64 distinct shots against verifier-reconstructed public fixture/challenge columns | 70 FRI queries, 26 PoW bits; fresh Zig verifier accepted proof | 228,544 trace cells; 22.006 ms prove, 35.377 ms decode/verify at one repetition | 12.501 MB whole-process RSS | Wide static columns grow with repetitions; SHAKE and parsing are trusted host verifier work |

All observations ran on the same Apple M5 Max with 64 GiB RAM. The Cairo
receipt's `target.cpu_model=apple_m1` names its generic Zig compilation target,
not the physical host. They must not be divided into a route speedup because
the proof boundaries differ. The RV32 and Cairo proof hashes and reproduction
commands are recorded in their `vectors/riscv_guests/iadd256_kmx` and
`vectors/cairo/qec_iadd256` READMEs and TSVs; the gate AIR's focused receipt
is in `direct-gate-air.md`. RV32 and Cairo timings are single observations;
the AIR table shows the median of five isolated runs. The compared first rung
uses the same fixed gate order, 64 SHAKE-derived test vectors, and one
repetition, but only the RV32 guest currently checks SHAKE derivation inside
its proved execution.
The RV32 guest exposes the raw KMX as public input, whereas the upstream Rust
challenge treats it as private and publishes its hash. None of these routes has
produced a complete 141-batch recursive root.

The direct AIR's verifier reparses the pinned public circuit, derives the 64
SHAKE pairs, recomputes the fixed-column root and rejects a changed challenge.
Its AIR proves the gates and terminal equalities, while SHAKE, SHA-256 and
parsing execute as trusted verifier code. The direct AIR's 12.501 MB is the
maximum RSS of a fresh benchmark process at one repetition, whereas the RV32
value is a CLI maximum RSS and the Cairo value is a process-lifetime physical
footprint.
These memory boundaries differ. The direct AIR also proved and freshly
verified two and four repetitions, with 60.369/80.929 ms median proving and
16.564/25.510 MB whole-process maximum RSS. The proof-of-work candidate
indices differ between rungs, so those times are not pure gate-scaling slopes.
All 15 direct-AIR observations, tamper checks, timing boundaries and
reproduction commands are in [direct-gate-air.md](direct-gate-air.md).

## What scaling already rules out

The first-batch RV32 setup consumes about 10.65 million instructions. Each
additional repetition adds about 101,403, so 61 repetitions exceed the
current 16,777,216-step native leaf cap. A 61-repetition segmented **execution**
was captured, but those segments are not proof-bearing. Replaying SHAKE from
the KMX seed made the last batch take 83,892,949 instructions for one
repetition; that too is execution-only evidence. Simply increasing leaf count
will not make the full upstream workload practical.

The direct Cairo executable has a 36.9 million-step proof and a 29.46 GB
host peak. Its generated 117 MB PIE exceeded the present PIE adapter's
`memory.bin` limit. Its separately verified proof cannot be passed directly
to `leaf-wrap`: the wrapper reproves adapted input under its registry's Cairo
profile, and the direct program publishes 513 cells where the circuit leaf
accepts exactly two bounded cells.

A separate fixed-statement Cairo1 program now returns two digest cells. The
pinned Cairo bootloader executes it inside a Cairo 0 trace with all eleven
public segments and binds the executable program hash and its result cells.
The bridge recomputes the SHA-pinned fixture, SHAKE inputs, gate outputs,
digest, generated source and arguments, then freshly compiles the executable
before admitting its compact input. Two distinct 64-shot leaves passed
independent circuit-proof verification and folded into a terminal root proof.
The pinned StarkWare Cairo verifier independently accepted that terminal
felt-stream proof; a focused checker also bound its public output to the
production registry and the two-leaf packed tree. Altered proof felts and an
altered output claim were rejected. The terminal verifier executed 9,747,576
Cairo steps; this is verification work, not part of the 8.26 s fold time.
The original standalone Cairo proof was not reused: `leaf-wrap` generated new
Cairo and circuit proofs. Exact receipts and commands are in the
[Cairo QEC README](../../vectors/cairo/qec_iadd256/README.md) and
[terminal-root verifier](../../tools/verify_terminal_root.md). This is a real
Cairo-to-fold path over batches 0 and 1, not the full workload.

## Next proof architecture

Use the fixed circuit hash to bind a parsed gate table once. Derive the
9,024 target/offset pairs in one authenticated SHAKE stream and prove indexed
state checkpoints at the 141 batch boundaries. Each leaf should then prove a
bounded range of `(batch, repetition, gate)` transitions on 64 bit-sliced
shots and bind its full 512-word state before and after. A root verifier must
check exact segment continuity, complete gate/repetition ranges, all 141
batches exactly once, the final 64-shot batch size, output/offset checks and
checked resource totals. Inputs and commitments must be included in the
transcript, not merely supplied as unverified host metadata.

A dedicated gate AIR avoids generic guest instruction overhead in the measured
one-to-four-repetition, 64-distinct-shot ladder. Its wide static columns grow
linearly with gate count and repetition count, so the next measurement must
use a scalable segmented relation at larger repetition counts. A one-shot or
fixed-fixture equivalence proof can validate the transition logic without
establishing the cost of the full workload. A sparse, row-oriented gate AIR
with authenticated state-access/permutation relations is the likely scalable
direction if a wide static circuit grows linearly with gate count. This is an
architecture hypothesis until a verified multi-segment root demonstrates it.
