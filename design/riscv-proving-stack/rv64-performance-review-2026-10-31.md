# Performance review: the multipliers still on the table (2026-10-31)

Status: retained research proposal, not a qualification or measured projection.
The source and receipts have since changed. See the [stage accounting](../../vectors/reports/rv64-word16-execution-20261031/stage-accounting/README.md)
for current measured geometry, corrected lookup counts and hash costs. In
particular the current CPU is 53/40, paired Keccak is 1923/2596, and native
2n evaluation is distinct from shared weighted-quotient geometry. Proposed
GPU, security and whole-block speedups below remain unqualified.

Written against `codex/rv64im-frontend` at `caeb185e1`. Each item states the
mechanism, the evidence in the repository, the expected multiplier, and the
smallest change that captures it. Multipliers compound along the chain
retirements x cells-per-retirement x prover-work-per-cell x (1/parallelism).

## 0. The cost model to steer by

Block cost = R x C x W / P, where R = retirements (104.25M today), C = cells
per retirement (533 today, main+interaction, all components), W = prover
work per cell (quotient on 4n, Blake2s lifted Merkle, 70 queries), P =
device parallelism (CPU today).

| Lever | Today | Reachable with what exists | Beyond the frontier |
| --- | ---: | ---: | ---: |
| R | 104M | 70M (delegations below) | 55M (DMA + SHA + arith256 + interpreter) |
| C | 533 on 4n | 150 on 2n | 100 on 2n |
| W | quotient + lifted Blake2s | 2n halves composition; single accumulators halve inverses | sumcheck constraints, WHIR commitment |
| P | 16 CPU threads | 4 GPUs, resident | 1 to 2 GPUs streaming |

Airbender Prime's reported point is one RTX PRO 6000 under 10 s p99 with
witness. Reaching it needs R x C around 8G cells and W at sumcheck cost;
passing it needs R x C around 5G cells. Today R x C is 55G.

## 1. Cells: single LogUp accumulator per component (about 0.7x cells)

Every component still keeps one inverse-plus-prefix pair per relation
(thin CPU: REG 16, FUNCTION 8, ROM 8, U16 12, U8 12 = 56 interaction
columns for 11 fractions). Pair-batching all fractions of a row into one
prefix needs 6 inverses + 1 prefix = 28 columns. Same for ALU (52 to about
28), LS v1 (116 to about 60), BINARY (28 to 20). Soundness is the standard
single-sum argument with distinct relation challenges; the receiver sums
one QM31 claim per component plus the tables to zero. Also halves the
batch inversions in interaction generation (156 s per block today).

## 2. Cells: no CONTROL chip, static results from the ROM (saves a chip)

LUI, AUIPC, JAL's link and every static next pc are functions of (pc,
instruction word). Put them in the ROM tuple; the CPU binds `C = rom.result`
and `next_pc = rom.next_pc` by family flag. JALR becomes one ALU operation
`(A + imm) & ~1` whose result the row binds to `next_pc`. Branches already
use the two-edge ROM scheme. This removes 4.6 percent of retirements from
any chip and the CONTROL design entirely.

## 3. Cells: 32-bit pc limbs, and `enabled` out of the row

Two u16 limbs per pc and next_pc (4 columns). `enabled = active*(1-zero)`
is a committed column only to keep degree down; with the row at degree 3
and the REG products already degree 3, fold it out where the term it
multiplies is degree 1 (about 3 columns). Small, free.

## 4. Cells: load/store owns memory, Poseidon RAM goes away (about 0.8x total, 35x on RAM cells)

At batch 0 the RAM providers are 385M main + 82M interaction cells (107
cells per retirement), with the 303-column Poseidon2 provider at 82 percent
of that, plus the 29 s RAM witness and the serial root chain. The LogUp
relation in the LS chip plus per-execution INIT/TEARDOWN costs under 10
cells per retirement amortized and lets batches prove in any order. The
closed_ram STARK already has the tuple, the ordering identities and the
sorted boundary tables; the missing pieces are the CPU owner join
(MEMORY bus with the row tick), the collector of cross-batch predecessor
(epoch, tick, value, rights), and general image INIT.

## 5. Cells: fixed tables committed once per block

Every batch recommits U16 (2^16), U8, AND (2^16) and SHIFT16 (2^21 x about
20 columns = 42M cells, 10 cells per retirement on its own). Only the
multiplicity column is per batch. Share the fixed trees across the 25 to 36
batches (the "reusable fixed commitments" path already exists for the ROM);
pay the fixed columns once.

## 6. Cells: measure exact-fact deduplication on real code

Weighted facts cut the ALU from 231M to 112M cells on a degenerate loop and
BINARY now has the same. The number that matters is the distinct
(op, a, b) ratio on batch 0 of the real block per family. Measure it before
counting on it; if it is above 0.5 on real code, the Zisk-style frequent
operations table (one row per distinct fact, multiplicity) is the cheaper
form and the same mechanism.

## 7. Work per cell: 2n and degree 3 everywhere (about 0.5x composition)

Composition is 287 s of the 36-batch run on 4n. The thin lane is degree 3 on
2n; keep every provider there too (the Keccak quartet is degree 5 on 4n:
record it as an experiment, do not promote it until it is degree 3 or it
pays for its own 4n). With composition split 1, the recursion leaf also
drops its composition columns from 16 to 8.

## 8. Work per cell: FRI fold step 4 and plain hasher in the batch protocol

Fold step 1 means 22 FRI layers; the recursion leaf spends two thirds of its
3.1M Blake G gates there. Fold step 4 (6 layers, packed leaves) and the plain
lifted hasher are config changes in `protocol.zig` with no AIR impact; they
cut the leaf to under 1M gates and the batch proof size by about 40
percent. Do them with the Word16 switch, one requalification.

## 9. Work per cell: witness as a streaming, per-chip, parallel pass

Main witness 99 s + RAM witness 29 s per block today, sequential per batch.
With the thin lane the row fill is a 48-byte tape to a 42-column row plus
appending request facts to per-family lists; chips fill from their lists
independently. Make it one parallel pass per batch into pinned buffers, and
overlap it with the previous batch's proving. On the GPU this is the first
kernel of the resident pipeline (design `rv64-cuda-port.md`).

## 10. Retirements: the four delegations that pay (about 0.67x R)

From the round-5 census and the lean-guest residuals: memcpy family 15.3M
(a DMA machine: one row per 8 bytes with two RAM tuples), SHA-256 11.2M
(64 rows per compression with byte lookups), secp field inverse and sqrt
about 9M (arith256 with hint verification: one row per 256-bit modular
product), ecrecover as one service over arith256 (44.9k ADD/DOUBLE bus
crossings to a few hundred). Together about 35M retirements, taking R to
about 70M. The interpreter dispatch (8.7M at 19 instructions per EVM op) and
MPT decode (8.5M) are guest work, not delegations.

## 11. Parallelism: fixed geometry is the gate for everything on the GPU

Variable logs per batch mean a different proof shape per batch, a different
recursion topology per batch (the receiver binds each leaf to its own hash
today), and no memory plan for the device. Fix every chip's log per
protocol version and split batches by capacity. This is the one item that
unlocks one verifying key, one leaf topology, device memory planning, and
multi-GPU scheduling at once.

## 12. Parallelism: the resident CUDA batch prover

Everything above is CPU-measured. The 5 GB per-batch memory plan on the
Word16 shape puts two batches in flight per 32 GB device; four 5090s give
8 to 12 s per block end to end at C = 150. The symbolic lane for constraint
kernel generation now exists (the external-lane contract), so the
constraint kernels are generated from the same authority the CPU runs.

## 13. Beyond: sumcheck constraints and a cheaper commitment

Airbender Prime's step was to stop computing a composition polynomial:
constraints are checked by a GKR sumcheck over the multilinear trace, which
removes the composition's coset evaluation and commitment (the single
largest GPU phase after LDE) and makes W proportional to field operations
per cell. WHIR then removes most of the Merkle hashing and shrinks proofs.
For us this is a new prover lane under the same AIRs: constraints stay in
`emitFor`, the lane evaluates them at sumcheck randomness instead of on
cosets. Everything in items 1 to 12 carries over. This is the item that
takes a 4-GPU parity result to a 1-GPU lead.

## 14. Two measurements to run before anything else

1. Batch 0 of block 24,628,607 through the thin lane with the honest
   coverage filter: cells per retirement, prove time per stage, against the
   legacy 533 and 16 to 22 s. Every item above should move this table.
2. The distinct-fact ratio per family on the same batch (item 6).

## 15. Security parity, stated once

70 queries at blowup 1 plus a 26-bit PoW is a conjectured level in the
mid-90s; Zisk states 128. Decide the target level now, because it sets the
query count that every cost above scales with, and state the conjecture
next to the number as the competitors do.
