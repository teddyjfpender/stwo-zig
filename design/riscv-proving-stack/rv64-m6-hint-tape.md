# RV64 M6 hint-tape v1: fold seed tape (no verifier graph on the fold critical path)

Stream `hint-tape`, branch `codex/rv64-m6-hint-tape`, base `95d40063d` (M5 integrate). Interface: `/workspace/m3/M6-INTERFACES.md`
section `hint-tape` (HT0, HT1). Proof format: **unchanged** (scheduling/witness-generation only).

## What changes

A v2 fold (fold message version 2, `om31_outer.zig`) has a topology that is a function of its geometry class
(`om31_outer.classKey`): the fold circuit guesses the child identity and FIXED root instead of embedding them as
constants (`rv64-m3-topo-binding.md`). The M5 producer already exploits this twice: the class PP cache
(`outer_wrap.PPCache`) and the class assignment-plan cache (`outer_assignment.ClassCache`: tasks, levels, seed-variable
layout). What was still rebuilt per fold was the **verifier graph** itself (≈39 M variables, 0.20–0.72 s) plus padding
(0.09 s), only to read back the seed values (constants and guessed child-proof words).

v1 records those seed values directly:

1. `om31_native/fold_tape.zig` `record(children)` replays the per-child **guess prologue** of `buildFoldMode` — proof
   capture conversion (`V.proof.fromNative` + `V.proof.guess`), the 8 identity words, the outputs, the output words and
   the claims — with the same calls, in the same order and with the same values, on a small trace-only context, and skips
   `V.verify` (the in-circuit verifier body). It returns the values of every origin of kind `seed`, in variable order.
2. `outer_assignment.Prepared.init`, given `device_prove.seed_tape`, pairs the tape with the class template: seeds =
   template constants (`Template.constants`, new) at the template's constant variables, then the tape values at the
   template's seed-origin variables. Tasks, permutation indices and level ends are the template's.
3. The pipeline (`execution_wrap.prepFoldTape`, `outer_wrap.prepareHostTape`) hands the device path a flags-only stub
   graph (trace-only, finalized, recording, no gates) and the class PP; device proving is unchanged.

## Why the bytes are identical (the premise and how it is checked)

The device assignment is a deterministic function of (tasks, indices, level ends, seeds). The first three come from a
template that was built from a full graph of the same class (M5 behaviour, unchanged). The seeds are equal when:

- **P1 (prologue = all seeds).** `V.verify` creates no origin of kind `seed`: every guess it makes is a placeholder that
  `noteWitnessHint` turns into a hint origin (divide, inverse-or-zero, lsb, byte), and constants are interned, not
  origins. *Check:* the tape length must equal the template's seed-origin count or the tape is refused (fallback to the
  full graph, logged `GPU_OUTER_SEED_TAPE refused=length`); `STWO_RV64_FOLD_SEED_TAPE=check` builds both and compares
  every value (`FOLD_SEED_TAPE check_ok`).
- **P2 (same order and values).** The replay calls the same functions with the same arguments in the same order, so
  the seed origins are created in the same relative order; seed variables are taken positionally from the template.
  *Check:* as P1 (check mode compares values position by position).
- **P3 (class constants).** The constant values of a v2 fold are class data (they come from the geometry, the profile
  string, counts and fixed domain words; child-key values are guessed, not constants). *Check:* every full-graph class
  hit (`initFromTemplate`) compares the node's constant values against the template and clears `constants_stable` on any
  difference, which refuses the tape for that class from then on (`GPU_OUTER_SEED_TAPE constants_unstable`).

The acceptance gate is end to end: every recursive proof hash of both dev blocks equals the M5 default receipts.

## Why a wrong tape cannot be accepted

The tape only feeds witness generation. The fold circuit and its AIR are unchanged and still constrain the complete
child verification and the output digest. A wrong seed yields an unsatisfied witness: the prover's output lookup-sum
check (`device_prove.proveOwned`) or the producer's own fresh verification of every fold proof before publication
(`outer_wrap.finishProved`) fails the request; the independent receiver re-verifies everything from source. The tape is
a host-only producer hint (like `class_hint`) and never enters a proof, a transcript or a receiver.

## Scope and what is deliberately not done in v1

- Leaves keep the M5 path (each leaf is its own class under the exact outer shape; 27 classes for 28 leaves on M5).
- The GPU DAG assignment is kept: measured at 16 ms of stream time per fold (2.1 k launches), it is not the fold cost;
  a fused fill kernel would save at most that (kill rule of plan §5 M6: keep the narrow-run DAG for the class).
- Durable-bytes restore and the lane (non-pipelined) path keep the full graph.

## Measured (v1, resident service, both dev blocks; pod not quiet, single observations) [M]

Warm requests, M5 baseline -> tape on: 24628607 fold host prep median 0.403 -> 0.025 s, fold tail 4.81 -> 3.32 s, recursion
18.87 -> 17.01 s, request 28.10 -> 26.30 s; 26235156 0.385 -> 0.019 s, 2.98 -> 2.30 s, 11.94 -> 10.82 s, 18.78 -> 17.24 s.
Every proof byte-identical to the M5 default receipts; check mode 26/26 folds equal; fresh M5 receiver accepted.
Receipts: `vectors/reports/rv64-m6-20261105/hint-tape/`.

## v2: dependency-chain runs for the device DAG (HT2)

The recursion is now device-bound between the first leaf wave and the fold tail, so device time of the assignment
matters: leaves spend 120-150 ms of stream time in the DAG (146 k levels, 3.7-10.5 k launches), folds 16 ms (9 k levels,
2.1 k launches). The M5 narrow runs cap a CTA run at 256 levels of width <= 256 (grid-constant packet) and load every task
record from DRAM after the barrier, so the record load sits on the per-level dependency latency.

`circuit_fill_chain.cu` keeps the exact task evaluation and level order and changes only the execution grouping:
one CTA (512 threads) runs any number of consecutive levels of width <= 2048 (strided), level ends come from a device
array staged through shared memory (1024 per chunk), and the next level's first record is prefetched before the
current level's dependent loads. Levels wider than 2048 keep the ordinary grid launch. Barrier semantics are the M5 narrow
run's (one `__syncthreads` per level orders the CTA's global writes before any later level reads them). Same tasks, same
seeds, same values: proof-neutral; `STWO_RV64_OUTER_ASSIGNMENT_CHAIN=0` restores the M5 narrow runs.
