# Real Ethereum windows and parallel v7 proving

This campaign moves actual retained execution onto the local-register and WORD
RAM architecture, closes every original family recursively, and measures the
three large CPU costs before planning a GPU implementation. It does not claim
that an admitted partial window proves its skipped prefix or an Ethereum block.

## Statement and problem match

The input is a pinned validator ELF, two independently selected complete machine
snapshots, a skipped-prefix offset and an exact retired-instruction count.
Program semantics, ROM membership, registers, RAM accesses, precompiles, lookup
requests and output-state equality remain exact. Both snapshots are benchmark
public admission, not success receipts made by the prover.

The memory problem is ordered read/write consistency with authenticated initial
values and a complete final-state assertion. The canonical reduction is a
telescoping rational multiset difference. For each event at address a, add
1/h(a,after) - 1/h(a,before), with space and canonical address/value limbs in h.
Sorted access-chain continuity telescopes intermediate values away. The sum must
equal the independently derived difference of complete outgoing and incoming
snapshots. Equal endpoint cells contribute zero; a changed untouched cell does
not. Initialization must still bind each first-touch value: a delta equation
alone cannot establish correct memory.

| Candidate | Guarantee and cost | Decision |
|---|---|---|
| Reuse old memory-Merkle partial leaves | Existing statement, but retains the architecture being replaced | Reference only |
| Declare an early window halted | Changes the program and completion theorem | Reject |
| Read every final memory cell through a new terminal provider | Exact, but creates large artificial access inventories | Defer |
| Original WORD RAM plus two physical delta planes | Exact existing chains plus a random rational identity; no new main columns | Select |

The new RAM component preserves all 161 original equations and adds two
recurrences, one per lane. It retains 88 main columns; interaction columns grow
from 116 to 124. Original field/range/link/clock equations and physical sums are
preserved. Word.initial supplies the existing five-coordinate relation; both
endpoint identities and all first roots are fixed before challenges. The new
window epoch, memory entry and recursive family have distinct domains.

Nonterminal completion is the genuine unretired program fetch. The final PC and
all registers are independently admitted. The incoming halt flag is zero; the
window RAM permits no positive-clock nonzero halt. No terminal output claim is
created. Returned summaries explicitly say `declared_window`; their legacy
43-byte output field is unused and zero-filled.

The original terminal epoch retains its exact ten-count transcript framing.
Window mode uses eleven counts and B7WE framing. This distinction propagates
through native, caller, ROM, lookup and memory recursive transcript recorders.
Shared verifier machinery is selected at compile time for these two finite
protocols; it introduces no runtime generic dispatch.

## Implementation and ownership

The source adapter restores the admitted incoming snapshot and uses the same
durable commit-once pipeline as terminal execution. It preserves native/caller
PCS trees, derives one ordered common epoch, then proves the original sources
and providers. Checkpoints are deleted before fresh original verification.

The recursive producer independently derives fixed verifier geometry, captures
the actual original equations, joins all families, and produces a single root.
Detached verification receives owned metadata, expected keys and the root after
original traces, PCS owners and proof objects are destroyed. Snapshot policy is
deep-cloned into metadata; a borrowed producer pointer does not survive.

`Owned.validate` checks structure but cannot authenticate arbitrary deserialized
initialization intervals against a capsule digest. Receiver authority must be
constructed by `Owned.derive` from independently selected capsule bytes. The
current API deliberately treats `Trusted.window` as external verifier policy.

## Parallel performance hypotheses

The retained Mixed421 observation spends 42.974 s in DEEP/FRI, 37.522 s in
composition and 17.054 s in native preparation. These are overlapping workload
categories within one proof, not additional block phases to sum with smaller
benchmarks. The selected changes preserve protocol/security:

- Keep bounded DEEP numerator groups when the complete roster exceeds the
  1 MiB metadata cap; indexed members and partial admission remove an
  all-or-nothing fallback. Preserve an exact grouped/direct partition.
- Batch native inversions in bounded tiles, prepare immutable row inputs once,
  retain caller-owned lookup storage, and normalize invariant claims once.
- Lease CPU worker tiles rather than create nested pools. Preserve exact
  physical claim order and deterministic prefix sums.

The local encoding research is supporting evidence for work removal, not a
source of inherited production speedups. Its most recent multiply/divide
pairing saves cells but does not consistently save time; it is not promoted
without a measured gain on these Ethereum workloads. Compile-time generics are
retained where they specialize equations without runtime cost.

## Qualification and measurement

Require original arbitrary-OODS/symbolic equation parity, every physical sum
bound before interaction commitment, hostile compensated delta claims, wrong
endpoint/initial values, and an independently resealed untouched final-cell
attack. Reuse the same compiled binary for increasing real windows and CPU
worker counts. Keep canonical q70/PoW26, exact ELF/input/state identities, proof
counts, source/binary manifests, phase times, RSS, tracked memory and logical
checkpoint I/O. Record diagnostic and canonical results separately.

The complete root entrypoint is
`src/frontends/riscv/block_v7_real_window_root_test_root_v2.zig`. Its default
genuine captured Keccak window is a correctness fixture; environment-selected
retained guest windows provide the larger measurements. Benchmark mode excludes
hostile controls, and loading/capture are reported separately from prepared
window to verified root. This document records the design; measured results
must be attached before any speedup or full-block claim.
