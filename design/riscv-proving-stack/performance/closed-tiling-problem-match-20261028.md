# Size executions by complete proof cost, not by cycles alone

Task: find whether fewer, larger native executions remain beneficial after RAM,
ROM, lookup tables, precompiles, register windows and endpoint closure are all
actually proved and freshly verified. Prior ALU-only tiling left globals open;
its 12–14x phase ratio cannot establish this result.

Inputs: the same release-ABI RV32 guest, authenticated ELF/input/output and
machine endpoints, with two SHA compressions, one Keccak permutation, repeated
register updates and load/store accesses, and real terminal output publication.
Partition the same execution into one, four and optionally eight nonempty
segments. Register custody is local in every arm. The existing bounded direct
batch driver proves 1–8 native children; original global provider files remain
required. This experiment does not change the theorem or claim a standalone
recursive block root.

Canonical match: contiguous segmentation under resource constraints, with a
cost for each segment and its recursive verifier. Dynamic programming is exact
for an additive cost model, but our composition-domain jumps, shared provider
tables and one recursive batch are not additive. Therefore do not invent a
linear per-cycle model or implement a planner before measuring the coupling.
First enumerate a small fixed set of feasible partitions. Candidate alternative:
minimize padded native cells alone. Prior ALU results falsified that objective;
record native, companion and memory cells to test it with global closure.

Sources: [ZisK's pinned topology](https://github.com/0xPolygonHermez/zisk/blob/1e22630bb7e143c30705a1603ed87cfd3da8c6ec/pil/zisk.pil)
instantiates separate Main, Mem, ROM, arithmetic and precompile AIR sizes;
[Stwo's prover](https://github.com/starkware-libs/stwo/blob/dev/crates/stwo/src/prover/mod.rs)
combines component constraints and commitments. The transferable idea is
independent component sizing and amortized proof overhead, not their reported
GPU wall time. No external source code is copied.

Hypothesis: local register custody and packed RAM remove the old memory-driven
need to fragment this mixed execution, so fewer native proofs reduce recursive
preparation/proving and metadata even if padding rises. Falsifiers: longer
segments exceed the same aggregate budget, global proof work erases recursion
savings, or any fresh closure fails. A failed arm is a resource/correctness
boundary, never silently omitted from a speedup claim.

Measurement: eight workers, fixed security profile and 40 GiB shared driver
budget. Record preflight, source initialization, driver wall, collection, base
publication, recursive preparation/setup/proof/encoding, fresh verification,
charged peak, file bytes and actual geometry. Family timings overlap; do not
sum them into wall time. Also record extra cold detached verification outside
the driver timer. Compare the exact closed span endpoints, program fetches and
memory event counts. Altered independent endpoint and missing proof files must
reject. Fresh complete verification, not a host digest, establishes validity.

Open: this synthetic mixed workload is not Ethereum's opcode/precompile mix.
The existing driver remains limited to one native batch and global providers
outside recursion. A successful test justifies larger real-block sizing and
integration work; it is not a block ETA or full recursive soundness certificate.
