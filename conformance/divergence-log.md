# Upstream divergence ledger

This is the operative ledger for intentional differences between the Zig
implementation and its pinned Rust correctness oracles. A difference remains a
release blocker unless its row explicitly says otherwise. Removing a difference
must remove the row in the same commit.

Some rows are architectural disclosures rather than temporary debts: their
absence is itself a gate failure, because deleting them would hide a permanent
divergence or an oracle limitation. Those rows are listed in
`REQUIRED_ARCHITECTURAL_DIVERGENCES` in
`scripts/riscv_release_gate_lib/contract.py`, and their conditions are read by
`python3 scripts/check_riscv_release_contract.py --all`; a row's status text and
the code that enforces it must be changed together.

## Active divergences

| Lane | Boundary | Current Zig behavior | Pinned-oracle behavior | Release status |
| --- | --- | --- | --- | --- |
| RISC-V | PCS geometry | Uses the repository's lifted PCS and folded query points. | Stark-V uses its upstream commitment/evaluation geometry. | Allowed only with the committed composition self-check and proof mutation coverage; not a semantic waiver. |
| RISC-V | Interaction transcript | After the shared Stark-V prefix, Zig mixes a domain-separated shard manifest before the fixed schema-v3 10-bit PoW nonce, twelve relation pairs, interaction claim/root, and downstream PCS. The production prover and verifier expose caller-owned channels; their exact byte-event traces agree, and independent CLI processes bind the final channel digest plus draw counter, implementation commit/dirty state, and executable SHA-256 in strict receipts. | Stark-V has no shard-manifest extension and its generated constant drops PoW to 1 bit in debug builds. | Allowed only with the committed full-path event-symmetry test, shared-prefix Rust parity, fixed release security parameters, transcript-state draw-count regression, and a fresh separate-process receipt from the exact candidate executable. Byte-identical proof-wire parity is not claimed after the documented extension. |
| RISC-V | RV32IM decode boundary | Rejects `FENCE.I` (`0x0000100f`) before witness construction because Zifencei is outside `rv32im-zkvm-v1`. | Pinned Sail retires the word even with `extensions.Zifencei.supported=false` and reports the configured ISA as `rv32im`. | Allowed only with the machine-profile record of the narrowing and the live negative gate that requires Zig rejection plus the pinned Sail disposition. This is a conservative narrowing: no admitted instruction semantics are overridden. |
| RISC-V | Opcode AIR constraint and lookup layout | Adds constraints and one lookup the pinned Stark-V AIR omits, each closing a demonstrated under-constraint. (1) Every read-only access binds `next == previous` (`semantics/common.zig` `readOnlyAccessConstraints`), applied to `rs1`/`rs2` across all sixteen register-touching families and to `src` in `load_store`. (2) `SB`/`SH` bind every unmarked byte of the destination word to its previous value. (3) `AUIPC` pins `imm_limbs[0] == 0`, making the U-type immediate's byte decomposition injective. (4) `JALR` adds an `rs1` middle-byte `range_check_8_8` request, raising its entry vector from 12 to 13 entries and 6 to 7 batches. Two residual obligations stay global rather than row-local and are documented at their site: DIV divisor-limb byte-ness (a non-byte `rs2` consume cannot balance the register bus because every write is byte-range-checked) and JALR `to_pc_lsb` (a flipped bit yields an odd fetch target no ROM entry can serve). | Pinned Stark-V leaves each of these unconstrained: a source access may emit a value it did not consume, `SB`/`SH` leave the unmarked bytes free, the AUIPC immediate admits a second decomposition offset by `p + 2`, `composeU32(rs1.next)` is unbounded in JALR, and its vector is 12 entries / 6 batches. | Allowed only with the demotion recorded in `conformance/upstream.md`, a pinned divergence shape for every affected CP-11 boundary, and the per-item rejection tests. Stark-V is no longer the correctness oracle for opcode AIR constraints: an oracle that admits these under-constraints cannot arbitrate AIR soundness. It stays pinned and authoritative for the shared transcript prefix and for legacy layout lineage. `per_family_witness_rows`, `relation_tuples`, `relation_sums` and the JALR interaction geometry therefore differ from the pinned dump by design; they are demoted in `scripts/riscv_release_gate_lib/air_divergence.py`, which requires each to publish the complete enumerated set of structural paths where the two dumps differ and accepts only the digests listed in `AUTHORIZED_SHAPES`. No shape is authorized yet, so the exhaustive CP-11 gate fails closed until one is recorded from a run over the post-fix candidate. Nothing is waived: a difference at any other path changes the digest and fails the gate, layout lineage (family identity, column identity, column order, relation order) must still agree, both sides must still balance to zero per relation domain, and every parity boundary including the shared transcript prefix is unaffected. Each item has an executable rejection test in its owning module, and the constraint-count and entry/batch pins in `opcode_entries.zig` and `opcode_interaction.zig` were updated in the same change. Two residual obligations are global rather than row-local and are documented at their site. Cross-family coverage is per-module only; a generic witness-rigidity suite over all seventeen families is not yet committed and remains open work under `soundness/ROADMAP.md`. |

## Closure requirements

Every release-blocking row requires prover/verifier integration, an adversarial
proof-level rejection test, and evidence against the exact pinned Rust oracle.
Internal Zig prove/verify consistency is necessary but cannot close a row by
itself.
