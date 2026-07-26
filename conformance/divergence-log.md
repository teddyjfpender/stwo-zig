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
| RISC-V | Opcode AIR constraint and lookup layout | Adds constraints, committed columns, and lookups the pinned Stark-V AIR omits, each closing a demonstrated under-constraint. (1) Every read-only access binds `next == previous` across all register-touching families and `load_store.src`. (2) `SB`/`SH` preserve every unmarked destination byte. (3) `AUIPC` pins the U-immediate decomposition. (4) JALR preserves its exact 32-column legacy prefix and appends nine columns that bind all source bytes, its signed I-immediate, bit 0, and u32 wraparound with an exact byte-carry recurrence; the bounded `target / 4` low20/high8 split mirrors the program AIR. Its relation vector is 18 entries / 9 batches rather than 12 / 6. (5) DIV-family rows add two divisor-byte requests and one quotient-sign request, raising their vector from 22 to 25 entries, while directly pinning the zero-divisor sign convention; `lt_diff` stays on RC_20. (6) Signed loads and right shifts bind their sign witnesses to the operand bit they claim. The previously global DIV byte-ness and JALR target-bit obligations are now row-local. | Pinned Stark-V permits source accesses to emit unconsumed values, leaves partial-store bytes and several sign witnesses free, admits the AUIPC `p + 2` alias, does not bind JALR's target decomposition, and does not byte-range DIV divisors. | Allowed only with the demotion recorded in `conformance/upstream.md`, a pinned divergence shape for every affected CP-11 boundary, and focused executable checks. Stark-V is no longer the correctness oracle for opcode AIR constraints; it remains pinned for the shared transcript prefix and legacy layout lineage. `per_family_witness_rows`, `relation_tuples`, `relation_sums`, and affected interaction geometry differ by design and are demoted through `scripts/riscv_release_gate_lib/air_divergence.py`, which accepts only complete structural-path digests listed in `AUTHORIZED_SHAPES`. No shape is authorized yet, so exhaustive CP-11 fails closed until a post-fix candidate shape is reviewed. Nothing is waived: an unlisted path changes the digest and fails, the JALR legacy column prefix and family identity remain checked, each reviewed relation addition/domain substitution is shape-bound, every relation domain must balance to zero, and the shared transcript prefix is unaffected. Constraint counts, entry/batch pins, wire geometry, and the witness-layout digest change with the implementation. The generic all-family witness-rigidity suite is committed; the end-to-end DIV committed-trace mutation remains an explicit TODO in `soundness/ROADMAP.md`. |

## Closure requirements

Every release-blocking row requires prover/verifier integration, an adversarial
proof-level rejection test, and evidence against the exact pinned Rust oracle.
Internal Zig prove/verify consistency is necessary but cannot close a row by
itself.
