//! RISC-V AIR claim and interaction claim types.
//!
//! Each enabled component has a ComponentClaim (containing log_size) and a
//! ComponentInteractionClaim (containing the logup claimed_sum). The
//! RiscVClaim aggregates all component claims into optional fields.
//!
//! Ported from stark-v's claim system for RV32IM.

const QM31 = @import("stwo_core").fields.qm31.QM31;
const M31 = @import("stwo_core").fields.m31.M31;

/// Per-component claim: the component is active with the given log_size.
pub const ComponentClaim = struct {
    log_size: u32,
};

/// Per-component interaction claim: the logup sum for this component.
pub const ComponentInteractionClaim = struct {
    claimed_sum: QM31,
};

/// Top-level RISC-V claim: aggregates optional claims for all components.
///
/// A component is present iff its claim is non-null, meaning the trace
/// contains rows for that opcode family / infrastructure table.
pub const RiscVClaim = struct {
    // ---- Opcode family components (16) ----
    base_alu_reg: ?ComponentClaim = null,
    base_alu_imm: ?ComponentClaim = null,
    shifts_reg: ?ComponentClaim = null,
    shifts_imm: ?ComponentClaim = null,
    lt_reg: ?ComponentClaim = null,
    lt_imm: ?ComponentClaim = null,
    branch_eq: ?ComponentClaim = null,
    branch_lt: ?ComponentClaim = null,
    lui: ?ComponentClaim = null,
    auipc: ?ComponentClaim = null,
    jalr: ?ComponentClaim = null,
    jal: ?ComponentClaim = null,
    load_store: ?ComponentClaim = null,
    mul: ?ComponentClaim = null,
    mulh: ?ComponentClaim = null,
    div: ?ComponentClaim = null,

    // ---- Infrastructure components ----
    program: ?ComponentClaim = null,
    memory: ?ComponentClaim = null,
    merkle: ?ComponentClaim = null,
    poseidon2: ?ComponentClaim = null,
    mem_clock_update: ?ComponentClaim = null,
    reg_clock_update: ?ComponentClaim = null,

    // ---- Preprocessed table components ----
    bitwise: ?ComponentClaim = null,
    range_check_20: ?ComponentClaim = null,
    range_check_8_8: ?ComponentClaim = null,
    range_check_8_11: ?ComponentClaim = null,
    range_check_8_8_4: ?ComponentClaim = null,
    range_check_m31: ?ComponentClaim = null,

    // ---- Preprocessed multiplicity tracking ----
    bitwise_mult: ?ComponentClaim = null,
    range_check_20_mult: ?ComponentClaim = null,
    range_check_8_8_mult: ?ComponentClaim = null,
    range_check_8_11_mult: ?ComponentClaim = null,
    range_check_8_8_4_mult: ?ComponentClaim = null,
    range_check_m31_mult: ?ComponentClaim = null,
};

// NOTE: the canonical interaction claim for the wired LogUp buses is
// `prover.RiscVInteractionClaim` (frontends/riscv/prover.zig); the historical
// per-family optional mirror that lived here was never consumed and was
// removed when the real interaction tree landed.

test "claims: default initialization" {
    const claim = RiscVClaim{};
    try @import("std").testing.expect(claim.base_alu_reg == null);
    try @import("std").testing.expect(claim.div == null);
    try @import("std").testing.expect(claim.range_check_m31 == null);
}
