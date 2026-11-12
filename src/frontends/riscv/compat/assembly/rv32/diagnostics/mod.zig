//! Proof-independent diagnostic surfaces owned by the RISC-V frontend.

pub const revm_legacy = @import("stwo_riscv_rv32").diagnostics.revm_legacy;
pub const public_values = @import("stwo_riscv_rv32").diagnostics.public_values;
pub const segment_manifest = @import("segment_manifest.zig");

pub const OPCODE_WITNESS_AUDIT_ENV = @import("stwo_riscv_rv32").diagnostics.opcode_witness.OPCODE_WITNESS_AUDIT_ENV;

test {
    @import("std").testing.refAllDecls(@This());
}
