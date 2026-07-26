//! Compatibility import for callers migrating to `riscv/isa/decode.zig`.

const canonical = @import("../isa/decode.zig");

pub const Opcode = canonical.Opcode;
pub const OperandUsage = canonical.OperandUsage;
pub const ProofOpcodeError = canonical.ProofOpcodeError;
pub const operandUsage = canonical.operandUsage;
pub const isLoad = canonical.isLoad;
pub const isStore = canonical.isStore;
pub const memoryWidthBytes = canonical.memoryWidthBytes;
pub const proofOpcode = canonical.proofOpcode;
pub const DecodedInst = canonical.DecodedInst;

test {
    _ = canonical;
}
