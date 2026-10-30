//! Experimental RV64IM execution frontend. No AIR, proof or SP1 ABI is admitted.
//! Kept separate from the released RV32IM machine and statement formats.
pub const profile = .{
    .name = "rv64im-execution-v0",
    .xlen = 64,
    .instruction_alignment = 4,
    .proof_supported = false,
    .sp1_abi_supported = false,
};
pub const decode = @import("decode.zig");
pub const memory = @import("memory.zig");
pub const machine = @import("machine.zig");
pub const elf = @import("elf.zig");
pub const Session = @import("session.zig").Session;
pub const Word = @import("word.zig").Word;
pub const csp_contract = @import("csp_contract.zig");
