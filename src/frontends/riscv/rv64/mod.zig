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
pub const execution_profile = @import("execution_profile.zig");
pub const services = @import("service_session.zig");
pub const compact_tape = @import("compact_tape.zig");
pub const compact_tape_wire = @import("compact_tape_wire.zig");
pub const arith256_mod = @import("service_primitives/arith256.zig");
pub const secp256k1_rcb = @import("service_primitives/secp256k1.zig");
pub const sha256_compression = @import("service_primitives/sha256.zig");
pub const ethereum_services = @import("ethereum_services/session.zig");
pub const boundary_capture = @import("boundary_capture.zig");
pub const ethereum_contract = @import("ethereum_contract.zig");
pub const fast_execution = @import("fast_execution.zig");
pub const ram_word_set = @import("ram_word_set.zig");
pub const checkpoint = @import("checkpoint.zig");

test "api signature: RV64 mathematical providers preserve canonical modules" {
    const math_test = @import("std").testing;
    try math_test.expect(arith256_mod == ethereum_services.arith256);
    try math_test.expect(secp256k1_rcb == ethereum_services.secp256k1);
    try math_test.expect(sha256_compression == ethereum_services.sha256);
}
