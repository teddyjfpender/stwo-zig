//! Concrete execution ABI identities. This does not alter ordinary RV64IM decode.
const isa = @import("decode.zig");
pub const Profile = enum { rv64im, keccak_service_v1, ethereum_services_v1, ethereum_services_v2 };
pub const KECCAK_TAG: u64 = 0x00010001;
pub const SECP_ADD_TAG: u64 = 0x00020001;
pub const SECP_DOUBLE_TAG: u64 = 0x00020002;
pub const SECP_ADD_WORD_TAG: u64 = 0x00020011;
pub const SECP_DOUBLE_WORD_TAG: u64 = 0x00020012;
pub const SecpPacketFormat = enum { big_endian_bytes_v1, little_endian_words_v2 };
pub const POINTER_REGISTER: u5 = 10;
pub const TAG_REGISTER: u5 = 17;
pub fn hasServices(profile: Profile) bool {
    return switch (profile) {
        .rv64im => false,
        .keccak_service_v1, .ethereum_services_v1, .ethereum_services_v2 => true,
    };
}
pub fn decode(profile: Profile, raw: u32) isa.Error!isa.Instruction {
    var result = try isa.Instruction.decode(raw);
    if (hasServices(profile) and result.opcode == .ECALL) {
        result.rs1 = POINTER_REGISTER;
        result.rs2 = TAG_REGISTER;
    }
    return result;
}
pub fn effects(profile: Profile, op: isa.Opcode) isa.Effects {
    if (hasServices(profile) and op == .ECALL) return .{ .reads_rs1 = true, .reads_rs2 = true, .writes_rd = false };
    return isa.effects(op);
}
/// Retiring instruction admission, distinct from recognizing a trapping opcode.
pub fn admitted(profile: Profile, op: isa.Opcode) bool {
    return switch (op) {
        .EBREAK => false,
        .ECALL => hasServices(profile),
        else => true,
    };
}
