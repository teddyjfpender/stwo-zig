//! Concrete execution ABI identities. This does not alter ordinary RV64IM decode.
const isa = @import("decode.zig");
/// `ethereum_services_v3` = v2 (Keccak-f, LE-word secp ADD/DOUBLE) plus the
/// admitted v3 service tags below. ISA decode and ECALL effects are identical
/// to v2; a tag is admitted only by a matching proof bridge (OWNER19 closure).
/// Extension point: further v3 tags (e.g. bulk memory 0x0003_0001/2) add a
/// constant here, a session dispatch arm, a tape section and a services family.
pub const Profile = enum { rv64im, keccak_service_v1, ethereum_services_v1, ethereum_services_v2, ethereum_services_v3 };
pub const KECCAK_TAG: u64 = 0x00010001;
pub const SECP_ADD_TAG: u64 = 0x00020001;
pub const SECP_DOUBLE_TAG: u64 = 0x00020002;
pub const SECP_ADD_WORD_TAG: u64 = 0x00020011;
pub const SECP_DOUBLE_WORD_TAG: u64 = 0x00020012;
/// One SHA-256 compression; 32-byte aligned 12-u64 packet, state written.
pub const SHA256_COMPRESS_TAG: u64 = 0x00030010;
/// r = (a*b + c) mod m (r = 0 when m = 0); 32-byte aligned 20-u64 packet
/// a, b, c, m, r (four LE limbs each), only r written.
pub const ARITH256_MOD_TAG: u64 = 0x00030021;
/// Admitted bulk memory (ethereum_services_v3): packet dst, src|byte, len
/// (memcpy/memset) or a, b, len, result (memcmp).
pub const MEMCPY_TAG: u64 = 0x00030001;
pub const MEMSET_TAG: u64 = 0x00030002;
pub const MEMCMP_TAG: u64 = 0x00030003;
pub const SecpPacketFormat = enum { big_endian_bytes_v1, little_endian_words_v2 };
pub const POINTER_REGISTER: u5 = 10;
pub const TAG_REGISTER: u5 = 17;
pub fn hasServices(profile: Profile) bool {
    return switch (profile) {
        .rv64im => false,
        .keccak_service_v1, .ethereum_services_v1, .ethereum_services_v2, .ethereum_services_v3 => true,
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
/// Profiles whose secp packets use the LE-word v2 format.
pub fn secpWords(profile: Profile) bool {
    return profile == .ethereum_services_v2 or profile == .ethereum_services_v3;
}
/// Admitted v3-only service tags (the ROM-independent service roster):
/// SHA-256 compression, arith256_mod and bulk memcpy/memset/memcmp.
pub fn admitsV3(profile: Profile, tag: u64) bool {
    return profile == .ethereum_services_v3 and (tag == SHA256_COMPRESS_TAG or tag == ARITH256_MOD_TAG or isBulkTag(tag));
}
pub fn isBulkTag(tag: u64) bool {
    return tag == MEMCPY_TAG or tag == MEMSET_TAG or tag == MEMCMP_TAG;
}
/// Most RAM words one admitted bulk call touches: three packet reads plus a
/// read and a write per word of a 1 MiB copy (bulk_memory.MAX_BYTES), plus
/// the extra source word of an unaligned copy (memcmp: four packet words and
/// two reads per word, one fewer).
pub const BULK_MAX_TOUCHED_WORDS: u64 = 4 + 2 * ((1 << 20) / 8);
