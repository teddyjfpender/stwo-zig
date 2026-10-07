//! Canonical native proof envelope for the single-header circuit+SHA profile.
//! The proof body is one postcard STARK proof; this module only encodes and
//! rejects malformed/replayed headers before the native AIR verifier runs.
const std = @import("std");
const core = @import("stwo_core");
const profile_mod = @import("../config/sha_joint_profile.zig");

const QM31 = core.fields.qm31.QM31;
pub const magic = "S31NAT6S";
pub const key_digest_len: usize = 32;
pub const header_len: usize = magic.len + key_digest_len + 8 + profile_mod.claimed_sum_count * 16;
pub const max_proof_bytes: usize = 64 << 20;

pub const Decoded = struct {
    nonce: u64,
    claimed_sums: [profile_mod.claimed_sum_count]QM31,
    proof_bytes: []const u8,
};

pub fn encodeHeader(
    profile: profile_mod.Profile,
    preprocessed_root: [32]u8,
    nonce: u64,
    claimed_sums: [profile_mod.claimed_sum_count]QM31,
) ![header_len]u8 {
    const digest = try profile.keyDigest(preprocessed_root);
    var bytes: [header_len]u8 = undefined;
    @memcpy(bytes[0..magic.len], magic);
    @memcpy(bytes[magic.len..][0..key_digest_len], &digest);
    std.mem.writeInt(u64, bytes[magic.len + key_digest_len ..][0..8], nonce, .little);
    var at: usize = magic.len + key_digest_len + 8;
    for (claimed_sums) |sum| for (sum.toM31Array()) |limb| {
        std.mem.writeInt(u32, bytes[at..][0..4], limb.toU32(), .little);
        at += 4;
    };
    std.debug.assert(at == header_len);
    return bytes;
}

pub fn decodeHeader(raw: []const u8, profile: profile_mod.Profile, preprocessed_root: [32]u8) !Decoded {
    if (raw.len <= header_len or raw.len > max_proof_bytes or !std.mem.eql(u8, raw[0..@min(raw.len, magic.len)], magic))
        return error.InvalidShaJointProofEnvelope;
    const expected = try profile.keyDigest(preprocessed_root);
    if (!std.mem.eql(u8, raw[magic.len..][0..key_digest_len], &expected))
        return error.WrongShaJointVerificationKey;
    const nonce = std.mem.readInt(u64, raw[magic.len + key_digest_len ..][0..8], .little);
    var claimed_sums: [profile_mod.claimed_sum_count]QM31 = undefined;
    var at: usize = magic.len + key_digest_len + 8;
    for (&claimed_sums) |*sum| {
        var limbs: [4]u32 = undefined;
        for (&limbs) |*limb| {
            limb.* = std.mem.readInt(u32, raw[at..][0..4], .little);
            if (limb.* >= core.fields.m31.Modulus) return error.NonCanonicalShaJointClaim;
            at += 4;
        }
        sum.* = QM31.fromU32Unchecked(limbs[0], limbs[1], limbs[2], limbs[3]);
    }
    std.debug.assert(at == header_len);
    return .{ .nonce = nonce, .claimed_sums = claimed_sums, .proof_bytes = raw[header_len..] };
}

test "joint SHA native envelope is canonical and key separated" {
    var addresses: [profile_mod.gate_address_count]u32 = undefined;
    for (&addresses, 0..) |*address, i| address.* = @intCast(i + 3);
    const fri = try core.pcs.config_v2.FriConfigV2.init(26, 0, 1, 70, 1);
    const pcs = core.pcs.config_v2.PcsConfigV2.fromFriAndTraceSize(fri, 18);
    const profile = try profile_mod.Profile.canonical(@splat(7), .{ 8, 9, 8, 16 }, 100, addresses, pcs);
    const root: [32]u8 = @splat(11);
    const claims: [profile_mod.claimed_sum_count]QM31 = @splat(QM31.one());
    const header = try encodeHeader(profile, root, 1234, claims);
    const raw = header ++ [_]u8{0xff}; // proof body placeholder, never accepted as a STARK
    const decoded = try decodeHeader(&raw, profile, root);
    try std.testing.expectEqual(@as(u64, 1234), decoded.nonce);
    try std.testing.expectEqualDeep(claims, decoded.claimed_sums);
    try std.testing.expectEqualSlices(u8, &.{0xff}, decoded.proof_bytes);
    try std.testing.expectError(error.WrongShaJointVerificationKey, decodeHeader(&raw, profile, @splat(12)));
    try std.testing.expectError(error.InvalidShaJointProofEnvelope, decodeHeader(&header, profile, root));
    var changed = raw;
    changed[0] ^= 1;
    try std.testing.expectError(error.InvalidShaJointProofEnvelope, decodeHeader(&changed, profile, root));
    changed = raw;
    std.mem.writeInt(u32, changed[magic.len + key_digest_len + 8 ..][0..4], core.fields.m31.Modulus, .little);
    try std.testing.expectError(error.NonCanonicalShaJointClaim, decodeHeader(&changed, profile, root));
    changed = raw;
    changed[magic.len] ^= 1;
    try std.testing.expectError(error.WrongShaJointVerificationKey, decodeHeader(&changed, profile, root));
    addresses[0] = 99;
    const other = try profile_mod.Profile.canonical(@splat(7), .{ 8, 9, 8, 16 }, 100, addresses, pcs);
    try std.testing.expectError(error.WrongShaJointVerificationKey, decodeHeader(&raw, other, root));
}
