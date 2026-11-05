//! Receiver-owned per-family PCS policy. No proof bytes select this policy.
//! The new policy is bound into the execution identity; the legacy policy
//! emits no extra framing and preserves every old worker byte.
const std = @import("std");
const core = @import("stwo_core");
pub const Config = core.pcs.PcsConfig;
pub const ENV = "STWO_RV64_KECCAK_FAMILY_PROFILE";
pub const DOMAIN = "rv64-m7/keccak-early-late/b16-q27-p20-fold4/v1";
pub const Policy = enum {
    legacy,
    m7_keccak_early_late_b16_q27_p20_fold4_v1,
    pub fn parse(text: []const u8) !Policy {
        if (text.len == 0 or std.mem.eql(u8, text, "legacy")) return .legacy;
        if (std.mem.eql(u8, text, @tagName(Policy.m7_keccak_early_late_b16_q27_p20_fold4_v1))) return .m7_keccak_early_late_b16_q27_p20_fold4_v1;
        return error.UnknownKeccakFamilyProfile;
    }
    pub fn truthConfig(self: Policy, base: Config, keccak: bool) Config {
        return if (self != .legacy and keccak) config() else base;
    }
    pub fn requireTruths(self: Policy, truths: anytype) !void {
        if (self == .legacy) return;
        var count: usize = 0;
        var total: u32 = 0;
        for (truths) |truth| if (truth == .keccak) {
            if (truth.first() != total + 1 or truth.count() == 0) return error.KeccakFamilyPartition;
            total = try std.math.add(u32, total, truth.count());
            count += 1;
        };
        const spans = split(total);
        if (count != @as(usize, @intFromBool(spans[0] != 0)) + @as(usize, @intFromBool(spans[1] != 0))) return error.KeccakFamilyPartition;
        var index: usize = 0;
        for (truths) |truth| if (truth == .keccak) {
            if (truth.count() != spans[index] or truth.keccak.setup.policy != .triple_v2) return error.KeccakFamilyPartition;
            const K = @import("stwo_riscv_frontend").rv64_air.crypto.keccak.layout;
            if (truth.keccak.setup.log != try K.logSizeFor(truth.keccak.setup.policy.geometry(), truth.count())) return error.KeccakFamilyPartition;
            index += 1;
        };
    }
    pub fn mixExecution(self: Policy, channel: anytype) void {
        if (self == .legacy) return;
        var digest: [32]u8 = undefined;
        std.crypto.hash.blake2.Blake2s256.hash(DOMAIN, &digest, .{});
        var words: [8]u32 = undefined;
        for (&words, 0..) |*word, i| word.* = std.mem.readInt(u32, digest[4 * i ..][0..4], .little);
        channel.mixU32s(&words);
        config().mixInto(channel);
    }
};
pub fn current() !Policy {
    var buffer: [96]u8 = undefined;
    const text = std.posix.getenv(ENV) orelse return .legacy;
    if (text.len > buffer.len) return error.UnknownKeccakFamilyProfile;
    @memcpy(buffer[0..text.len], text);
    return Policy.parse(buffer[0..text.len]);
}
/// Stable source-owned split: the first ceil(total/2) calls, then the rest.
/// No zero-call physical proof is emitted for an absent/single-call family.
pub fn split(total: u32) [2]u32 {
    const early = total / 2 + total % 2;
    return .{ early, total - early };
}
pub fn config() Config {
    var fri = core.fri.FriConfig.init(0, 4, 27) catch unreachable;
    fri.fold_step = 4;
    return .{ .pow_bits = 20, .fri_config = fri };
}
pub fn isConfig(value: Config) bool {
    return std.meta.eql(value, config());
}
test "Keccak family profile pins exact config and preserves non Keccak" {
    const policy = try Policy.parse("m7_keccak_early_late_b16_q27_p20_fold4_v1");
    const Candidate = @import("../../../word16_execution/om31_security_candidate.zig");
    const base = Candidate.configFor(.d2_native_b4_q54_p20_fold4);
    try (try Candidate.ledgerAtBlowup(Candidate.Facts.caps(), 4)).requireRawModuloBits(151);
    try std.testing.expectEqual(base, policy.truthConfig(base, false));
    const selected = policy.truthConfig(base, true);
    try std.testing.expectEqual(@as(u32, 128), 4 * @as(u32, @intCast(selected.fri_config.n_queries)) + selected.pow_bits);
    try std.testing.expectEqual(@as(u32, 4), selected.fri_config.fold_step);
    try std.testing.expectEqual(base, Policy.legacy.truthConfig(base, true));
    var changed = selected;
    changed.fri_config.n_queries -= 1;
    try std.testing.expect(!isConfig(changed));
    try std.testing.expectError(error.UnknownKeccakFamilyProfile, Policy.parse("b16"));
    const Ch = core.channel.raw_mod_m31.Om31Channel;
    var old = Ch.init();
    const before = old.digestBytes();
    Policy.legacy.mixExecution(&old);
    try std.testing.expectEqual(before, old.digestBytes());
    policy.mixExecution(&old);
    try std.testing.expect(!std.mem.eql(u8, &before, &old.digestBytes()));
}

test "Keccak family source admission rejects repartition holes and wrong policy" {
    // Use the actual source setup type for the geometry/policy authority.
    const Real = @import("../../keccak/shared/roster.zig").TruthSetup;
    const R = @import("../roster.zig");
    const a = std.testing.allocator;
    var setup = try Real.initPolicy(a, 5, @import("../../keccak/shared/key.zig").Key.Suite.production(), .triple_v2);
    defer setup.deinit();
    var truths = [_]R.Truth{
        .{ .keccak = .{ .setup = &setup, .first_id = 1, .calls = 1 } },
        .{ .keccak = .{ .setup = &setup, .first_id = 2, .calls = 1 } },
    };
    const policy = Policy.m7_keccak_early_late_b16_q27_p20_fold4_v1;
    try policy.requireTruths(&truths);
    truths[1].keccak.first_id = 3;
    try std.testing.expectError(error.KeccakFamilyPartition, policy.requireTruths(&truths));
    truths[1].keccak.first_id = 2;
    truths[0].keccak.calls = 2;
    truths[1].keccak.calls = 0;
    try std.testing.expectError(error.KeccakFamilyPartition, policy.requireTruths(&truths));
}
