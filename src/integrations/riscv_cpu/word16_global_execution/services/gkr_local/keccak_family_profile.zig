//! Additive receiver-owned policy preparation; no production caller selects it.
//! Restores the deferred M7 profile identity and exact legacy no-op framing.
//! Call requireTruthsForTotal with a source-owned total before binding authority.
const std = @import("std");
const core = @import("stwo_core");
const K = @import("stwo_riscv_frontend").rv64_air.crypto.keccak;
pub const Config = core.pcs.PcsConfig;
pub const DOMAIN = "rv64-m7/keccak-early-late/b16-q27-p20-fold4/v1";
pub const Policy = enum {
    legacy,
    m7_keccak_early_late_b16_q27_p20_fold4_v1,

    pub fn parse(text: []const u8) !Policy {
        if (text.len == 0 or std.mem.eql(u8, text, "legacy")) return .legacy;
        if (std.mem.eql(u8, text, @tagName(Policy.m7_keccak_early_late_b16_q27_p20_fold4_v1)))
            return .m7_keccak_early_late_b16_q27_p20_fold4_v1;
        return error.UnknownKeccakFamilyProfile;
    }
    pub fn truthConfig(self: Policy, base: Config, keccak: bool) Config {
        return if (self != .legacy and keccak) config() else base;
    }
    /// Canonical-shape check only. Global closure must independently bind the
    /// total; use requireTruthsForTotal when that source authority is available.
    pub fn requireTruths(self: Policy, truths: anytype) !void {
        if (self == .legacy) return;
        _ = try validateTruths(truths);
    }
    /// An inferred total cannot authenticate a missing suffix. The caller owns
    /// expected_total, derived from the captured execution rather than proof data.
    pub fn requireTruthsForTotal(self: Policy, expected_total: u32, truths: anytype) !void {
        if (self == .legacy) return;
        if (try validateTruths(truths) != expected_total) return error.KeccakFamilyPartition;
    }
    pub fn mixExecution(self: Policy, channel: anytype) void {
        if (self == .legacy) return;
        var digest: [32]u8 = undefined;
        std.crypto.hash.blake2.Blake2s256.hash(DOMAIN, &digest, .{});
        var words: [8]u32 = undefined;
        for (&words, 0..) |*word, i|
            word.* = std.mem.readInt(u32, digest[4 * i ..][0..4], .little);
        channel.mixU32s(&words);
        config().mixInto(channel);
    }
};

fn validateTruths(truths: anytype) !u32 {
    var count: usize = 0;
    var total: u32 = 0;
    var counts: [2]usize = .{ 0, 0 };
    for (truths) |truth| if (truth == .keccak) {
        if (count == counts.len or truth.count() == 0) return error.KeccakFamilyPartition;
        const next = std.math.add(u32, total, 1) catch return error.KeccakFamilyPartition;
        if (truth.first() != next) return error.KeccakFamilyPartition;
        total = std.math.add(u32, total, truth.count()) catch return error.KeccakFamilyPartition;
        counts[count] = truth.count();
        count += 1;
    };
    const spans = split(total);
    if (count != @as(usize, @intFromBool(spans[0] != 0)) + @as(usize, @intFromBool(spans[1] != 0)))
        return error.KeccakFamilyPartition;
    var index: usize = 0;
    for (truths) |truth| if (truth == .keccak) {
        if (truth.count() != spans[index] or truth.keccak.setup.policy != .triple_v2)
            return error.KeccakFamilyPartition;
        const log = try K.layout.logSizeFor(.pair29, truth.count());
        if (log > 21 or truth.keccak.setup.log != log) return error.KeccakFamilyPartition;
        try K.layout.validateGeometryFor(.pair29, truth.count(), truth.first(), log);
        index += 1;
    };
    // Charge actual paired slots across both spans. Two odd spans introduce
    // one more pair than a single merged span; no characteristic wrap allowed.
    _ = try K.layout.admitRoster(&counts, &.{});
    return total;
}

pub fn current() !Policy {
    return .legacy;
}
/// First ceil(total/2) source calls, then the rest; no empty physical proof.
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
test {
    _ = @import("keccak_family_profile_test.zig");
}
