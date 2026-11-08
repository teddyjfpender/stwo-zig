const std = @import("std");
const core = @import("stwo_core");
const P = @import("keccak_family_profile.zig");
const K = @import("stwo_riscv_frontend").rv64_air.crypto.keccak;
const policy = P.Policy.m7_keccak_early_late_b16_q27_p20_fold4_v1;
const Setup = struct { log: u32 = 5, policy: K.equations.BatchPolicy = .triple_v2 };
const Truth = union(enum) {
    keccak: struct { setup: *const Setup, first_id: u32, calls: u32 },
    other,
    pub fn first(self: Truth) u32 {
        return self.keccak.first_id;
    }
    pub fn count(self: Truth) u32 {
        return self.keccak.calls;
    }
};
fn truth(setup: *const Setup, first: u32, calls: u32) Truth {
    return .{ .keccak = .{ .setup = setup, .first_id = first, .calls = calls } };
}

test "Keccak family exact receiver policy, conjectured parameters and legacy framing" {
    try std.testing.expectEqual(P.Policy.legacy, try P.Policy.parse(""));
    try std.testing.expectEqual(policy, try P.Policy.parse(@tagName(policy)));
    for ([_][]const u8{ "b16", "m7_keccak_early_late_b16_q26_p20_fold4_v1", "legacy " }) |name|
        try std.testing.expectError(error.UnknownKeccakFamilyProfile, P.Policy.parse(name));
    const base = @import("../../../word16_execution/om31_security_candidate.zig").configFor(.d2_native_b4_q54_p20_fold4);
    try std.testing.expectEqualDeep(base, policy.truthConfig(base, false));
    try std.testing.expectEqualDeep(base, P.Policy.legacy.truthConfig(base, true));
    const selected = policy.truthConfig(base, true);
    try std.testing.expectEqual(@as(u32, 128), selected.fri_config.log_blowup_factor * @as(u32, @intCast(selected.fri_config.n_queries)) + selected.pow_bits);
    try std.testing.expectEqual(@as(u32, 4), selected.fri_config.fold_step);
    var tampered = selected;
    tampered.fri_config.n_queries -= 1;
    try std.testing.expect(!P.isConfig(tampered));
    var channel = core.channel.raw_mod_m31.Om31Channel.init();
    const before = channel.digestBytes();
    P.Policy.legacy.mixExecution(&channel);
    try std.testing.expectEqual(before, channel.digestBytes());
    policy.mixExecution(&channel);
    try std.testing.expect(!std.mem.eql(u8, &before, &channel.digestBytes()));
}

test "Keccak family source-owned total and canonical spans reject tampering" {
    const setup: Setup = .{};
    try policy.requireTruthsForTotal(0, &[_]Truth{.other});
    try policy.requireTruthsForTotal(1, &[_]Truth{truth(&setup, 1, 1)});
    var truths = [_]Truth{ truth(&setup, 1, 2), .other, truth(&setup, 3, 1) };
    try policy.requireTruthsForTotal(3, &truths);
    try std.testing.expectError(error.KeccakFamilyPartition, policy.requireTruthsForTotal(4, &truths));
    for ([_]u32{ 0, 1, 2, 4, std.math.maxInt(u32) }) |first| {
        truths[2].keccak.first_id = first;
        try std.testing.expectError(error.KeccakFamilyPartition, policy.requireTruthsForTotal(3, &truths));
    }
    truths[2].keccak.first_id = 3;
    truths[2].keccak.calls = 0;
    try std.testing.expectError(error.KeccakFamilyPartition, policy.requireTruthsForTotal(3, &truths));
    try std.testing.expectError(error.KeccakFamilyPartition, policy.requireTruthsForTotal(3, &[_]Truth{ truth(&setup, 1, 1), truth(&setup, 2, 2) }));
    try std.testing.expectError(error.KeccakFamilyPartition, policy.requireTruthsForTotal(3, &[_]Truth{ truth(&setup, 1, 1), truth(&setup, 2, 1), truth(&setup, 3, 1) }));
    try std.testing.expectError(error.KeccakFamilyPartition, policy.requireTruthsForTotal(3, &[_]Truth{ truth(&setup, 3, 1), truth(&setup, 1, 2) }));
    const wrong: Setup = .{ .policy = .throughput_v1 };
    try std.testing.expectError(error.KeccakFamilyPartition, policy.requireTruthsForTotal(1, &[_]Truth{truth(&wrong, 1, 1)}));
    const padded: Setup = .{ .log = 6 };
    try std.testing.expectError(error.KeccakFamilyPartition, policy.requireTruthsForTotal(1, &[_]Truth{truth(&padded, 1, 1)}));
    try std.testing.expectError(error.KeccakFamilyPartition, policy.requireTruthsForTotal(std.math.maxInt(u32), &[_]Truth{ truth(&setup, 1, std.math.maxInt(u32)), truth(&setup, 0, 1) }));
}

test "Keccak family aggregate source mass charges both odd padded spans" {
    // Each 60,000-call span passes its individual characteristic bound;
    // their combined chi mass exceeds p. No allocations or proof fixture.
    const calls: u32 = 60_000;
    const setup: Setup = .{ .log = try K.layout.logSizeFor(.pair29, calls) };
    try std.testing.expectError(error.KeccakLookupMassExceeded, policy.requireTruthsForTotal(2 * calls, &[_]Truth{ truth(&setup, 1, calls), truth(&setup, calls + 1, calls) }));
    const split_mass = try K.layout.admitRoster(&.{ 3, 3 }, &.{});
    const merged_mass = try K.layout.admitRoster(&.{6}, &.{});
    try std.testing.expect(split_mass.chi > merged_mass.chi);
    for ([_]u32{ 0, 1, 2, 20_994, 29_998, 29_999, std.math.maxInt(u32) }) |total| {
        const spans = P.split(total);
        try std.testing.expectEqual(@as(u64, total), @as(u64, spans[0]) + spans[1]);
        try std.testing.expect(spans[0] >= spans[1] and spans[0] - spans[1] <= 1);
    }
}
