//! Exact original provider framing/public tuple/ownership checks. No PCS or
//! proof is executed; independent admissions are not fabricated by fixtures.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const Plan = @import("block_v5_readonly_input_plan_v1.zig");
const Table = @import("block_v5_readonly_input_provider_v2.zig");
const Provider = @import("block_v5_readonly_input_provider_proof_v2.zig");
const Global = @import("block_v5_readonly_input_global_protocol_v2.zig");
const Air = @import("block_v5_readonly_input_provider_component_v2.zig");
const Statement = @import("../recursion/air/block_v5_readonly_provider_statement_v2.zig");
const Bus = @import("../recursion/block_v5_readonly_provider_recursive_public_bus_v2.zig");
const intervals = [_]Plan.Interval{ .{ .lower = 0, .upper = 1, .readonly = false, .value = 0 }, .{ .lower = 1, .upper = 2, .readonly = true, .value = 0xffffffff }, .{ .lower = 2, .upper = Plan.WORD_LIMIT, .readonly = false, .value = 0 } };
fn pin() !Provider.Pin {
    const shape = try Table.shard(0, 11, 0, &intervals, &.{ .{ .interval_index = 0, .count = 65535 }, .{ .interval_index = 0, .count = 1 }, .{ .interval_index = 1, .count = 3 } });
    return .{ .shape = shape, .roots = .{ @splat(3), @splat(5) }, .ordinal_digest = try Table.ordinalDigest(shape, @splat(1), &.{ 0, 0, 1 }), .plan_digest = @splat(1), .config = .{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) }, .range_index = 2 };
}
fn claims(proposed: Provider.Pin) Air.Claim {
    return .{ .classification_sum = Q.fromBase(M.fromCanonical(17)), .read_sum = Q.fromBase(M.fromCanonical(19)), .range_sums = @splat(Q.fromBase(M.fromCanonical(23))), .counts = proposed.shape.counts };
}
fn framing(a: std.mem.Allocator) !void {
    const proposed = try pin();
    const claim = claims(proposed);
    const epoch = Global.Epoch{ .plan_digest = proposed.plan_digest, .roster_digest = @splat(7) };
    var frame = try Statement.record(a, proposed, @splat(11), epoch, claim);
    defer frame.deinit();
    var replay = core.proof_suites.Blake3.Channel{};
    try frame.replay(&replay, frame.first);
    if (!std.meta.eql(replay, Provider.firstChannel(proposed))) return error.ReadonlyProviderRecursiveFrameMismatch;
    replay = .{};
    var direct = replay;
    try frame.replay(&replay, frame.claims[0..4]);
    Global.mixSuffix(&direct, epoch.plan_digest, epoch.roster_digest);
    const rd = try replay.drawSecureFelts(a, 4);
    defer a.free(rd);
    const dd = try direct.drawSecureFelts(a, 4);
    defer a.free(dd);
    if (!std.meta.eql(rd, dd) or !std.meta.eql(replay, direct)) return error.ReadonlyProviderRecursiveFrameMismatch;
    try frame.replay(&replay, frame.claims[4..]);
    try Provider.mixPcsSuffix(&direct, proposed, claim);
    if (!std.meta.eql(replay, direct)) return error.ReadonlyProviderRecursiveFrameMismatch;
    for (0..2) |i| if (!std.meta.eql(try frame.digest(frame.roots_offset[i]), proposed.roots[i])) return error.ReadonlyProviderRecursiveFrameMismatch;
    var copy = try frame.clone(a);
    defer copy.deinit();
    if (!std.meta.eql(copy.words, frame.words) or !std.meta.eql(copy.claims, frame.claims)) return error.ReadonlyProviderRecursiveFrameMismatch;
}
test "readonly provider recursive v2: original first shared suffix eleven claims three integer frames and every owner fault" {
    try framing(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, framing, .{});
}
test "readonly provider recursive v2: exact claim census canonicality roots and public LE16 group coordinates" {
    const a = std.testing.allocator;
    const proposed = try pin();
    const claim = claims(proposed);
    var frame = try Statement.record(a, proposed, @splat(11), .{ .plan_digest = @splat(1), .roster_digest = @splat(7) }, claim);
    defer frame.deinit();
    var invalid = claim;
    invalid.counts.range_requests -= 1;
    try std.testing.expectError(error.InvalidReadonlyProviderClaim, Statement.record(a, proposed, @splat(11), .{ .plan_digest = @splat(1), .roster_digest = @splat(7) }, invalid));
    invalid = claim;
    invalid.classification_sum = Q.fromM31Array(.{ .{ .v = core.fields.m31.Modulus }, M.zero(), M.zero(), M.zero() });
    try std.testing.expectError(error.InvalidReadonlyProviderClaim, Statement.record(a, proposed, @splat(11), .{ .plan_digest = @splat(1), .roster_digest = @splat(7) }, invalid));
    var values = Bus.Values{ .allocator = a, .template = @splat(13), .statement = try frame.clone(a), .public = try a.alloc(Q, 20), .roots_count = 2 };
    defer values.deinit();
    values.public[0..11].* = .{ claim.classification_sum, claim.read_sum } ++ claim.range_sums;
    for ([_]u64{ claim.counts.events, claim.counts.readonly }, 0..) |count, which| for (0..4) |limb| {
        values.public[11 + 4 * which + limb] = Q.fromBase(M.fromCanonical(@intCast((count >> @as(u6, @intCast(16 * limb))) & 65535)));
    };
    values.public[19] = Q.fromBase(M.fromCanonical(proposed.shape.group_id));
    try values.validate();
    try std.testing.expectEqualDeep(Q.fromBase(M.fromCanonical(3)).toM31Array(), try values.at(.public_input, 11));
    try std.testing.expectEqualDeep(Q.one().toM31Array(), try values.at(.public_input, 12));
    try std.testing.expectEqualDeep(Q.fromBase(M.fromCanonical(11)).toM31Array(), try values.at(.public_input, 19));
    try std.testing.expectError(error.InvalidFusedRecursivePublicSchedule, values.at(.public_input, 20));
    var clone = try values.clone(a);
    defer clone.deinit();
    values.statement.words[values.statement.roots_offset[1]] ^= 1;
    try std.testing.expect(!std.meta.eql(try values.at(.first_root, 8), try clone.at(.first_root, 8)));
}
