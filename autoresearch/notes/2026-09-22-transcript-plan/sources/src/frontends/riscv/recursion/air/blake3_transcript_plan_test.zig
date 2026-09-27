const std = @import("std");
const core = @import("stwo_core");
const plan = @import("blake3_transcript_plan.zig");
const t = @import("blake3_transcript_witness.zig");
const M = core.fields.m31.M31;
test "BLAKE3 transcript plan reuses private preprocessing and binds capacity and roles" {
    const a = std.testing.allocator;
    var ops = [_]t.Operation{
        .{ .routed_integer = .{ .value = @import("blake3_rejection_fixture.zig").SEED, .source = .{ .circuit = 10, .first_wire = 0 } } },
        .{ .secure = .{ .output = .oods, .attempts = 0, .values = @splat(M.zero()) } },
    };
    var key = try plan.Plan.init(a, .{ .namespace = 100, .attempt_capacity = 3 }, &ops);
    defer key.deinit();
    var live = try key.prepare(a, &ops);
    defer live.deinit();
    try std.testing.expectEqual(@as(u64, 2), live.next_draw);
    const id = key.id;
    ops[0].routed_integer.value = 42;
    ops[1].secure.attempts = 999;
    var changed = try key.prepare(a, &ops);
    defer changed.deinit();
    try std.testing.expect(!std.mem.eql(u8, &live.final_digest.?, &changed.final_digest.?));
    var same = try plan.Plan.init(a, key.config, &ops);
    defer same.deinit();
    try std.testing.expectEqualSlices(u8, &id, &same.id);
    ops[1].secure.output = .composition;
    try std.testing.expectError(error.Blake3TranscriptPlanMismatch, key.prepare(a, &ops));
    ops[1].secure.output = .oods;
    const public_ops = [_]t.Operation{ .{ .integer = 42 }, ops[1] };
    try std.testing.expectError(error.Blake3TranscriptPlanMismatch, key.prepare(a, &public_ops));
    var narrow = try plan.Plan.init(a, .{ .namespace = 100, .attempt_capacity = 1 }, &ops);
    defer narrow.deinit();
    try std.testing.expect(!std.mem.eql(u8, &id, &narrow.id));
    ops[0].routed_integer.value = @import("blake3_rejection_fixture.zig").SEED;
    try std.testing.expectError(error.Blake3RetryCapacityExhausted, narrow.prepare(a, &ops));
    key.config.attempt_capacity = 1;
    try std.testing.expectError(error.CorruptBlake3TranscriptPlan, key.prepare(a, &ops));
    key.config.attempt_capacity = 3;
    key.fixed.boundary_rows[0][t.boundary.PHYSICAL_MAIN_COLUMN_COUNT] = M.zero();
    try std.testing.expectError(error.CorruptBlake3TranscriptPlan, key.validate());
    try std.testing.expectError(error.InvalidBlake3Transcript, plan.Plan.init(a, .{ .namespace = 100, .attempt_capacity = 0 }, &ops));
    try std.testing.checkAllAllocationFailures(a, allocationCase, .{});
}
fn allocationCase(a: std.mem.Allocator) !void {
    const ops = [_]t.Operation{.{ .routed_integer = .{ .value = 42, .source = .{ .circuit = 10, .first_wire = 0 } } }};
    var key = try plan.Plan.init(a, .{ .namespace = 100, .attempt_capacity = 1 }, &ops);
    var live = key.prepare(a, &ops) catch |err| {
        key.deinit();
        return err;
    };
    defer live.deinit();
    var fixed = key.intoFixed();
    defer fixed.deinit();
    // Force arena growth after transfer; one owner must free every new block.
    const extra = try fixed.arena.allocator().alloc(u8, 1_000_000);
    @memset(extra, 0);
}
