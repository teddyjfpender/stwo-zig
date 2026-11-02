const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const O = core.fields.om31.OM31;
const Frame = @import("frame.zig");
const Inputs = @import("inputs.zig");
const Source = @import("source_inputs.zig");
const Ch = @import("challenges.zig").For(O);
const Child = @import("child.zig");
const a = std.testing.allocator;
const Metadata = struct {
    pub fn emit(_: @This(), instance: Frame.Instance, logical: usize, sink: *Inputs.RowSink) !void {
        for (0..instance.terms) |i| sink.emitBase(.range16, [1]M{M.fromCanonical(@intCast(257 * logical + i))}, if (instance.origin.core == .alu) M.one() else M.one().neg());
    }
};
test "streamed metadata ranges match original physical inputs across row and padded lane boundaries" {
    var channel = core.channel.raw_mod_m31.Om31Channel.init();
    const ch = Ch.draw(&channel);
    for ([_]u32{ 1, 3, 7, 15, 31, 65, 127, 128 }) |terms| {
        const subset = [_]Frame.Instance{.{ .origin = .{ .core = .alu }, .row_log = 5, .terms = terms, .fixed_offset = 0, .main_offset = 0 }};
        var original = try Inputs.Inputs.init(a, &subset, &ch, Metadata{});
        defer original.deinit();
        var batch = try Source.Batch(Metadata).init(a, &subset, &ch, Metadata{});
        defer batch.deinit();
        const n = original.layers[0].LogUpMultiplicities.numerators.evals;
        const d = original.layers[0].LogUpMultiplicities.denominators.evals;
        var ns: [64]M = undefined;
        var ds: [64]O = undefined;
        for ([_]usize{ 0, 1, (@as(usize, 1) << @intCast(try subset[0].laneLog())) - 1, n.len - @min(n.len, 64) }) |first| {
            const len = @min(@as(usize, 64), n.len - first);
            try batch.sources[0].read(first, ns[0..len], ds[0..len]);
            try std.testing.expectEqualDeep(n[first..][0..len], ns[0..len]);
            try std.testing.expectEqualDeep(d[first..][0..len], ds[0..len]);
        }
    }
}
const instances = [_]Frame.Instance{
    .{ .origin = .{ .core = .alu }, .row_log = 5, .terms = 3, .fixed_offset = 0, .main_offset = 0 },
    .{ .origin = .{ .core = .range16 }, .row_log = 5, .terms = 3, .fixed_offset = 2, .main_offset = 47 },
};
const scope = @import("receipt.zig").Scope{ .statement = @splat(1), .fixed = @splat(2), .main = @splat(3), .ordinal = 0 };
fn streamedLifecycle(allocator: std.mem.Allocator) !void {
    inline for ([_]bool{ false, true }) |cp| {
        const child = try Child.Unbound.proveTimedWithPolicy(allocator, 4 << 20, scope, &instances, Metadata{}, .{ .checkpointed = cp, .tight_admission = true, .stream_bottom = true }, null);
        defer child.deinit();
        var pending = try Child.verifyPending(allocator, scope, &instances, &child.result.proof, child.digest);
        defer pending.deinit(allocator);
    }
}
test "streamed metadata child is byte equal with physical terminal binding and cleans every OOM" {
    const before = try Child.Unbound.proveTimedWithPolicy(a, 4 << 20, scope, &instances, Metadata{}, .{ .checkpointed = true, .tight_admission = true }, null);
    defer before.deinit();
    inline for ([_]bool{ false, true }) |cp| {
        const after = try Child.Unbound.proveTimedWithPolicy(a, 4 << 20, scope, &instances, Metadata{}, .{ .checkpointed = cp, .tight_admission = true, .stream_bottom = true }, null);
        defer after.deinit();
        try std.testing.expectEqualDeep(before.result.proof, after.result.proof);
        try std.testing.expectEqualDeep(before.result.artifact, after.result.artifact);
        try std.testing.expectEqualDeep(before.binding.columns, after.binding.columns);
        try std.testing.expectEqualDeep(before.digest, after.digest);
        var pending = try Child.verifyPending(a, scope, &instances, &after.result.proof, after.digest);
        defer pending.deinit(a);
    }
    try std.testing.checkAllAllocationFailures(a, streamedLifecycle, .{});
}
test "streamed metadata selection defaults off rejects malformed policy and independently selects dense or checkpoint upper storage" {
    try std.testing.expect(!try Child.parseStreamBottom(null, true));
    try std.testing.expect(!try Child.parseStreamBottom("0", false));
    try std.testing.expect(try Child.parseStreamBottom("1", true));
    try std.testing.expect(try Child.parseStreamBottom("1", false));
    try std.testing.expectError(error.InvalidGkrStreamBottomPolicy, Child.parseStreamBottom("2", true));
    try std.testing.expectError(error.InvalidGkrStreamBottomPolicy, Child.parseStreamBottom("yes", true));
    try std.testing.expectError(error.InvalidGkrStreamBottomPolicy, Child.Unbound.proveTimedWithPolicy(a, 0, scope, &instances, Metadata{}, .{ .stream_bottom = true }, null));
}
