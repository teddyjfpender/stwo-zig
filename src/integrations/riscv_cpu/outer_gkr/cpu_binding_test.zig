const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const B = @import("binding_v2.zig");
const C = @import("cpu_binding.zig");
const Legacy = @import("binding.zig");
const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;
const a = std.testing.allocator;
fn word(seed: usize) O {
    var coordinates: [8]M = undefined;
    for (&coordinates, 0..) |*v, i| v.* = M.fromU64(seed * 177 + i * 61 + 17);
    return O.fromM31Array(coordinates);
}
fn targetFor(eq: []const O, projection: []const O) O {
    var sum = O.zero();
    for (eq, projection) |e, p| sum = sum.add(e.mul(p));
    return sum;
}
fn allocationCase(allocator: std.mem.Allocator, point: []const O, projection: []const O, target: O) !void {
    var out = try C.columns(allocator, point, projection, target);
    defer out.deinit(allocator);
}
test "outer GKR CPU joined binding is exact across logical chunks and worker counts" {
    for ([_]u32{ 5, 12, 13, 16 }) |log| {
        var point: [16]O = undefined;
        for (point[0..log], 0..) |*v, i| v.* = word(i + 11);
        const projection = try a.alloc(O, @as(usize, 1) << @intCast(log));
        defer a.free(projection);
        for (projection, 0..) |*v, i| v.* = word(i + 117);
        const eq = try Legacy.eqTable(a, point[0..log]);
        defer a.free(eq);
        const target = targetFor(eq, projection);
        var reference = try B.columns(a, point[0..log], projection, target);
        defer reference.deinit(a);
        for ([_]usize{ 0, 2, 4 }) |workers| {
            var pool: engine.work_pool.WorkPool = undefined;
            var binding: ?engine.work_pool.ScopedPoolBinding = null;
            if (workers != 0) {
                try pool.initInPlaceWithOptions(.{ .worker_count = workers });
                binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
            }
            defer if (binding) |*bound| {
                bound.deinit();
                pool.deinit();
            };
            var actual = try C.columns(a, point[0..log], projection, target);
            defer actual.deinit(a);
            try std.testing.expectEqualSlices(u8, std.mem.sliceAsBytes(reference.eq), std.mem.sliceAsBytes(actual.eq));
            try std.testing.expectEqualSlices(u8, std.mem.sliceAsBytes(reference.prefix), std.mem.sliceAsBytes(actual.prefix));
            try std.testing.expectError(error.OuterGkrTerminalMismatch, C.columns(a, point[0..log], projection, target.add(O.one())));
            projection[projection.len / 2] = projection[projection.len / 2].add(O.one());
            try std.testing.expectError(error.OuterGkrTerminalMismatch, C.columns(a, point[0..log], projection, target));
            projection[projection.len / 2] = projection[projection.len / 2].sub(O.one());
        }
        if (log == 12) {
            try std.testing.checkAllAllocationFailures(a, allocationCase, .{ point[0..log], projection, target });
            const budget = try engine.host_budget_allocator.SharedHostBudget.create(a, 8 << 20);
            defer budget.destroy();
            try allocationCase(budget.allocator(), point[0..log], projection, target);
            try std.testing.expectEqual(@as(usize, 0), budget.snapshot().live_bytes);
            try std.testing.expectError(error.OuterGkrBindingShape, C.columns(a, point[0..log], projection[1..], target));
            try std.testing.expectEqual(@as(usize, 0), budget.snapshot().live_bytes);
        }
    }
}
