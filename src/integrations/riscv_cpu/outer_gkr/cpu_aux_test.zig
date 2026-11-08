const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Aux = @import("../word16_global_execution/services/gkr_local/public_aux.zig");
const MP = @import("../logup_gkr/mle_point.zig");
const C = @import("cpu_aux.zig");
const O = core.fields.om31.OM31;
const Poly = engine.poly.circle.CircleCoefficients;
const a = std.testing.allocator;
fn allocationCase(allocator: std.mem.Allocator, polys: *const [Aux.COLUMNS]Poly) !void {
    const values = try C.evaluate(allocator, polys, polys[0].log_size);
    defer for (values) |column| allocator.free(column.values);
}
test "outer GKR batched auxiliary extension matches independent per-column FFTs" {
    var channel = core.channel.raw_mod_m31.Om31Channel.init();
    for ([_]u32{ 4, 12, 16 }) |log| {
        var point: [16]O = undefined;
        for (point[0..log]) |*z| z.* = channel.drawSecureFelt();
        const checked = try MP.MleEvalPointFor(O).init(point[0..log]);
        var polys = try Aux.init(a, &checked, log, null);
        defer for (&polys) |*poly| poly.deinit(a);
        const domain = core.poly.circle.canonic.CanonicCoset.new(log + 1).circleDomain();
        var expected: [Aux.COLUMNS]engine.poly.circle.CircleEvaluation = undefined;
        var made: usize = 0;
        defer for (expected[0..made]) |column| a.free(column.values);
        for (polys, &expected) |poly, *column| {
            column.* = try poly.evaluate(a, domain);
            made += 1;
        }
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
            const actual = try C.evaluate(a, &polys, log);
            defer for (actual) |column| a.free(column.values);
            for (actual, expected) |got, want| try std.testing.expectEqualSlices(core.fields.m31.M31, want.values, got.values);
        }
        if (log == 4) {
            try std.testing.checkAllAllocationFailures(a, allocationCase, .{&polys});
            const budget = try engine.host_budget_allocator.SharedHostBudget.create(a, 1 << 20);
            defer budget.destroy();
            try allocationCase(budget.allocator(), &polys);
            try std.testing.expectEqual(@as(usize, 0), budget.snapshot().live_bytes);
            try std.testing.expectError(error.InvalidHybridAuxGeometry, C.evaluate(budget.allocator(), &polys, log + 1));
        }
    }
}
