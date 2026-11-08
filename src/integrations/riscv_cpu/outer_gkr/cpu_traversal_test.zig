const std = @import("std");
const engine = @import("stwo_prover_engine");
const P = @import("profile.zig");
const S = @import("section.zig");
const a = std.testing.allocator;
fn inputsHash(inputs: *const S.Inputs) [32]u8 {
    var h = std.crypto.hash.blake2.Blake2s256.init(.{});
    for (inputs.numerators, inputs.denominators) |n, d| {
        h.update(std.mem.sliceAsBytes(n));
        h.update(std.mem.sliceAsBytes(d));
    }
    var out: [32]u8 = undefined;
    h.final(&out);
    return out;
}
fn lifecycle(allocator: std.mem.Allocator, class: *const P.Class, inputs: *const S.Inputs) !void {
    const channel = S.benchChannel();
    var section = try S.proveCpu(allocator, &channel, class, inputs);
    defer section.deinit(allocator);
}
test "outer GKR packed scoped traversal preserves reference section and immutable facts" {
    var class = P.TEST_SMALL.withBindingV2();
    var instances: [P.MAX_INSTANCES]P.Instance = undefined;
    @memcpy(instances[0..class.instances.len], class.instances);
    class.instances = instances[0..class.instances.len];
    for (&class.row_logs) |*log| log.* += 4;
    for (instances[0..class.instances.len]) |*instance| instance.row_log += 4;
    var inputs = try S.synthetic(a, &class, 0x1234, true);
    defer inputs.deinit(a);
    // Real gate callers contain whole lane groups with unit weights. Keep
    // other groups genuinely weighted and compare the complete section.
    @memset(inputs.numerators[0], @import("stwo_core").fields.m31.M31.one());
    @memset(inputs.numerators[2], @import("stwo_core").fields.m31.M31.one());
    const before = inputsHash(&inputs);
    const channel = S.benchChannel();
    var reference = try S.proveCpuReferenceForTesting(a, &channel, &class, &inputs);
    defer reference.deinit(a);
    const words = try S.encode(a, &reference);
    defer a.free(words);
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
        var stats: S.CpuStats = .{};
        var actual = try S.proveCpuWithStats(a, &channel, &class, &inputs, &stats);
        defer actual.deinit(a);
        try std.testing.expect(stats.unit_instances >= 2);
        try std.testing.expect(stats.unit_facts >= inputs.numerators[0].len + inputs.numerators[2].len);
        const actual_words = try S.encode(a, &actual);
        defer a.free(actual_words);
        try std.testing.expectEqualSlices(u32, words, actual_words);
        try std.testing.expectEqual(before, inputsHash(&inputs));
        var ch_ref = channel;
        var v_ref = try S.verify(a, &ch_ref, &reference);
        defer v_ref.deinit(a);
        var ch_actual = channel;
        var v_actual = try S.verify(a, &ch_actual, &actual);
        defer v_actual.deinit(a);
        try std.testing.expectEqualSlices(u8, &ch_ref.inner.digest, &ch_actual.inner.digest);
        var late_channel = S.StrictChannel{ .inner = ch_actual };
        const late = @import("binding.zig").drawChallenges(&late_channel, class.instances.len);
        for (std.enums.values(P.Component)) |kind| {
            if (!P.gkrBound(kind)) continue;
            const scalar = try @import("binding_v2.zig").projectFromInputs(a, &class, kind, v_actual.artifact.ood_point, &inputs, &late);
            defer a.free(scalar);
            const projected = try @import("cpu_projection.zig").project(a, &class, kind, v_actual.artifact.ood_point, &inputs, &late);
            defer a.free(projected);
            try std.testing.expectEqualSlices(u8, std.mem.sliceAsBytes(scalar), std.mem.sliceAsBytes(projected));
        }
    }
    // One changed weight must take the weighted route, rather than reusing a
    // family-based or stale unit classification on the next request.
    inputs.numerators[0][inputs.numerators[0].len - 1] = @import("stwo_core").fields.m31.M31.zero();
    var changed_reference = try S.proveCpuReferenceForTesting(a, &channel, &class, &inputs);
    defer changed_reference.deinit(a);
    var changed = try S.proveCpu(a, &channel, &class, &inputs);
    defer changed.deinit(a);
    const changed_words = try S.encode(a, &changed_reference);
    defer a.free(changed_words);
    const changed_actual = try S.encode(a, &changed);
    defer a.free(changed_actual);
    try std.testing.expectEqualSlices(u32, changed_words, changed_actual);
    const small = P.TEST_SMALL.withBindingV2();
    var tiny = try S.synthetic(a, &small, 31, true);
    defer tiny.deinit(a);
    try std.testing.checkAllAllocationFailures(a, lifecycle, .{ &small, &tiny });
    const budget = try engine.host_budget_allocator.SharedHostBudget.create(a, 16 << 20);
    defer budget.destroy();
    try lifecycle(budget.allocator(), &small, &tiny);
    try std.testing.expectEqual(@as(usize, 0), budget.snapshot().live_bytes);
}
