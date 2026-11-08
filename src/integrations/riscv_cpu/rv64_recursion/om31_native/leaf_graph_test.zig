const std = @import("std");
const G = @import("leaf_graph.zig");
const Fixture = @import("../../word16_global_execution/services/gkr_local/coordinator_fixture.zig");
const Execution = @import("../../word16_global_execution/services/gkr_local/execution.zig");
const MW = @import("../../word16_global_execution/services/gkr_local/manifest_wire.zig");
const F = @import("../../word16_global_execution/services/fixture.zig");
const a = std.testing.allocator;
test "OM31 native PCS concrete leaf orchestration admits actual CPU and truth frames" {
    const engine = @import("stwo_prover_engine");
    var pool: engine.work_pool.WorkPool = .{};
    try pool.initInPlaceWithOptions(.{ .worker_count = 8 });
    defer pool.deinit();
    var pool_binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer pool_binding.deinit();
    var fixture = try Fixture.Case.init(a);
    defer fixture.deinit();
    const config = try Fixture.config();
    const setups = fixture.keys.pointers();
    const truths = fixture.keys.truths();
    var inventory = try Execution.Inventory.init(a, &setups, &truths, fixture.bundle.requests, F.expectedFor(fixture.keys.cpus[0].materials.program.identity), config);
    defer inventory.deinit();
    var stages = try MW.decode(a, inventory.execution_identity, inventory.workers, fixture.bundle.stage_one_bytes);
    defer stages.deinit();
    var manifest = try stages.verifyAndSeal(a, inventory.execution_identity, inventory.workers);
    defer manifest.deinit(a);
    const cpu_input = G.CpuInput{ .setup = fixture.keys.cpus[0], .request = fixture.bundle.requests[0], .expected = inventory.workers[0], .first = inventory.first_ids[0], .manifest = &manifest, .index = 0, .stage = &stages.stages[0], .config = config, .encoded = &fixture.bundle.cpus[0] };
    var cpu = try G.cpu(a, cpu_input);
    defer cpu.deinit();
    try std.testing.expectEqual(@as(usize, 9), cpu.ctx.circuit.output.items.len);
    {
        var trace = try G.cpuTraceOnly(a, cpu_input);
        defer trace.deinit();
        try traceParity(cpu.ctx, trace.ctx);
    }
    {
        var actual = try @import("outer_wrap.zig").wrapGraph(a, cpu.ctx, cpu.digest);
        defer actual.deinit();
        std.debug.print("OM31_ACTUAL_CPU_WRAP vars={} preprocess_ns={} prove_ns={} verify_ns={}\n", .{ cpu.ctx.circuit.n_vars, actual.timings.preprocess_ns, actual.timings.prove_ns, actual.timings.verify_ns });
        const bytes = try actual.serialize(a);
        defer a.free(bytes);
        var receiver_graph = try G.cpuTraceOnly(a, cpu_input);
        defer receiver_graph.deinit();
        var restored = try @import("outer_wrap.zig").wrapGraphOrLoad(a, receiver_graph.ctx, receiver_graph.digest, bytes);
        defer restored.deinit();
        try std.testing.expect(restored.restored);
        try std.testing.expectEqual(@as(u64, 0), restored.timings.prove_ns);
        try std.testing.expectEqual(@as(usize, 0), receiver_graph.ctx.value_table.capacity);
        try std.testing.expectEqual(actual.authority.identity, restored.authority.identity);
        const restored_bytes = try restored.serialize(a);
        defer a.free(restored_bytes);
        try std.testing.expectEqualSlices(u8, bytes, restored_bytes);
    }
    const ordinal = setups.len;
    const truth_input = G.TruthInput{ .truth = truths[0], .expected = inventory.workers[ordinal], .manifest = &manifest, .config = config, .encoded = &fixture.bundle.truths[0] };
    var truth = try G.truth(a, truth_input);
    defer truth.deinit();
    try std.testing.expectEqual(@as(usize, 9), truth.ctx.circuit.output.items.len);
    var trace = try G.truthTraceOnly(a, truth_input);
    defer trace.deinit();
    try traceParity(truth.ctx, trace.ctx);
}

fn traceParity(original: *const @import("common.zig").Context, trace: *const @import("common.zig").Context) !void {
    const schedule = @import("stwo_circuit_frontend").builder.witness_plan;
    try std.testing.expectEqualDeep(original.circuit, trace.circuit);
    try std.testing.expectEqual(@as(usize, 0), trace.value_table.items.len);
    try std.testing.expectEqual(@as(usize, 0), trace.value_table.capacity);
    var plan = try schedule.build(a, trace);
    defer plan.deinit();
    var reference = try schedule.buildDfsReference(a, trace);
    defer reference.deinit();
    try std.testing.expectEqualDeep(reference.tasks, plan.tasks);
    try std.testing.expectEqualDeep(reference.seeds, plan.seeds);
    try std.testing.expectEqualSlices(usize, reference.level_ends, plan.level_ends);
    const values = try schedule.evaluate(a, trace, plan);
    defer a.free(values);
    try std.testing.expectEqualDeep(original.values(), values);
}
