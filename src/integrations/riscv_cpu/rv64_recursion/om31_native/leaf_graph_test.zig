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
    var cpu = try G.cpu(a, .{ .setup = fixture.keys.cpus[0], .request = fixture.bundle.requests[0], .expected = inventory.workers[0], .first = inventory.first_ids[0], .manifest = &manifest, .index = 0, .stage = &stages.stages[0], .config = config, .encoded = &fixture.bundle.cpus[0] });
    defer cpu.deinit();
    try std.testing.expectEqual(@as(usize, 9), cpu.ctx.circuit.output.items.len);
    {
        var actual = try @import("outer_wrap.zig").wrapGraph(a, cpu.ctx, cpu.digest);
        defer actual.deinit();
        std.debug.print("OM31_ACTUAL_CPU_WRAP vars={} preprocess_ns={} prove_ns={} verify_ns={}\n", .{ cpu.ctx.circuit.n_vars, actual.timings.preprocess_ns, actual.timings.prove_ns, actual.timings.verify_ns });
    }
    const ordinal = setups.len;
    var truth = try G.truth(a, .{ .truth = truths[0], .expected = inventory.workers[ordinal], .manifest = &manifest, .config = config, .encoded = &fixture.bundle.truths[0] });
    defer truth.deinit();
    try std.testing.expectEqual(@as(usize, 9), truth.ctx.circuit.output.items.len);
}
