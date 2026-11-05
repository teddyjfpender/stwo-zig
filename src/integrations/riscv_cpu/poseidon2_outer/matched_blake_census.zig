//! Actual complete all-Blake control on the SAME JUMPDEST five-step workload
//! and native b4/q54/P20 geometry as the pure-P2 AST candidate. This is a native
//! accepted control + valid leaf graph census, not an outer proof or Ethereum.
const std = @import("std");
const Core = @import("stwo_core");
const Engine = @import("stwo_prover_engine");
const Circuit = @import("stwo_circuit_frontend");
const Fixture = @import("../word16_global_execution/services/jumpdest_fixture.zig");
const R = @import("../word16_global_execution/services/roster.zig");
const W = @import("../word16_global_execution/services/gkr_local/worker_protocol.zig");
const Coordinator = @import("../word16_global_execution/services/gkr_local/coordinator.zig");
const Fixed = @import("../word16_global_execution/services/gkr_local/fixed_authority.zig");
const FixedSet = @import("../word16_global_execution/services/gkr_local/fixed_authority_set.zig").Set;
const Inventory = @import("../word16_global_execution/services/gkr_local/execution.zig").Inventory;
const MW = @import("../word16_global_execution/services/gkr_local/manifest_wire.zig");
const G = @import("../rv64_recursion/om31_native/leaf_graph.zig");
const Fingerprint = @import("../rv64_recursion/om31_native/topology_fingerprint.zig");
fn census(a: std.mem.Allocator, ctx: anytype, cfg: Core.pcs.PcsConfig, trace_only: bool) !void {
    const PP = Circuit.common.preprocessed;
    const list = Circuit.common.component_list;
    const sizes = Circuit.common.finalize.computePaddedSizes(PP.CircuitView.fromBuilder(&ctx.circuit));
    const layout = try PP.ColumnLayout.fromComponentSizes(sizes);
    const logs = try list.circuitComponentLogSizes(&layout);
    var main: u64 = 0;
    var inter: u64 = 0;
    var fixed: u64 = 0;
    for (logs.toArray(), list.component_facts.toArray()) |log, f| {
        const rows = @as(u64, 1) << @intCast(log);
        main += rows * f.trace_columns;
        inter += rows * f.interaction_columns * 2;
    }
    for (layout.entries) |entry| fixed += @as(u64, 1) << @intCast(entry.log_size);
    const json = try std.json.Stringify.valueAlloc(a, .{ .status = "M valid_native_allBlake_control_and_full_CPUleaf_graph;not_outerproof_orEthereum", .scope = "sameJUMPDEST5stepCPU0sourcegeometry;existingallBlakephysical_andlocalprotocol", .config = cfg, .trace_only = trace_only, .source_program = Fixture.WORDS, .raw = ctx.gate_counts, .component_logs = logs, .main_cells = main, .fixed_cells = fixed, .interaction_cells = inter, .total_trace_cells = main + fixed + inter, .variables = ctx.circuit.n_vars, .native_verified = true, .graph_numerically_valid = true, .p2_candidate_natively_compatible = false, .security_certified = false }, .{});
    defer a.free(json);
    std.debug.print("MATCHED_BLAKE_CPU_LEAF_CENSUS {s}\n", .{json});
}
test "matched all-Blake complete CPU b4 q54 P20 graph census" {
    const a = std.testing.allocator;
    var pool: Engine.work_pool.WorkPool = .{};
    try pool.initInPlaceWithOptions(.{ .worker_count = 8 });
    defer pool.deinit();
    var bound = try Engine.work_pool.ScopedPoolBinding.init(&pool);
    defer bound.deinit();
    var captured = try Fixture.Captured.init(a);
    defer captured.deinit();
    var setups: [2]R.CpuSetup = undefined;
    var made: usize = 0;
    defer for (setups[0..made]) |*s| s.deinit();
    for (&setups, 0..) |*s, i| {
        s.* = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &Fixture.WORDS }, try captured.native[i].geometry(), Fixture.bridges[i]);
        made += 1;
    }
    const ptrs = [_]*const R.CpuSetup{ &setups[0], &setups[1] };
    var cfg: Core.pcs.PcsConfig = .{ .pow_bits = 20, .fri_config = try Core.fri.FriConfig.init(0, 2, 54) };
    cfg.fri_config.fold_step = 4;
    var cache = try Fixed.Fixed.Cache.init(a, 2 << 30);
    defer cache.deinit();
    var authority = try FixedSet.init(a, &cache, &ptrs, &.{}, cfg);
    defer authority.deinit();
    const expected = Fixture.expectedFor(captured.program.identity);
    var bundle = try Coordinator.produceWithAuthority(a, &ptrs, &.{}, &.{ &captured.native[0], &captured.native[1] }, &captured.advice, expected, cfg, .{ .gkr_budget = 2 << 30, .global_budget = 2 << 30 }, &authority);
    defer bundle.deinit(a);
    const verified = try bundle.verifyWithAuthority(a, &ptrs, &.{}, expected, cfg, &authority);
    try std.testing.expect(verified.completed);
    var inventory = try Inventory.initWithAuthority(a, &ptrs, &.{}, bundle.requests, expected, cfg, &authority);
    defer inventory.deinit();
    var stages = try MW.decode(a, inventory.execution_identity, inventory.workers, bundle.stage_one_bytes);
    defer stages.deinit();
    var pending = try stages.verifyAndSeal(a, inventory.execution_identity, inventory.workers);
    defer pending.deinit(a);
    const input = G.CpuInput{ .setup = ptrs[0], .request = bundle.requests[0], .expected = inventory.workers[0], .first = inventory.first_ids[0], .manifest = &pending, .index = 0, .stage = &stages.stages[0], .config = cfg, .encoded = &bundle.cpus[0], .fixed = &authority.bindings[0] };
    var graph = try G.cpu(a, input);
    defer graph.deinit();
    try census(a, graph.ctx, cfg, false);
    var trace = try G.cpuTraceOnly(a, input);
    defer trace.deinit();
    const fp = Fingerprint.compute(graph.ctx);
    const tp = Fingerprint.compute(trace.ctx);
    try std.testing.expectEqualSlices(u8, &fp.gates, &tp.gates);
    try std.testing.expectEqualSlices(u8, &fp.constants, &tp.constants);
    try census(a, trace.ctx, cfg, true);
}
