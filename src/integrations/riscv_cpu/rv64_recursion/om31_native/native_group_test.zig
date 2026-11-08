const std = @import("std");
const Group = @import("native_group.zig");
const G = @import("leaf_graph.zig");
const Fixture = @import("../../word16_global_execution/services/gkr_local/coordinator_fixture.zig");
const Execution = @import("../../word16_global_execution/services/gkr_local/execution.zig");
const MW = @import("../../word16_global_execution/services/gkr_local/manifest_wire.zig");
const F = @import("../../word16_global_execution/services/fixture.zig");
const a = std.testing.allocator;
test "native verifier group authenticates adjacent CPU and truth members in one graph" {
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
    var members: [5]Group.Member = undefined;
    for (setups, 0..) |setup, i| members[i] = .{ .cpu = G.CpuInput{ .setup = setup, .request = fixture.bundle.requests[i], .expected = inventory.workers[i], .first = inventory.first_ids[i], .manifest = &manifest, .index = i, .stage = &stages.stages[i], .config = config, .encoded = &fixture.bundle.cpus[i] } };
    for (truths, 0..) |truth, i| members[setups.len + i] = .{ .truth = G.TruthInput{ .truth = truth, .expected = inventory.workers[setups.len + i], .manifest = &manifest, .config = config, .encoded = &fixture.bundle.truths[i] } };
    try std.testing.expectError(error.NativeGroupRange, Group.build(a, &.{}, .{ .first = 0, .total = 5 }, false));
    try std.testing.expectError(error.NativeGroupRange, Group.build(a, &members, .{ .first = 0, .total = 5 }, false));
    const swapped = [_]Group.Member{ members[1], members[0] };
    try std.testing.expectError(error.NativeGroupOrder, Group.build(a, &swapped, .{ .first = 0, .total = 5 }, false));
    const duplicate = [_]Group.Member{ members[0], members[0] };
    try std.testing.expectError(error.NativeGroupOrder, Group.build(a, &duplicate, .{ .first = 0, .total = 5 }, false));
    var changed_manifest = manifest;
    changed_manifest.digest[0] ^= 1;
    var mixed = [_]Group.Member{ members[0], members[1] };
    mixed[1].cpu.manifest = &changed_manifest;
    try std.testing.expectError(error.NativeGroupManifest, Group.build(a, &mixed, .{ .first = 0, .total = 5 }, false));
    try std.testing.expectError(error.NativeGroupRange, Group.build(a, members[0..1], .{ .first = std.math.maxInt(u32), .total = 5 }, false));
    try std.testing.expectError(error.NativeGroupCompleteRoster, @import("group_execution.zig").run(a, &setups, &truths, &fixture.bundle, F.expectedFor(fixture.keys.cpus[0].materials.program.identity), config, null, std.fs.cwd(), true));
    // The old fixture carries legacy secp providers, which current V3
    // statement authority deliberately refuses. No invented compatibility.
    try std.testing.expectError(error.NotV3Truth, Group.build(a, members[3..5], .{ .first = 3, .total = 5 }, false));
    // A proper subrange is not an accepting execution root.
    for ([_]struct { start: u32, end: u32 }{.{ .start = 0, .end = 3 }}) |r| {
        var graph = try Group.build(a, members[r.start..r.end], .{ .first = r.start, .total = 5 }, false);
        defer graph.deinit();
        var trace = try Group.build(a, members[r.start..r.end], .{ .first = r.start, .total = 5 }, true);
        defer trace.deinit();
        try std.testing.expectEqualDeep(graph.ctx.circuit, trace.ctx.circuit);
        try std.testing.expectEqualSlices(u32, graph.words, trace.words);
        try std.testing.expectEqual(graph.digest, trace.digest);
        try std.testing.expectEqual(@as(usize, 0), trace.ctx.value_table.capacity);
        try std.testing.expectEqual(@as(usize, 9), graph.ctx.circuit.output.items.len);
        std.debug.print("NATIVE_GROUP first={} count={} qm31={} blake={} vars={}\n", .{ r.start, r.end - r.start, graph.ctx.circuit.nQm31OpsRows(), graph.ctx.circuit.blake_g_gate.items.len, graph.ctx.circuit.n_vars });
    }
}

test "native verifier group V3 SHA physical proof restores against independent trace authority" {
    const core = @import("stwo_core");
    const A = @import("stwo_riscv_frontend").rv64_air;
    const HR = @import("../../word16_global_execution/sha256/roster.zig");
    const R = @import("../../word16_global_execution/services/roster.zig");
    const W = @import("../../word16_global_execution/services/gkr_local/worker_protocol.zig");
    const Worker = @import("../../word16_global_execution/services/gkr_local/truth_v3_worker.zig");
    const M = @import("../../word16_global_execution/services/gkr_local/manifest.zig");
    var setup = try HR.TruthSetup.init(a, 5);
    defer setup.deinit();
    var source = try A.crypto.sha256.trace.Source.init(a, &.{A.crypto.sha256.native.PADDING}, 1, 5);
    a.free(source.fixed);
    source.fixed = setup.fixed;
    source.owns_fixed = false;
    const truth = R.Truth{ .sha256 = .{ .setup = &setup, .first_id = 1, .calls = 1 } };
    var cfg = W.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 2) };
    cfg.fri_config.fold_step = 4;
    const expected = M.ExpectedWorker{ .kind = .delegation, .ordinal = 0, .statement = try Worker.truthStatement(truth, cfg, @splat(17)), .fixed = truth.key().root, .global_relations = .{ .ram = false, .kio = false, .wire = true }, .mass = try Worker.truthMass(truth), .local_instances = null };
    var worker = try Worker.TruthWorker.init(a, truth, .{ .sha256 = .{ .source = source } }, expected, cfg, 512 << 20);
    defer worker.deinit(a);
    const stage = try worker.seal(a);
    var entries = [_]M.Entry{.{ .kind = .delegation, .global_relations = expected.global_relations, .mass = expected.mass, .scope = .{ .statement = expected.statement, .fixed = expected.fixed, .main = stage.main, .ordinal = 0 }, .local = null }};
    const digest: [32]u8 = @splat(29);
    const pending = M.PendingManifest{ .entries = &entries, .digest = digest, .shared = M.drawShared(digest) };
    var encoded = try worker.complete(a, &pending, 0, 512 << 20);
    defer encoded.deinit(a);
    const members = [_]Group.Member{.{ .truth = .{ .truth = truth, .expected = expected, .manifest = &pending, .config = cfg, .encoded = &encoded } }};
    var graph = try Group.build(a, &members, .{ .first = 0, .total = 1 }, false);
    defer graph.deinit();
    var trace = try Group.build(a, &members, .{ .first = 0, .total = 1 }, true);
    defer trace.deinit();
    try std.testing.expectEqualDeep(graph.ctx.circuit, trace.ctx.circuit);
    try std.testing.expectEqual(graph.digest, trace.digest);
    const Outer = @import("outer_wrap.zig");
    var proof = try Outer.wrapGraph(a, graph.ctx, graph.digest);
    defer proof.deinit();
    const bytes = try proof.serialize(a);
    defer a.free(bytes);
    var restored = try Outer.wrapGraphOrLoad(a, trace.ctx, trace.digest, bytes);
    defer restored.deinit();
    try std.testing.expect(restored.restored);
    try std.testing.expectEqual(@as(u64, 0), restored.timings.prove_ns);
    try std.testing.expectEqual(proof.effectiveIdentity(), restored.effectiveIdentity());
    try std.testing.expectEqual(@as(usize, 0), trace.ctx.value_table.capacity);
}
