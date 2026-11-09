//! Complete two-shard OP-profile execution with inherited SHA, arithmetic,
//! bulk-memory and load effects; all native claims close at a fresh receiver.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const F = @import("../word16_global_execution/services/v3_fixture.zig");
const R = @import("../word16_global_execution/services/roster.zig");
const T = @import("../word16_global_execution/services/types.zig");
const P = @import("../word16_global_execution/services/protocol.zig");
const Coordinator = @import("../word16_global_execution/services/gkr_local/coordinator.zig");
const Pipeline = @import("../word16_global_execution/services/pipeline.zig");
const CPU = @import("pure_p2_cpu_worker.zig");
const Key = @import("pure_p2_fixed_key.zig").Key;
const Truth = @import("pure_p2_truth_worker.zig");
const Inventory = @import("pure_p2_op_inventory.zig").Inventory;
const Manifest = @import("pure_p2_manifest.zig");
const a = std.testing.allocator;
test "OP complete mixed native inventory fresh receiver closes all shards and providers" {
    var pool: engine.work_pool.WorkPool = .{};
    try pool.initInPlaceWithOptions(.{ .worker_count = 8 });
    defer pool.deinit();
    var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    const profile = @import("pure_p2_worker_protocol.zig").Profile.op_target_b4_q72_p0_fold4_v1;
    var captured = try F.Captured.initForOp(a);
    defer captured.deinit();
    var setups: [2]R.CpuSetup = undefined;
    var fresh: [2]R.CpuSetup = undefined;
    var keys: [2]Key = undefined;
    var fresh_keys: [2]Key = undefined;
    var made: usize = 0;
    defer for (0..made) |i| {
        keys[i].deinit();
        fresh_keys[i].deinit();
        setups[i].deinit();
        fresh[i].deinit();
    };
    for (0..2) |i| {
        var geometry = try captured.native[i].geometry();
        geometry.boundary_log = F.BOUNDARY_LOG;
        setups[i] = try R.CpuSetup.initForOpProgram(a, .{ .base = 4096, .words = &F.WORDS }, geometry, F.BRIDGES[i]);
        fresh[i] = try R.CpuSetup.initForOpProgram(a, .{ .base = 4096, .words = &F.WORDS }, geometry, F.BRIDGES[i]);
        keys[i] = try Key.initForOp(a, &setups[i], profile);
        fresh_keys[i] = try Key.initForOp(a, &fresh[i], profile);
        made += 1;
    }
    var sha = try @import("../word16_global_execution/sha256/roster.zig").TruthSetup.init(a, F.SHA_LOG);
    defer sha.deinit();
    var arith = try @import("../word16_global_execution/arith256/roster.zig").TruthSetup.init(a, F.ARITH_LOG);
    defer arith.deinit();
    const truths = F.truthsFor(&sha, &arith);
    var tk0 = try Truth.Key.init(a, truths[0], profile);
    defer tk0.deinit();
    var tk1 = try Truth.Key.init(a, truths[1], profile);
    defer tk1.deinit();
    var fk0 = try Truth.Key.init(a, truths[0], profile);
    defer fk0.deinit();
    var fk1 = try Truth.Key.init(a, truths[1], profile);
    defer fk1.deinit();
    const Native = @import("../word16_execution/prepared.zig").Prepared;
    const natives = [_]*Native{ &captured.native[0], &captured.native[1] };
    var requests = [_]P.Request{ try Coordinator.requestView(&natives, &captured.advice, 0), try Coordinator.requestView(&natives, &captured.advice, 1) };
    try Coordinator.assignSpongeIds(&requests);
    const spans = [_]T.OpTowerSpan{ .{}, .{} };
    const expected = F.expectedFor(captured.program.identity, captured.loaded);
    var inventory = try Inventory.init(a, profile, &.{ &setups[0], &setups[1] }, &requests, &spans, &.{ &keys[0], &keys[1] }, &truths, &.{ &tk0, &tk1 }, &.{}, expected);
    defer inventory.deinit();
    var receiver = try Inventory.init(a, profile, &.{ &fresh[0], &fresh[1] }, &requests, &spans, &.{ &fresh_keys[0], &fresh_keys[1] }, &truths, &.{ &fk0, &fk1 }, &.{}, expected);
    defer receiver.deinit();
    try std.testing.expectEqualSlices(u8, &inventory.execution, &receiver.execution);
    try std.testing.expectError(error.UnqualifiedOpProtocol, P.admit(a, &.{ &setups[0], &setups[1] }, &truths, &requests, expected));
    try std.testing.expect(std.meta.isError(Inventory.init(a, profile, &.{ &fresh[0], &fresh[1] }, &requests, &spans, &.{ &fresh_keys[0], &fresh_keys[1] }, truths[0..1], &.{&fk0}, &.{}, expected)));
    var bad_endpoint = expected;
    bad_endpoint.final_pc += 4;
    try std.testing.expect(std.meta.isError(Inventory.init(a, profile, &.{ &fresh[0], &fresh[1] }, &requests, &spans, &.{ &fresh_keys[0], &fresh_keys[1] }, &truths, &.{ &fk0, &fk1 }, &.{}, bad_endpoint)));
    var cpus: [2]CPU.Worker = undefined;
    var count: usize = 0;
    defer for (cpus[0..count]) |*worker| worker.deinit();
    for (0..2) |i| {
        var source = try Pipeline.buildCpuSourceForOp(a, &setups[i], requests[i], spans[i], natives[i], &captured.advice, i, inventory.first_ids[i], false, null);
        cpus[i] = CPU.Worker.initForOp(a, &setups[i], requests[i], spans[i], source, inventory.workers[i], inventory.first_ids[i], &keys[i], .{ .gkr_bytes = 1 << 30, .global_bytes = 1 << 30 }) catch |err| {
            source.deinit();
            return err;
        };
        count += 1;
    }
    const limits = Truth.Limits{ .live_bytes = 1 << 30, .main_bytes = 128 << 20, .interaction_bytes = 512 << 20, .advice_bytes = 128 << 20 };
    var tw0 = try Truth.Worker.init(a, &tk0, truths[0], Truth.SourceBuilder.fromAdvice(&captured.advice), inventory.workers[2], limits);
    defer tw0.deinit();
    var tw1 = try Truth.Worker.init(a, &tk1, truths[1], Truth.SourceBuilder.fromAdvice(&captured.advice), inventory.workers[3], limits);
    defer tw1.deinit();
    const stages = [_]Manifest.StageOne{ try cpus[0].seal(a), try cpus[1].seal(a), try tw0.seal(), try tw1.seal() };
    var pending = try Manifest.verifyAndSeal(a, inventory.execution, inventory.workers, &stages);
    defer pending.deinit(a);
    var fresh_pending = try Manifest.verifyAndSeal(a, receiver.execution, receiver.workers, &stages);
    defer fresh_pending.deinit(a);
    var c0 = try cpus[0].complete(a, &pending, 0);
    defer c0.deinit(a);
    var c1 = try cpus[1].complete(a, &pending, 1);
    defer c1.deinit(a);
    var t0 = try tw0.complete(&pending, 2);
    defer t0.deinit(a);
    var t1 = try tw1.complete(&pending, 3);
    defer t1.deinit(a);
    const claims = [_]Manifest.Claims{
        try CPU.verifyForOp(a, &fresh[0], requests[0], spans[0], receiver.workers[0], receiver.first_ids[0], &fresh_pending, 0, &fresh_keys[0], &c0, null),
        try CPU.verifyForOp(a, &fresh[1], requests[1], spans[1], receiver.workers[1], receiver.first_ids[1], &fresh_pending, 1, &fresh_keys[1], &c1, null),
        try Truth.verify(a, &fk0, truths[0], receiver.workers[2], &fresh_pending, 2, &t0),
        try Truth.verify(a, &fk1, truths[1], receiver.workers[3], &fresh_pending, 3, &t1),
    };
    try fresh_pending.checkGlobalClosure(&claims);
    const BW = @import("pure_p2_op_bundle.zig");
    const MW = @import("pure_p2_manifest_wire.zig");
    const stage_bytes = try MW.encode(a, inventory.execution, inventory.workers, &stages);
    defer a.free(stage_bytes);
    var borrowed_proofs = [_]BW.Proof{
        .{ .bytes = c0.bytes, .claims = c0.claims }, .{ .bytes = c1.bytes, .claims = c1.claims },
        .{ .bytes = t0.bytes, .claims = t0.claims }, .{ .bytes = t1.bytes, .claims = t1.claims },
    };
    const borrowed = BW.Bundle{ .stage_one = stage_bytes, .proofs = &borrowed_proofs };
    const wire_limits = BW.Limits{ .bytes = 64 << 20, .proof_bytes = 16 << 20 };
    const bytes = try BW.encode(a, &borrowed, wire_limits);
    defer a.free(bytes);
    var durable = try BW.decode(a, bytes, receiver.workers.len, wire_limits);
    defer durable.deinit(a);
    try durable.verify(a, &receiver, &.{ &fresh[0], &fresh[1] }, &requests, &spans, &.{ &fresh_keys[0], &fresh_keys[1] }, &truths, &.{ &fk0, &fk1 }, &.{});
    try std.testing.expectError(error.InvalidOpNativeBundle, BW.decode(a, bytes, 3, wire_limits));
    try std.testing.expectError(error.OpNativeBundleLimit, BW.decode(a, bytes, 4, .{ .bytes = bytes.len - 1, .proof_bytes = 16 << 20 }));
    try std.testing.expect(std.meta.isError(BW.decode(a, bytes[0 .. bytes.len - 1], 4, wire_limits)));
    const saved = durable.proofs[0].claims[0];
    durable.proofs[0].claims[0] = saved.add(@import("stwo_core").fields.om31.OM31.one());
    try std.testing.expect(std.meta.isError(durable.verify(a, &receiver, &.{ &fresh[0], &fresh[1] }, &requests, &spans, &.{ &fresh_keys[0], &fresh_keys[1] }, &truths, &.{ &fk0, &fk1 }, &.{})));
    durable.proofs[0].claims[0] = saved;
    try std.testing.expectError(error.GlobalGkrManifestRoster, fresh_pending.checkGlobalClosure(claims[0..3]));
    std.debug.print("OP_MIXED_COMPLETE steps={} CPU=2 truth=2 SHA=2 ARITH=2 bulk=2 native_bytes={} closure=RAM_Wire fresh=true\n", .{ F.STEPS, c0.bytes.len + c1.bytes.len + t0.bytes.len + t1.bytes.len });
}
