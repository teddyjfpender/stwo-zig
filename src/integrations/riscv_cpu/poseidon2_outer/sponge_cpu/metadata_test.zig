//! Real two-shard execution proves the replacement OWNER consumer locally.
//! Physical frontier binding/shared global closure remain separate gates.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Fixture = @import("../../word16_global_execution/services/sponge_fixture.zig");
const R = @import("../../word16_global_execution/services/roster.zig");
const T = @import("../../word16_global_execution/services/types.zig");
const Coordinator = @import("../../word16_global_execution/services/gkr_local/coordinator.zig");
const Pipeline = @import("../../word16_global_execution/services/pipeline.zig");
const Frame = @import("frame.zig");
const Source = @import("source.zig");
const Provider = @import("provider.zig").Provider;
const Native = @import("native.zig");
const Base = @import("../pure_p2_native.zig");
test "sponge CPU authentic two-shard source GKR consumes all OWNER calls without wide slots" {
    const a = std.testing.allocator;
    var pool: engine.work_pool.WorkPool = .{};
    try pool.initInPlaceWithOptions(.{ .worker_count = 4 });
    defer pool.deinit();
    var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    var captured = try Fixture.Captured.initForOp(a);
    defer captured.deinit();
    for (&captured.native, 0..) |*prepared, ordinal| {
        var geometry = try prepared.geometry();
        geometry.boundary_log = Fixture.BOUNDARY_LOG;
        const bridges = T.Logs{ .keccak = if (ordinal == 0) 5 else null };
        var setup = try R.CpuSetup.initForOpProgram(a, .{ .base = 4096, .words = &Fixture.WORDS }, geometry, bridges);
        defer setup.deinit();
        const request = try Coordinator.requestView(&.{ &captured.native[0], &captured.native[1] }, &captured.advice, ordinal);
        const epoch: u16 = @intCast(ordinal + 1);
        try std.testing.expect(request.sponge.calls != 0);
        var frontier = try Source.Source.initCalls(a, captured.advice.sponge[ordinal].calls, request.sponge.calls, 5, epoch, @intCast(ordinal));
        defer frontier.deinit();
        var source = try Pipeline.buildCpuSourceForOp(a, &setup, request, .{}, prepared, &captured.advice, ordinal, @as([T.FAMILIES]u32, @splat(1)), false, null);
        defer source.deinit();
        try std.testing.expect(source.sponge_plan == null and source.sponge[0] == null and source.sponge[1] == null);
        try frontier.mergeInto(&source);
        var roster = try Frame.Roster.init(a, &setup, request.sponge.calls, 5, epoch, @intCast(ordinal));
        defer roster.deinit();
        for (roster.instances[0 .. roster.instances.len - 1]) |instance| try std.testing.expect(instance == .legacy and instance.legacy.origin != .sponge);
        try std.testing.expectEqual(setup.columnCount(1), roster.instances[roster.instances.len - 1].mainOffset());
        const scope = Native.Scope{ .statement = @splat(0x71), .fixed = Base.hashWords(&.{ 1, 2 }), .main = Base.hashWords(&.{ 3, 4 }), .ordinal = @intCast(ordinal), .epoch = epoch, .calls = request.sponge.calls };
        var child = try Native.proveUnbound(a, scope, roster.instances, Provider{ .legacy = .{ .source = &source }, .frontier = &frontier });
        defer child.deinit(a);
        const encoded = try Native.encode(a, roster.instances, &child.result.proof);
        defer a.free(encoded);
        var decoded = try Native.decode(a, roster.instances, encoded);
        defer decoded.deinit();
        if (ordinal == 0) try @import("manifest_test.zig").exerciseCheckedCpu(a, scope, roster.instances, &decoded.proof, child.digest);
        var pending = try Native.verifyPending(a, scope, roster.instances, &decoded.proof, child.digest);
        defer pending.deinit(a);
        var prefix: engine.lookups.gkr_verifier.ForField(core.fields.om31.OM31).GkrArtifact = undefined;
        const legacy = try pending.checkedLegacy(roster.legacy.len, &prefix);
        try legacy.validate();
        try std.testing.expectEqualSlices(core.fields.om31.OM31, pending.artifact.ood_point, legacy.artifact.ood_point);
        var wrong = scope;
        wrong.epoch += 1;
        try std.testing.expectError(error.SpongeFrontierGeometry, Native.begin(wrong, roster.instances));
        wrong = scope;
        wrong.calls += 1;
        var rejected = Native.verifyPending(a, wrong, roster.instances, &decoded.proof, child.digest);
        if (rejected) |*unexpected| {
            unexpected.deinit(a);
            return error.AcceptedChangedSpongeCallCoverage;
        } else |_| {}
    }
}
