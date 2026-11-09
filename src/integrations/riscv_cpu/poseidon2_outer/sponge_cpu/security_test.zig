//! Source-only qualification: no witness expansion, GKR or physical STARK.
const std = @import("std");
const core = @import("stwo_core");
const Fixture = @import("../../word16_global_execution/services/sponge_fixture.zig");
const R = @import("../../word16_global_execution/services/roster.zig");
const T = @import("../../word16_global_execution/services/types.zig");
const P = @import("../../word16_global_execution/services/protocol.zig");
const Wire = @import("../../word16_global_execution/services/wire.zig");
const Coordinator = @import("../../word16_global_execution/services/gkr_local/coordinator.zig");
const Bounds = @import("../../word16_global_execution/services/gkr_local/source_bounds.zig");
const Frame = @import("frame.zig");
const Detached = @import("../sponge_local_gkr/authority.zig");
const Security = @import("security.zig");
fn allocationRoundtrip(a: std.mem.Allocator, program_log: u32, declarations: *const [2]Wire.CpuDeclaration, truth: *const [1]Wire.TruthDeclaration, requests: *const [2]P.Request, spans: *const [2]T.OpTowerSpan, detached: []const Detached.Geometry) !void {
    var report = try Bounds.deriveForOpDetached(a, program_log, declarations, truth, requests, spans, &.{}, &.{ 5, 5 }, detached);
    defer report.deinit();
}
test "detached security complete actual source scopes characteristic and conditional ledger" {
    const a = std.testing.allocator;
    var captured = try Fixture.Captured.initForOp(a);
    defer captured.deinit();
    var setups: [2]R.CpuSetup = undefined;
    var rosters: [2]Frame.Roster = undefined;
    var made: usize = 0;
    defer for (0..made) |i| {
        rosters[i].deinit();
        setups[i].deinit();
    };
    var declarations: [2]Wire.CpuDeclaration = undefined;
    var requests: [2]P.Request = undefined;
    var instances: [2][]const Frame.Instance = undefined;
    for (&captured.native, 0..) |*prepared, i| {
        var geometry = try prepared.geometry();
        geometry.boundary_log = Fixture.BOUNDARY_LOG;
        setups[i] = try R.CpuSetup.initForOpProgram(a, .{ .base = 4096, .words = &Fixture.WORDS }, geometry, .{ .keccak = if (i == 0) 5 else null });
        rosters[i] = Frame.Roster.init(a, &setups[i], @intCast(captured.advice.sponge[i].calls.len), 5, @intCast(i + 1), @intCast(i)) catch |err| {
            setups[i].deinit();
            return err;
        };
        made += 1;
        declarations[i] = .{ .geometry = geometry, .bridges = setups[i].bridges };
        requests[i] = try Coordinator.requestView(&.{ &captured.native[0], &captured.native[1] }, &captured.advice, i);
        instances[i] = rosters[i].instances;
    }
    try Coordinator.assignSpongeIds(&requests);
    const spans = [_]T.OpTowerSpan{.{}} ** 2;
    const truth = [_]Wire.TruthDeclaration{.{ .family = .keccak, .first_id = 1, .calls = 6, .logs = .{ Fixture.KECCAK_LOG, 0 } }};
    const detached = [_]Detached.Geometry{.{ .calls = 3, .permutations = 5, .first_id = 2, .detached = true }};
    var report = try Bounds.deriveForOpDetached(a, setups[0].materials.program.log_size, &declarations, &truth, &requests, &spans, &.{}, &.{ 5, 5 }, &detached);
    defer report.deinit();
    const preflight = try Security.preflight(.op_target_b4_q72_p0_fold4_v1, &report, &truth, &.{});
    const checked = try Security.check(.op_target_b4_q72_p0_fold4_v1, &report, &instances, &detached, &truth, &.{});
    for (checked.conditional_degree_weight, preflight.conditional_degree_weight) |exact, envelope| try std.testing.expect(exact <= envelope);
    try std.testing.expect(!preflight.security_qualified and !preflight.production_admission);
    try std.testing.expectError(error.DetachedSecurityShape, Security.preflight(.reference_b2_q24_p0, &report, &truth, &.{}));
    try std.testing.expectEqual(@as(usize, 4), report.op.base.shape.native_proofs);
    try std.testing.expectEqual(@as(u32, 3), checked.cpu_and_detached.scopes);
    try std.testing.expectEqual(@as(u32, 1), checked.truth.scopes);
    try std.testing.expectEqual(@as(u32, 0), checked.miller.scopes);
    try std.testing.expect(!checked.security_qualified and !checked.production_admission);
    const owner = report.detached_scopes[0].relations[@intFromEnum(Bounds.DetachedRelation.owner)];
    try std.testing.expect(owner.unit_positive_mass > 0 and owner.unit_negative_mass > 0);
    try std.testing.expect(owner.denominator_slots >= 3);
    const integer = report.op.base.global_signed;
    try std.testing.expect(integer.wire.positive > 0 and integer.wire.negative > 0);
    try std.testing.expectError(error.DetachedSecurityShape, Security.check(.reference_b2_q24_p0, &report, &instances, &detached, &truth, &.{}));
    var invalid = detached;
    invalid[0].first_id += 1;
    try std.testing.expectError(error.InvalidDetachedSourceInventory, Bounds.deriveForOpDetached(std.testing.failing_allocator, setups[0].materials.program.log_size, &declarations, &truth, &requests, &spans, &.{}, &.{ 5, 5 }, &invalid));
    // Legacy path still refuses nonzero sponge counts without its actual bridge.
    var old = Bounds.deriveForOp(a, setups[0].materials.program.log_size, &declarations, &truth, &requests, &spans, &.{});
    if (old) |*unexpected| {
        unexpected.deinit();
        return error.AcceptedNewSourceAsLegacy;
    } else |_| {}
    try std.testing.checkAllAllocationFailures(a, allocationRoundtrip, .{ setups[0].materials.program.log_size, &declarations, &truth, &requests, &spans, &detached });
    var zero_requests = requests;
    for (&zero_requests) |*request| request.sponge = .{};
    var zero_truth = truth;
    zero_truth[0].calls = 1; // Only the direct Keccak source remains.
    var empty = try Bounds.deriveForOpDetached(a, setups[0].materials.program.log_size, &declarations, &zero_truth, &zero_requests, &spans, &.{}, &.{ 5, 5 }, &.{});
    defer empty.deinit();
    try std.testing.checkAllAllocationFailures(a, allocationRoundtrip, .{ setups[0].materials.program.log_size, &declarations, &zero_truth, &zero_requests, &spans, @as([]const Detached.Geometry, &.{}) });
    const zero_preflight = try Security.preflight(.op_target_b4_q72_p0_fold4_v1, &empty, &zero_truth, &.{});
    const zero_checked = try Security.check(.op_target_b4_q72_p0_fold4_v1, &empty, &instances, &.{}, &zero_truth, &.{});
    for (zero_checked.conditional_degree_weight, zero_preflight.conditional_degree_weight) |exact, envelope| try std.testing.expect(exact <= envelope);
    try std.testing.expectEqual(@as(usize, 3), empty.op.base.shape.native_proofs);
    try std.testing.expectEqual(@as(usize, 0), empty.detached_scopes.len);
    try std.testing.expectEqual(@as(u32, 2), zero_checked.cpu_and_detached.scopes);
    try std.testing.expectError(error.InvalidDetachedSourceInventory, Bounds.deriveForOpDetached(std.testing.failing_allocator, setups[0].materials.program.log_size, &declarations, &truth, &requests, &spans, &.{}, &.{ 5, 5 }, &.{}));
    try std.testing.expectError(error.InvalidDetachedSourceInventory, Bounds.deriveForOpDetached(std.testing.failing_allocator, setups[0].materials.program.log_size, &declarations, &zero_truth, &zero_requests, &spans, &.{}, &.{ 5, 5 }, &detached));
    const json = try std.json.Stringify.valueAlloc(a, .{ .scope = "source_only_no_STARK_or_GKR", .shape = report.op.base.shape, .cpu_and_detached = checked.cpu_and_detached, .conditional_degrees = report.op.base.conditional_degrees, .detached_relations = report.detached_scopes[0].relations, .global_signed = integer, .security_qualified = false, .production_admission = false }, .{});
    defer a.free(json);
    std.debug.print("OP_DETACHED_SECURITY {s}\n", .{json});
}

test {
    _ = @import("../../word16_global_execution/services/gkr_local/source_bounds_test.zig");
}
