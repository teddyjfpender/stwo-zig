//! Conditional source accounting is admission preflight, not execution acceptance.
const std = @import("std");
const core = @import("stwo_core");
const front = @import("stwo_riscv_frontend");
const A = front.rv64_air;
const Bounds = @import("../../word16_global_execution/services/gkr_local/source_bounds.zig");
const P = @import("../../word16_global_execution/services/protocol.zig");
const T = @import("../../word16_global_execution/services/types.zig");
const Wire = @import("../../word16_global_execution/services/wire.zig");
const Geometry = @import("../../word16_execution/geometry.zig").Geometry;
const a = std.testing.allocator;
fn request(epoch: u16) P.Request {
    var registers: [32]u64 = @splat(0);
    registers[10] = 0x10000;
    registers[17] = A.crypto.bn254_tower.execution.TAG;
    return .{ .calls = @splat(0), .base = .{ .cpu = .{ .steps = 1, .initial_pc = 4096, .final_pc = 4100, .initial_registers = registers, .final_registers = registers, .register_clocks = @splat(0) }, .epoch = epoch, .division_requests = 0, .multiplication_requests = 0, .memory = .{ .initial = &.{}, .terminal = &.{}, .epoch = epoch, .ls_count = 0 } } };
}

test "OP source accounting closes exact signed topology and canonical SSA writes" {
    const declarations = [_]Wire.CpuDeclaration{ .{ .geometry = .{ .cpu_log = 5 }, .bridges = .{ .tower = 5 } }, .{ .geometry = .{ .cpu_log = 5 }, .bridges = .{ .tower = 5 } } };
    const requests = [_]P.Request{ request(1), request(2) };
    const spans = [_]T.OpTowerSpan{ .{ .calls = 1, .first_id = 1 }, .{ .calls = 1, .first_id = 2 } };
    const truth = [_]Bounds.OpTowerTruthDeclaration{.{ .calls = 2, .first_id = 1, .frontier_log = 8, .arithmetic_log = 15 }};
    var report = try Bounds.deriveForOp(a, 5, &declarations, &.{}, &requests, &spans, &truth);
    defer report.deinit();
    try std.testing.expectEqual(@as(usize, 3), report.base.shape.native_proofs);
    try std.testing.expectEqual(@as(u64, 160), report.base.global_signed.ram.positive);
    try std.testing.expectEqual(@as(u64, 160), report.base.global_signed.ram.negative);
    try std.testing.expectEqual(@as(u64, 64), report.base.global_signed.wire.positive);
    try std.testing.expectEqual(@as(u64, 64), report.base.global_signed.wire.negative);
    const local = report.op_truth_scopes[0];
    try std.testing.expectEqual(@as(u64, 64), local.canonical_writes);
    try std.testing.expectEqual(@as(u64, 64 * 97), local.bytes.unit_consumer_mass);
    try std.testing.expectEqual(@as(u64, 64 * 31), local.carries.unit_consumer_mass);
    try std.testing.expectEqual(@as(u64, 256), local.bytes.valid_provider_support);
    try std.testing.expectEqual(@as(u64, 32768), local.carries.valid_provider_support);
    try std.testing.expectEqual(@as(u64, 344), local.ssa.unit_positive_mass);
    try std.testing.expectEqual(@as(u64, 344), local.ssa.unit_negative_mass);
    try std.testing.expectEqual(@as(usize, 35), local.ssa.arity);
    try std.testing.expect(!report.base.security_qualified and !report.base.transcript_round_bound_qualified);
    try std.testing.expectError(error.UnqualifiedOpProtocol, Bounds.derive(a, 5, &declarations, &.{}, &requests));
    try std.testing.expectError(error.InvalidOpTowerCoverage, Bounds.deriveForOp(a, 5, &declarations, &.{}, &requests, &spans, &.{}));
    var repeated = spans;
    repeated[1].first_id = 1;
    try std.testing.expectError(error.InvalidOpTowerCoverage, Bounds.deriveForOp(a, 5, &declarations, &.{}, &requests, &repeated, &truth));
    const duplicate = [_]Bounds.OpTowerTruthDeclaration{ .{ .calls = 1, .first_id = 1, .frontier_log = 8, .arithmetic_log = 15 }, .{ .calls = 1, .first_id = 1, .frontier_log = 8, .arithmetic_log = 15 } };
    try std.testing.expectError(error.InvalidOpTowerCoverage, Bounds.deriveForOp(a, 5, &declarations, &.{}, &requests, &spans, &duplicate));
    var extra = spans;
    extra[0].calls = 2;
    var larger = declarations;
    larger[0].bridges.tower = 6;
    try std.testing.expectError(error.InvalidCombinedServiceCount, Bounds.deriveForOp(a, 5, &larger, &.{}, &requests, &extra, &truth));
}

test "OP independent local scopes do not acquire a false aggregate characteristic cap" {
    const count = 200;
    var declarations: [count]Wire.CpuDeclaration = undefined;
    var requests: [count]P.Request = undefined;
    var spans: [count]T.OpTowerSpan = undefined;
    for (&declarations, &requests, &spans, 0..) |*declaration, *req, *span, i| {
        declaration.* = .{ .geometry = Geometry{ .cpu_log = 22 }, .bridges = .{ .tower = 5 } };
        req.* = request(@intCast(i + 1));
        span.* = .{ .calls = 1, .first_id = @intCast(i + 1) };
    }
    const truth = [_]Bounds.OpTowerTruthDeclaration{.{ .calls = count, .first_id = 1, .frontier_log = 12, .arithmetic_log = 15 }};
    var report = try Bounds.deriveForOp(a, 5, &declarations, &.{}, &requests, &spans, &truth);
    defer report.deinit();
    const Range = @import("../../word16_global_execution/services/gkr_local/fractions.zig").Relation.range8;
    var summed_local: u64 = 0;
    for (report.base.cpu_scopes) |scope| {
        const bound = scope.relations[@intFromEnum(Range)];
        try bound.validate();
        summed_local += bound.unit_consumer_mass;
    }
    std.debug.print("OP_LOCAL_SCOPE_UNION local_range8_total={d} proofs={d} shared_ram_positive={d}\n", .{ summed_local, count, report.base.global_signed.ram.positive });
    try std.testing.expect(summed_local > core.fields.m31.Modulus);
    try std.testing.expect(report.base.global_signed.ram.positive < core.fields.m31.Modulus);
    try std.testing.expect(!report.base.security_qualified);
}
