//! Actual quotient consumers: both secure-field families preserve admission provenance.
const std = @import("std");
const core = @import("stwo_core");
const api = @import("stwo_prover_api");
const TreeVec = core.pcs.TreeVec;

fn provider(comptime S: type, allocator: std.mem.Allocator, columns: TreeVec([]const api.ColumnEvaluation), points: TreeVec([][]core.circle.CirclePoint(S)), values: TreeVec([][]S), log: u32, diagnostic: ?*?api.error_codes.ColumnFailure) !void {
    if (S == core.fields.qm31.QM31) {
        var result = try @import("pcs/quotients/lazy_provider.zig").LazyQuotientProvider.initForBackendWithWorkRecorderDiagnosed(void, allocator, columns, points, values, S.one(), log, null, diagnostic);
        defer result.deinit(allocator);
    } else {
        var result = try @import("pcs/quotient_field.zig").ForField(S).LazyQuotientProvider.initForBackendWithWorkRecorderAndByteLimitDiagnosed(void, allocator, columns, points, values, S.one(), log, null, null, diagnostic);
        defer result.deinit(allocator);
    }
}

fn admitted(comptime S: type, allocator: std.mem.Allocator, diagnostic: ?*?api.error_codes.ColumnFailure) !void {
    const Point = core.circle.CirclePoint(S);
    const data = [_]core.fields.m31.M31{core.fields.m31.M31.zero()} ** 2;
    var columns = [_][]const api.ColumnEvaluation{&.{.{ .log_size = 1, .values = &data }}};
    var points = [_][]Point{&.{}};
    var point_trees = [_][][]Point{&points};
    var values = [_][]S{&.{}};
    var value_trees = [_][][]S{&values};
    try provider(S, allocator, TreeVec([]const api.ColumnEvaluation).initOwned(&columns), TreeVec([][]Point).initOwned(&point_trees), TreeVec([][]S).initOwned(&value_trees), 1, diagnostic);
}

fn admission(comptime S: type) !void {
    const Point = core.circle.CirclePoint(S);
    var diagnostic: ?api.error_codes.ColumnFailure = null;
    var columns = [_][]const api.ColumnEvaluation{&.{.{ .log_size = 2, .values = &.{} }}};
    var point_columns = [_][]Point{&.{}};
    var point_trees = [_][][]Point{&point_columns};
    var value_columns = [_][]S{&.{}};
    var value_trees = [_][][]S{&value_columns};
    try std.testing.expectError(error.InvalidColumnLength, provider(S, std.testing.allocator, TreeVec([]const api.ColumnEvaluation).initOwned(&columns), TreeVec([][]Point).initOwned(&point_trees), TreeVec([][]S).initOwned(&value_trees), 2, &diagnostic));
    try std.testing.expectEqual(@as(u16, 0x3003), diagnostic.?.entry.code);
    diagnostic = null;
    try std.testing.expectError(error.ShapeMismatch, provider(S, std.testing.allocator, TreeVec([]const api.ColumnEvaluation).initOwned(&columns), TreeVec([][]Point).initOwned(&.{}), TreeVec([][]S).initOwned(&.{}), 2, &diagnostic));
    try std.testing.expectEqual(@as(u16, 0x3001), diagnostic.?.entry.code);
    diagnostic = null;
    try std.testing.expectError(error.InvalidColumnLogSize, provider(S, std.testing.allocator, TreeVec([]const api.ColumnEvaluation).initOwned(&.{}), TreeVec([][]Point).initOwned(&.{}), TreeVec([][]S).initOwned(&.{}), @bitSizeOf(usize), &diagnostic));
    try std.testing.expectEqual(@as(u16, 0x3002), diagnostic.?.entry.code);
    diagnostic = null;
    try admitted(S, std.testing.allocator, &diagnostic);
    try std.testing.expect(diagnostic == null);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, struct {
        fn run(allocator: std.mem.Allocator) !void {
            var empty: ?api.error_codes.ColumnFailure = null;
            try admitted(S, allocator, &empty);
            try std.testing.expect(empty == null);
        }
    }.run, .{});
    var failure = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    diagnostic = null;
    try std.testing.expectError(error.OutOfMemory, admitted(S, failure.allocator(), &diagnostic));
    try std.testing.expect(diagnostic == null);
    try std.testing.expectEqual(failure.allocated_bytes, failure.freed_bytes);
}

test "typed quotient origin survives QM31 and OM31 consumers without mapping OOM" {
    try admission(core.fields.qm31.QM31);
    try admission(core.fields.om31.OM31);
}
