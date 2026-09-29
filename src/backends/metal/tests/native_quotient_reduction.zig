//! Exercise the real segmented production path against the scalar quotient.
const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const runtime_mod = @import("../runtime.zig");
const quotient = prover.pcs.quotient_ops;
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const Point = core.circle.CirclePointQM31;
const TreeVec = core.pcs.utils.TreeVec;
const Raw = struct {
    pub const rawQuotientInputs = true;
};

test "metal: native segmented quotient reduction matches scalar mixed heights and batches" {
    const a = std.testing.allocator;
    const full_log = 17;
    const short_log = 14;
    const short_rows = 1 << short_log;
    const per_run = 256;
    const run_count = 4;
    const count = 1 + per_run * run_count;
    // Each owned run has unused guard words, forcing separate source bindings.
    // A one-word prefix also exercises non-page-aligned no-copy source aliases.
    var arenas: [run_count][]M31 = undefined;
    var initialized: usize = 0;
    defer for (arenas[0..initialized]) |arena| a.free(arena);
    for (&arenas, 0..) |*arena, run| {
        arena.* = try a.alloc(M31, per_run * short_rows + 1025);
        initialized += 1;
        for (arena.*, 0..) |*value, i| value.* = M31.fromCanonical(@intCast((i * 19 + run * 173 + 5) % 2147483647));
    }
    const full = try a.alloc(M31, 1 << full_log);
    defer a.free(full);
    for (full, 0..) |*value, i| value.* = M31.fromCanonical(@intCast(i * 13 + 7));
    const columns = try a.alloc(quotient.ColumnEvaluation, count);
    defer a.free(columns);
    columns[0] = .{ .log_size = full_log, .values = full };
    for (arenas, 0..) |arena, run| for (0..per_run) |i| {
        const start = 1 + i * short_rows;
        columns[1 + run * per_run + i] = .{ .log_size = short_log, .values = arena[start..][0..short_rows] };
    };
    var points = [_]Point{ core.circle.SECURE_FIELD_CIRCLE_GEN.mul(7), core.circle.SECURE_FIELD_CIRCLE_GEN.mul(19) };
    var samples = [_]QM31{ QM31.fromU32Unchecked(3, 5, 7, 11), QM31.fromU32Unchecked(13, 17, 19, 23) };
    const point_columns = try a.alloc([]Point, count);
    defer a.free(point_columns);
    const sample_columns = try a.alloc([]QM31, count);
    defer a.free(sample_columns);
    for (point_columns, sample_columns, 0..) |*p, *s, i| {
        const n: usize = if (i % 3 == 0) 2 else 1;
        p.* = points[0..n];
        s.* = samples[0..n];
    }
    var column_tree = [_][]const quotient.ColumnEvaluation{columns};
    var point_tree = [_][][]Point{point_columns};
    var sample_tree = [_][][]QM31{sample_columns};
    const ct = TreeVec([]const quotient.ColumnEvaluation).initOwned(&column_tree);
    const pt = TreeVec([][]Point).initOwned(&point_tree);
    const st = TreeVec([][]QM31).initOwned(&sample_tree);
    const alpha = QM31.fromU32Unchecked(29, 31, 37, 41);
    var expected = try quotient.computeFriQuotients(a, ct, pt, st, alpha, full_log, 1);
    defer expected.deinit(a);
    var provider = try quotient.LazyQuotientProvider.initForBackend(Raw, a, ct, pt, st, alpha, full_log);
    defer provider.deinit(a);
    var actual = try prover.secure_column.SecureColumnByCoords.zeros(a, 1 << full_log);
    defer actual.deinit(a);
    var runtime = try runtime_mod.Runtime.init();
    defer runtime.deinit();
    _ = try runtime.computeQuotients(a, &provider, &actual);
    for (expected.columns, actual.columns) |e, v| try std.testing.expectEqualSlices(M31, e, v);
}
