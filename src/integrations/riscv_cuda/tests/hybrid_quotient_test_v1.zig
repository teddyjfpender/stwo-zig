const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Plan = @import("../hybrid_quotient_plan_v1.zig");
const Provider = engine.pcs.quotient_ops.LazyQuotientProvider;
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const Point = core.circle.CirclePointQM31;
const Tree = core.pcs.utils.TreeVec;
const Column = engine.pcs.ColumnEvaluation;

pub fn run(comptime device: bool) !void {
    const a = std.testing.allocator;
    const raw = [_]M{ M.one(), M.fromCanonical(3), M.fromCanonical(7), M.fromCanonical(11) };
    const constant = [_]M{M.fromCanonical(13)} ** 2;
    const coefficients = [_]M{ M.fromCanonical(17), M.fromCanonical(19), M.fromCanonical(23), M.fromCanonical(29) };
    const polynomial = try engine.poly.circle.poly.CircleCoefficients.initBorrowed(&coefficients);
    const restored = try polynomial.evaluate(a, core.poly.circle.canonic.CanonicCoset.new(5).circleDomain());
    defer a.free(restored.values);
    const other_coefficients = [_]M{ M.fromCanonical(31), M.fromCanonical(37) };
    const other = try engine.poly.circle.poly.CircleCoefficients.initBorrowed(&other_coefficients);
    const restored_same = try other.evaluate(a, core.poly.circle.canonic.CanonicCoset.new(5).circleDomain());
    defer a.free(restored_same.values);
    const restored_small = try other.evaluate(a, core.poly.circle.canonic.CanonicCoset.new(3).circleDomain());
    defer a.free(restored_small.values);
    const restored_tiny = try other.evaluate(a, core.poly.circle.canonic.CanonicCoset.new(2).circleDomain());
    defer a.free(restored_tiny.values);
    var columns = [_]Column{ .{ .log_size = 2, .values = &raw }, .{ .log_size = 1, .values = &constant }, .{ .log_size = 5, .values = restored.values }, .{ .log_size = 2, .values = &raw }, .{ .log_size = 5, .values = restored_same.values }, .{ .log_size = 3, .values = restored_small.values }, .{ .log_size = 2, .values = restored_tiny.values } };
    var column_trees = [_][]const Column{&columns};
    var points = [_]Point{ core.circle.SECURE_FIELD_CIRCLE_GEN.mul(7), core.circle.SECURE_FIELD_CIRCLE_GEN.mul(13), core.circle.SECURE_FIELD_CIRCLE_GEN.mul(19) };
    var values = [_]Q{ Q.zero(), Q.one(), Q.fromU32Unchecked(3, 5, 7, 11) };
    var point_columns = [_][]Point{ points[0..2], points[0..1], points[1..3], &.{}, points[0..2], points[1..2], points[0..1] };
    var value_columns = [_][]Q{ values[0..2], values[0..1], values[1..3], &.{}, values[0..2], values[1..2], values[0..1] };
    var point_trees = [_][][]Point{&point_columns};
    var value_trees = [_][][]Q{&value_columns};
    const cs = Tree([]const Column).initOwned(&column_trees);
    const ps = Tree([][]Point).initOwned(&point_trees);
    const vs = Tree([][]Q).initOwned(&value_trees);
    const alpha = Q.fromU32Unchecked(2, 3, 5, 7);
    var expected = try engine.pcs.quotient_ops.computeFriQuotients(a, cs, ps, vs, alpha, 7, 1);
    defer expected.deinit(a);
    // Preserve exact original columns/samples with compact source storage;
    // the raw executor must not inherit Metal's synthetic coordinate promotion.
    columns[2] = .{ .log_size = 5, .values = &.{}, .coefficient_values = &coefficients };
    columns[4] = .{ .log_size = 5, .values = &.{}, .coefficient_values = &other_coefficients };
    columns[5] = .{ .log_size = 3, .values = &.{}, .coefficient_values = &other_coefficients };
    columns[6] = .{ .log_size = 2, .values = &.{}, .coefficient_values = &other_coefficients };
    var provider = try Provider.initForBackend(engine.pcs.QuotientExecutor.RawInputs, a, cs, ps, vs, alpha, 7);
    defer provider.deinit(a);
    var plan = try Plan.Owned.init(a, &provider, .{});
    defer plan.deinit();
    try std.testing.expectEqual(@as(usize, 6), plan.sources.len);
    try std.testing.expectEqual(provider.prepared.contribution_plan.contributions.len, plan.terms.len);
    // Same-height compact columns are contiguous while every original source
    // index remains unchanged. This enables genuine batched GPU LDE.
    try std.testing.expectEqual(plan.sources[2].offset + 32, plan.sources[3].offset);
    try std.testing.expectEqual(provider.prepared.sample_batches.len, plan.group_logs.len);
    try std.testing.expect(provider.raw_columns[2].coefficient_values != null);
    try std.testing.expectError(error.CudaQuotientResourceLimit, Plan.Owned.init(a, &provider, .{ .max_device_bytes = plan.device_bytes - 1 }));
    try std.testing.expectError(error.CudaQuotientResourceLimit, Plan.Owned.init(a, &provider, .{ .max_metadata_bytes = 1 }));
    const X = @import("../hybrid_quotient_executor_v1.zig");
    const expansion = try X.expansionGeometry(&plan, .{});
    try std.testing.expectEqual(@as(u32, 5), expansion.max_log);
    try std.testing.expectError(error.CudaQuotientResourceLimit, X.expansionGeometry(&plan, .{ .max_device_expansion_scratch_bytes = 63 }));
    try std.testing.expectError(error.CudaQuotientResourceLimit, X.expansionGeometry(&plan, .{ .max_host_scratch_bytes = 127 }));
    try std.testing.expectError(error.CudaQuotientResourceLimit, X.expansionGeometry(&plan, .{ .plan = .{ .max_device_bytes = plan.device_bytes + expansion.extra_device_bytes - 1 } }));
    var output = try engine.secure_column.SecureColumnByCoords.uninitialized(a, provider.domain_size);
    defer output.deinit(a);
    if (device) {
        var owner = try X.Owner.open(0, 90, .{});
        defer owner.deinit() catch @panic("CUDA teardown failed");
        const executor = owner.executor();
        try executor.execute(a, &provider, &output);
        try std.testing.expectEqual(@as(usize, 1), owner.stats.calls);
        try std.testing.expectEqual(@as(usize, 3), owner.stats.expanded_gpu_columns);
        try std.testing.expectEqual(@as(usize, 1), owner.stats.expanded_cpu_columns);
        try std.testing.expect(owner.stats.expansion_kernel_launches > 0);
        try std.testing.expectEqual(2 + owner.stats.expansion_kernel_launches, owner.stats.kernel_launches);
        try std.testing.expect(owner.stats.kernel_launches != 0 and owner.stats.h2d_bytes != 0 and owner.stats.d2h_bytes != 0);
        std.debug.print("CUDA_DEEP_RECEIPT {f}\n", .{std.json.fmt(owner.stats, .{})});
    } else try emulate(a, &provider, &plan, &output);
    for (expected.columns, output.columns) |want, got| try std.testing.expectEqualSlices(M, want, got);
}
fn unpack(value: anytype) Q {
    return Q.fromU32Unchecked(value.a, value.b, value.c, value.d);
}
fn emulate(a: std.mem.Allocator, p: *Provider, plan: *const Plan.Owned, out: *engine.secure_column.SecureColumnByCoords) !void {
    const source = try a.alloc(M, plan.source_words);
    defer a.free(source);
    for (plan.sources) |entry| {
        const target = source[entry.offset..][0 .. @as(usize, 1) << @intCast(entry.log)];
        if (entry.column.coefficient_values) |c| {
            const poly = try engine.poly.circle.poly.CircleCoefficients.initBorrowed(c);
            const eval = try poly.evaluate(a, core.poly.circle.canonic.CanonicCoset.new(entry.log).circleDomain());
            defer a.free(eval.values);
            @memcpy(target, eval.values);
        } else if (entry.column.log_size == 0) @memset(target, entry.column.values[0]) else @memcpy(target, entry.column.values);
    }
    const sample_points = try a.alloc(Point, p.prepared.sample_batches.len);
    defer a.free(sample_points);
    for (sample_points, p.prepared.sample_batches) |*point, batch| point.* = batch.point;
    for (0..p.domain_size) |row| {
        const point = p.domain.at(core.utils.bitReverseIndex(row, p.lifting_log_size));
        const inverses = try core.pcs.quotients.denominatorInverses(a, sample_points, point);
        defer a.free(inverses);
        var answer = Q.zero();
        for (plan.group_logs, 0..) |log, group| {
            const native_row = ((row >> @intCast(p.lifting_log_size - log + 1)) << 1) + (row & 1);
            var numerator = Q.zero();
            for (plan.terms[plan.group_offsets[group]..plan.group_offsets[group + 1]]) |term| {
                const input = plan.sources[term.source_index];
                const r = ((native_row >> @intCast(log - term.source_log_size + 1)) << 1) + (native_row & 1);
                const lines = plan.lines[term.term_index * 3 ..][0..3];
                numerator = numerator.add(unpack(lines[2]).mulM31(source[input.offset + r]).sub(unpack(lines[1])));
            }
            numerator = numerator.sub(unpack(plan.first[group]).mulM31(point.y));
            answer = answer.add(numerator.mulCM31(inverses[group]));
        }
        const words = answer.toM31Array();
        inline for (0..4) |coordinate| out.columns[coordinate][row] = words[coordinate];
    }
}

test "CUDA DEEP topology preserves every source/sample with compact inputs and exact resource caps" {
    try run(false);
}
