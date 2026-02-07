const std = @import("std");
const accumulation = @import("accumulation.zig");
const circle = @import("../circle.zig");
const qm31 = @import("../fields/qm31.zig");
const pcs = @import("../pcs/mod.zig");
const pcs_utils = @import("../pcs/utils.zig");
const verifier_types = @import("../verifier_types.zig");

const QM31 = qm31.QM31;
const Point = circle.CirclePointQM31;

pub const TraceLogDegreeBounds = pcs.TreeVec([]u32);
pub const MaskPoints = pcs.TreeVec([][]Point);
pub const MaskValues = pcs.TreeVec([][]QM31);

pub const Error = error{
    MissingPreprocessedTree,
    PreprocessedColumnSizeMismatch,
    PreprocessedColumnSizeMissing,
};

pub const ComponentVTable = struct {
    nConstraints: *const fn (ctx: *const anyopaque) usize,
    maxConstraintLogDegreeBound: *const fn (ctx: *const anyopaque) u32,
    traceLogDegreeBounds: *const fn (ctx: *const anyopaque, allocator: std.mem.Allocator) anyerror!TraceLogDegreeBounds,
    maskPoints: *const fn (ctx: *const anyopaque, allocator: std.mem.Allocator, point: Point, max_log_degree_bound: u32) anyerror!MaskPoints,
    preprocessedColumnIndices: *const fn (ctx: *const anyopaque, allocator: std.mem.Allocator) anyerror![]usize,
    evaluateConstraintQuotientsAtPoint: *const fn (
        ctx: *const anyopaque,
        point: Point,
        mask: *const MaskValues,
        evaluation_accumulator: *accumulation.PointEvaluationAccumulator,
        max_log_degree_bound: u32,
    ) anyerror!void,
};

pub const Component = struct {
    ctx: *const anyopaque,
    vtable: *const ComponentVTable,

    pub inline fn nConstraints(self: Component) usize {
        return self.vtable.nConstraints(self.ctx);
    }

    pub inline fn maxConstraintLogDegreeBound(self: Component) u32 {
        return self.vtable.maxConstraintLogDegreeBound(self.ctx);
    }

    pub inline fn traceLogDegreeBounds(self: Component, allocator: std.mem.Allocator) anyerror!TraceLogDegreeBounds {
        return self.vtable.traceLogDegreeBounds(self.ctx, allocator);
    }

    pub inline fn maskPoints(self: Component, allocator: std.mem.Allocator, point: Point, max_log_degree_bound: u32) anyerror!MaskPoints {
        return self.vtable.maskPoints(self.ctx, allocator, point, max_log_degree_bound);
    }

    pub inline fn preprocessedColumnIndices(self: Component, allocator: std.mem.Allocator) anyerror![]usize {
        return self.vtable.preprocessedColumnIndices(self.ctx, allocator);
    }

    pub inline fn evaluateConstraintQuotientsAtPoint(
        self: Component,
        point: Point,
        mask: *const MaskValues,
        evaluation_accumulator: *accumulation.PointEvaluationAccumulator,
        max_log_degree_bound: u32,
    ) anyerror!void {
        return self.vtable.evaluateConstraintQuotientsAtPoint(
            self.ctx,
            point,
            mask,
            evaluation_accumulator,
            max_log_degree_bound,
        );
    }
};

pub const Components = struct {
    components: []const Component,
    n_preprocessed_columns: usize,

    pub fn compositionLogDegreeBound(self: Components) u32 {
        var max_bound: u32 = 0;
        for (self.components) |c| {
            max_bound = @max(max_bound, c.maxConstraintLogDegreeBound());
        }
        return max_bound;
    }

    pub fn maskPoints(
        self: Components,
        allocator: std.mem.Allocator,
        point: Point,
        max_log_degree_bound: u32,
        include_all_preprocessed_columns: bool,
    ) !MaskPoints {
        var all_masks = std.ArrayList(MaskPoints).init(allocator);
        defer all_masks.deinit();
        for (self.components) |component| {
            try all_masks.append(try component.maskPoints(allocator, point, max_log_degree_bound));
        }
        defer for (all_masks.items) |*tv| tv.deinitDeep(allocator);

        var mask_points = try pcs_utils.concatCols([]Point, allocator, all_masks.items);
        errdefer mask_points.deinitDeep(allocator);

        if (verifier_types.PREPROCESSED_TRACE_IDX >= mask_points.items.len) return Error.MissingPreprocessedTree;

        var new_preprocessed = try allocator.alloc([]Point, self.n_preprocessed_columns);
        var init_count: usize = 0;
        errdefer {
            var i: usize = 0;
            while (i < init_count) : (i += 1) allocator.free(new_preprocessed[i]);
            allocator.free(new_preprocessed);
        }

        if (include_all_preprocessed_columns) {
            for (new_preprocessed) |*col| {
                col.* = try allocator.alloc(Point, 1);
                col.*[0] = point;
                init_count += 1;
            }
        } else {
            for (new_preprocessed) |*col| {
                col.* = try allocator.alloc(Point, 0);
                init_count += 1;
            }
            for (self.components) |component| {
                const pre = try component.preprocessedColumnIndices(allocator);
                defer allocator.free(pre);
                for (pre) |idx| {
                    allocator.free(new_preprocessed[idx]);
                    new_preprocessed[idx] = try allocator.alloc(Point, 1);
                    new_preprocessed[idx][0] = point;
                }
            }
        }

        freeNestedSlice([]Point, allocator, mask_points.items[verifier_types.PREPROCESSED_TRACE_IDX]);
        mask_points.items[verifier_types.PREPROCESSED_TRACE_IDX] = new_preprocessed;
        return mask_points;
    }

    pub fn evalCompositionPolynomialAtPoint(
        self: Components,
        point: Point,
        mask_values: *const MaskValues,
        random_coeff: QM31,
        max_log_degree_bound: u32,
    ) !QM31 {
        var evaluation_accumulator = accumulation.PointEvaluationAccumulator.init(random_coeff);
        for (self.components) |component| {
            try component.evaluateConstraintQuotientsAtPoint(
                point,
                mask_values,
                &evaluation_accumulator,
                max_log_degree_bound,
            );
        }
        return evaluation_accumulator.finalize();
    }

    pub fn columnLogSizes(self: Components, allocator: std.mem.Allocator) !TraceLogDegreeBounds {
        var preprocessed_sizes = try allocator.alloc(u32, self.n_preprocessed_columns);
        var preprocessed_sizes_moved = false;
        errdefer if (!preprocessed_sizes_moved) allocator.free(preprocessed_sizes);
        @memset(preprocessed_sizes, 0);

        var visited = try allocator.alloc(bool, self.n_preprocessed_columns);
        defer allocator.free(visited);
        @memset(visited, false);

        var all_sizes = std.ArrayList(TraceLogDegreeBounds).init(allocator);
        defer all_sizes.deinit();
        for (self.components) |component| {
            try all_sizes.append(try component.traceLogDegreeBounds(allocator));
        }
        defer for (all_sizes.items) |*tv| tv.deinitDeep(allocator);

        for (self.components, all_sizes.items) |component, trace_sizes| {
            if (verifier_types.PREPROCESSED_TRACE_IDX >= trace_sizes.items.len) return Error.MissingPreprocessedTree;
            const pre = try component.preprocessedColumnIndices(allocator);
            defer allocator.free(pre);
            const logs = trace_sizes.items[verifier_types.PREPROCESSED_TRACE_IDX];

            const n = @min(pre.len, logs.len);
            var i: usize = 0;
            while (i < n) : (i += 1) {
                const column_index = pre[i];
                const log_size = logs[i];
                if (visited[column_index]) {
                    if (preprocessed_sizes[column_index] != log_size) {
                        return Error.PreprocessedColumnSizeMismatch;
                    }
                } else {
                    preprocessed_sizes[column_index] = log_size;
                    visited[column_index] = true;
                }
            }
        }

        for (visited) |v| {
            if (!v) return Error.PreprocessedColumnSizeMissing;
        }

        var out = try pcs_utils.concatCols(u32, allocator, all_sizes.items);
        errdefer out.deinitDeep(allocator);
        if (verifier_types.PREPROCESSED_TRACE_IDX >= out.items.len) return Error.MissingPreprocessedTree;

        allocator.free(out.items[verifier_types.PREPROCESSED_TRACE_IDX]);
        out.items[verifier_types.PREPROCESSED_TRACE_IDX] = preprocessed_sizes;
        preprocessed_sizes_moved = true;
        return out;
    }
};

fn freeNestedSlice(comptime T: type, allocator: std.mem.Allocator, slice: []T) void {
    const ti = @typeInfo(T);
    if (ti == .pointer and ti.pointer.size == .slice) {
        const Child = ti.pointer.child;
        for (slice) |inner| freeNestedSlice(Child, allocator, inner);
    }
    allocator.free(slice);
}

test "air components: orchestration" {
    const alloc = std.testing.allocator;

    const Mock = struct {
        max_bound: u32,
        eval_value: QM31,
        preprocessed_idx: []const usize,
        preprocessed_sizes: []const u32,

        fn asComponent(self: *const @This()) Component {
            return .{
                .ctx = self,
                .vtable = &.{
                    .nConstraints = nConstraints,
                    .maxConstraintLogDegreeBound = maxConstraintLogDegreeBound,
                    .traceLogDegreeBounds = traceLogDegreeBounds,
                    .maskPoints = maskPoints,
                    .preprocessedColumnIndices = preprocessedColumnIndices,
                    .evaluateConstraintQuotientsAtPoint = evaluateConstraintQuotientsAtPoint,
                },
            };
        }

        fn cast(ctx: *const anyopaque) *const @This() {
            return @ptrCast(@alignCast(ctx));
        }

        fn nConstraints(_: *const anyopaque) usize {
            return 1;
        }

        fn maxConstraintLogDegreeBound(ctx: *const anyopaque) u32 {
            return cast(ctx).max_bound;
        }

        fn traceLogDegreeBounds(ctx: *const anyopaque, allocator: std.mem.Allocator) !TraceLogDegreeBounds {
            const self = cast(ctx);
            const pp = try allocator.dupe(u32, self.preprocessed_sizes);
            const main = try allocator.dupe(u32, &[_]u32{self.max_bound});
            const outer = try allocator.dupe([]u32, &[_][]u32{ pp, main });
            return TraceLogDegreeBounds.initOwned(outer);
        }

        fn maskPoints(_: *const anyopaque, allocator: std.mem.Allocator, point: Point, _: u32) !MaskPoints {
            const pp_cols = try allocator.alloc([]Point, 0);
            const main_col_points = try allocator.alloc(Point, 1);
            main_col_points[0] = point;
            const main_cols = try allocator.dupe([]Point, &[_][]Point{main_col_points});
            const outer = try allocator.dupe([][]Point, &[_][][]Point{ pp_cols, main_cols });
            return MaskPoints.initOwned(outer);
        }

        fn preprocessedColumnIndices(ctx: *const anyopaque, allocator: std.mem.Allocator) ![]usize {
            return allocator.dupe(usize, cast(ctx).preprocessed_idx);
        }

        fn evaluateConstraintQuotientsAtPoint(
            ctx: *const anyopaque,
            _: Point,
            _: *const MaskValues,
            evaluation_accumulator: *accumulation.PointEvaluationAccumulator,
            _: u32,
        ) !void {
            evaluation_accumulator.accumulate(cast(ctx).eval_value);
        }
    };

    const comp0 = Mock{
        .max_bound = 7,
        .eval_value = QM31.fromBase(QM31.fromU32Unchecked(1, 0, 0, 0).tryIntoM31() catch unreachable),
        .preprocessed_idx = &[_]usize{0},
        .preprocessed_sizes = &[_]u32{5},
    };
    const comp1 = Mock{
        .max_bound = 9,
        .eval_value = QM31.fromBase(QM31.fromU32Unchecked(2, 0, 0, 0).tryIntoM31() catch unreachable),
        .preprocessed_idx = &[_]usize{0},
        .preprocessed_sizes = &[_]u32{5},
    };

    const components_arr = [_]Component{ comp0.asComponent(), comp1.asComponent() };
    const components = Components{
        .components = components_arr[0..],
        .n_preprocessed_columns = 1,
    };

    try std.testing.expectEqual(@as(u32, 9), components.compositionLogDegreeBound());

    var mask_values = MaskValues.initOwned(try alloc.alloc([][]QM31, 0));
    defer mask_values.deinitDeep(alloc);
    const alpha = QM31.fromU32Unchecked(3, 0, 0, 0);
    const point = circle.SECURE_FIELD_CIRCLE_GEN;
    const eval = try components.evalCompositionPolynomialAtPoint(point, &mask_values, alpha, 10);
    const expected = QM31.fromU32Unchecked(1, 0, 0, 0).mul(alpha).add(QM31.fromU32Unchecked(2, 0, 0, 0));
    try std.testing.expect(eval.eql(expected));

    var column_sizes = try components.columnLogSizes(alloc);
    defer column_sizes.deinitDeep(alloc);
    try std.testing.expectEqual(@as(usize, 2), column_sizes.items.len);
    try std.testing.expectEqual(@as(usize, 1), column_sizes.items[verifier_types.PREPROCESSED_TRACE_IDX].len);
    try std.testing.expectEqual(@as(u32, 5), column_sizes.items[verifier_types.PREPROCESSED_TRACE_IDX][0]);

    var mask = try components.maskPoints(alloc, point, 10, true);
    defer mask.deinitDeep(alloc);
    try std.testing.expectEqual(@as(usize, 1), mask.items[verifier_types.PREPROCESSED_TRACE_IDX][0].len);
    try std.testing.expect(mask.items[verifier_types.PREPROCESSED_TRACE_IDX][0][0].eql(point));
}
