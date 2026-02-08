const std = @import("std");
const circle = @import("../../core/circle.zig");
const core_air_accumulation = @import("../../core/air/accumulation.zig");
const core_air_components = @import("../../core/air/components.zig");
const m31 = @import("../../core/fields/m31.zig");
const qm31 = @import("../../core/fields/qm31.zig");
const pcs = @import("../../core/pcs/mod.zig");
const accumulation = @import("accumulation.zig");
const secure_column = @import("../secure_column.zig");

const CirclePointQM31 = circle.CirclePointQM31;
const M31 = m31.M31;
const QM31 = qm31.QM31;
const TreeVec = pcs.TreeVec;
const SecureColumnByCoords = secure_column.SecureColumnByCoords;

pub const ComponentProverError = error{
    InvalidLogSize,
    InvalidColumnLength,
};

/// Trace column polynomial represented by its evaluation values.
pub const Poly = struct {
    log_size: u32,
    values: []const M31,

    pub fn validate(self: Poly) ComponentProverError!void {
        const expected = try checkedPow2(self.log_size);
        if (self.values.len != expected) return ComponentProverError.InvalidColumnLength;
    }

    pub fn valueAtLiftingPosition(
        self: Poly,
        lifting_log_size: u32,
        position: usize,
    ) ComponentProverError!M31 {
        try self.validate();
        if (self.log_size > lifting_log_size) return ComponentProverError.InvalidLogSize;

        const lifting_size = try checkedPow2(lifting_log_size);
        if (position >= lifting_size) return ComponentProverError.InvalidColumnLength;

        const shift = lifting_log_size - self.log_size;
        if (shift >= @bitSizeOf(usize)) return ComponentProverError.InvalidLogSize;
        const shift_amt: std.math.Log2Int(usize) = @intCast(shift + 1);
        const idx = ((position >> shift_amt) << 1) + (position & 1);
        if (idx >= self.values.len) return ComponentProverError.InvalidColumnLength;
        return self.values[idx];
    }
};

pub const Trace = struct {
    polys: TreeVec([]const Poly),
};

pub const ComponentProverVTable = struct {
    nConstraints: *const fn (ctx: *const anyopaque) usize,
    maxConstraintLogDegreeBound: *const fn (ctx: *const anyopaque) u32,
    traceLogDegreeBounds: *const fn (ctx: *const anyopaque, allocator: std.mem.Allocator) anyerror!core_air_components.TraceLogDegreeBounds,
    maskPoints: *const fn (
        ctx: *const anyopaque,
        allocator: std.mem.Allocator,
        point: CirclePointQM31,
        max_log_degree_bound: u32,
    ) anyerror!core_air_components.MaskPoints,
    preprocessedColumnIndices: *const fn (ctx: *const anyopaque, allocator: std.mem.Allocator) anyerror![]usize,
    evaluateConstraintQuotientsAtPoint: *const fn (
        ctx: *const anyopaque,
        point: CirclePointQM31,
        mask: *const core_air_components.MaskValues,
        evaluation_accumulator: *core_air_accumulation.PointEvaluationAccumulator,
        max_log_degree_bound: u32,
    ) anyerror!void,
    evaluateConstraintQuotientsOnDomain: *const fn (
        ctx: *const anyopaque,
        trace: *const Trace,
        evaluation_accumulator: *accumulation.DomainEvaluationAccumulator,
    ) anyerror!void,
};

pub const ComponentProver = struct {
    ctx: *const anyopaque,
    vtable: *const ComponentProverVTable,

    pub inline fn nConstraints(self: ComponentProver) usize {
        return self.vtable.nConstraints(self.ctx);
    }

    pub inline fn maxConstraintLogDegreeBound(self: ComponentProver) u32 {
        return self.vtable.maxConstraintLogDegreeBound(self.ctx);
    }

    pub inline fn traceLogDegreeBounds(
        self: ComponentProver,
        allocator: std.mem.Allocator,
    ) anyerror!core_air_components.TraceLogDegreeBounds {
        return self.vtable.traceLogDegreeBounds(self.ctx, allocator);
    }

    pub inline fn maskPoints(
        self: ComponentProver,
        allocator: std.mem.Allocator,
        point: CirclePointQM31,
        max_log_degree_bound: u32,
    ) anyerror!core_air_components.MaskPoints {
        return self.vtable.maskPoints(
            self.ctx,
            allocator,
            point,
            max_log_degree_bound,
        );
    }

    pub inline fn preprocessedColumnIndices(
        self: ComponentProver,
        allocator: std.mem.Allocator,
    ) anyerror![]usize {
        return self.vtable.preprocessedColumnIndices(self.ctx, allocator);
    }

    pub inline fn evaluateConstraintQuotientsAtPoint(
        self: ComponentProver,
        point: CirclePointQM31,
        mask: *const core_air_components.MaskValues,
        evaluation_accumulator: *core_air_accumulation.PointEvaluationAccumulator,
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

    pub inline fn evaluateConstraintQuotientsOnDomain(
        self: ComponentProver,
        trace: *const Trace,
        evaluation_accumulator: *accumulation.DomainEvaluationAccumulator,
    ) anyerror!void {
        return self.vtable.evaluateConstraintQuotientsOnDomain(
            self.ctx,
            trace,
            evaluation_accumulator,
        );
    }
};

pub const ComponentProvers = struct {
    components: []const ComponentProver,
    n_preprocessed_columns: usize,

    pub const ComponentsView = struct {
        prover_components: []ComponentProver,
        core_components: []core_air_components.Component,
        n_preprocessed_columns: usize,

        pub fn deinit(self: *ComponentsView, allocator: std.mem.Allocator) void {
            allocator.free(self.core_components);
            allocator.free(self.prover_components);
            self.* = undefined;
        }

        pub fn asCore(self: ComponentsView) core_air_components.Components {
            return .{
                .components = self.core_components,
                .n_preprocessed_columns = self.n_preprocessed_columns,
            };
        }
    };

    pub fn componentsView(
        self: ComponentProvers,
        allocator: std.mem.Allocator,
    ) !ComponentsView {
        const prover_components = try allocator.dupe(ComponentProver, self.components);
        errdefer allocator.free(prover_components);

        const core_components = try allocator.alloc(
            core_air_components.Component,
            prover_components.len,
        );
        errdefer allocator.free(core_components);

        for (prover_components, 0..) |_, i| {
            core_components[i] = .{
                .ctx = &prover_components[i],
                .vtable = &CORE_COMPONENT_ADAPTER_VTABLE,
            };
        }

        return .{
            .prover_components = prover_components,
            .core_components = core_components,
            .n_preprocessed_columns = self.n_preprocessed_columns,
        };
    }

    pub fn compositionLogDegreeBound(self: ComponentProvers) u32 {
        var max_bound: u32 = 0;
        for (self.components) |component| {
            max_bound = @max(max_bound, component.maxConstraintLogDegreeBound());
        }
        return max_bound;
    }

    pub fn totalConstraints(self: ComponentProvers) usize {
        var total: usize = 0;
        for (self.components) |component| total += component.nConstraints();
        return total;
    }

    pub fn computeCompositionEvaluation(
        self: ComponentProvers,
        allocator: std.mem.Allocator,
        random_coeff: QM31,
        trace: *const Trace,
    ) anyerror!SecureColumnByCoords {
        var accumulator = try accumulation.DomainEvaluationAccumulator.init(
            allocator,
            random_coeff,
            self.compositionLogDegreeBound(),
            self.totalConstraints(),
        );
        defer accumulator.deinit();

        for (self.components) |component| {
            try component.evaluateConstraintQuotientsOnDomain(trace, &accumulator);
        }
        return accumulator.finalize();
    }
};

const CORE_COMPONENT_ADAPTER_VTABLE = core_air_components.ComponentVTable{
    .nConstraints = coreAdapterNConstraints,
    .maxConstraintLogDegreeBound = coreAdapterMaxConstraintLogDegreeBound,
    .traceLogDegreeBounds = coreAdapterTraceLogDegreeBounds,
    .maskPoints = coreAdapterMaskPoints,
    .preprocessedColumnIndices = coreAdapterPreprocessedColumnIndices,
    .evaluateConstraintQuotientsAtPoint = coreAdapterEvaluateConstraintQuotientsAtPoint,
};

fn coreAdapterCast(ctx: *const anyopaque) *const ComponentProver {
    return @ptrCast(@alignCast(ctx));
}

fn coreAdapterNConstraints(ctx: *const anyopaque) usize {
    return coreAdapterCast(ctx).nConstraints();
}

fn coreAdapterMaxConstraintLogDegreeBound(ctx: *const anyopaque) u32 {
    return coreAdapterCast(ctx).maxConstraintLogDegreeBound();
}

fn coreAdapterTraceLogDegreeBounds(
    ctx: *const anyopaque,
    allocator: std.mem.Allocator,
) anyerror!core_air_components.TraceLogDegreeBounds {
    return coreAdapterCast(ctx).traceLogDegreeBounds(allocator);
}

fn coreAdapterMaskPoints(
    ctx: *const anyopaque,
    allocator: std.mem.Allocator,
    point: CirclePointQM31,
    max_log_degree_bound: u32,
) anyerror!core_air_components.MaskPoints {
    return coreAdapterCast(ctx).maskPoints(
        allocator,
        point,
        max_log_degree_bound,
    );
}

fn coreAdapterPreprocessedColumnIndices(
    ctx: *const anyopaque,
    allocator: std.mem.Allocator,
) anyerror![]usize {
    return coreAdapterCast(ctx).preprocessedColumnIndices(allocator);
}

fn coreAdapterEvaluateConstraintQuotientsAtPoint(
    ctx: *const anyopaque,
    point: CirclePointQM31,
    mask: *const core_air_components.MaskValues,
    evaluation_accumulator: *core_air_accumulation.PointEvaluationAccumulator,
    max_log_degree_bound: u32,
) anyerror!void {
    return coreAdapterCast(ctx).evaluateConstraintQuotientsAtPoint(
        point,
        mask,
        evaluation_accumulator,
        max_log_degree_bound,
    );
}

fn checkedPow2(log_size: u32) ComponentProverError!usize {
    if (log_size >= @bitSizeOf(usize)) return ComponentProverError.InvalidLogSize;
    return @as(usize, 1) << @intCast(log_size);
}

test "prover air component prover: poly lifting index" {
    const values = [_]M31{
        M31.fromCanonical(10),
        M31.fromCanonical(20),
        M31.fromCanonical(30),
        M31.fromCanonical(40),
    };
    const poly = Poly{ .log_size = 2, .values = values[0..] };
    try std.testing.expect((try poly.valueAtLiftingPosition(2, 3)).eql(values[3]));

    const lifted = [_]M31{
        values[0],
        values[1],
        values[0],
        values[1],
        values[2],
        values[3],
        values[2],
        values[3],
    };
    var i: usize = 0;
    while (i < lifted.len) : (i += 1) {
        try std.testing.expect((try poly.valueAtLiftingPosition(3, i)).eql(lifted[i]));
    }
}

test "prover air component prover: composition accumulation" {
    const alloc = std.testing.allocator;

    const Mock = struct {
        max_log_size: u32,

        fn asComponent(self: *const @This()) ComponentProver {
            return .{
                .ctx = self,
                .vtable = &.{
                    .nConstraints = nConstraints,
                    .maxConstraintLogDegreeBound = maxConstraintLogDegreeBound,
                    .traceLogDegreeBounds = traceLogDegreeBounds,
                    .maskPoints = maskPoints,
                    .preprocessedColumnIndices = preprocessedColumnIndices,
                    .evaluateConstraintQuotientsAtPoint = evaluateConstraintQuotientsAtPoint,
                    .evaluateConstraintQuotientsOnDomain = evaluateConstraintQuotientsOnDomain,
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
            return cast(ctx).max_log_size;
        }

        fn traceLogDegreeBounds(
            ctx: *const anyopaque,
            allocator: std.mem.Allocator,
        ) !core_air_components.TraceLogDegreeBounds {
            const self = cast(ctx);
            const preprocessed = try allocator.alloc(u32, 0);
            const main = try allocator.dupe(u32, &[_]u32{self.max_log_size});
            return core_air_components.TraceLogDegreeBounds.initOwned(
                try allocator.dupe([]u32, &[_][]u32{ preprocessed, main }),
            );
        }

        fn maskPoints(
            _: *const anyopaque,
            allocator: std.mem.Allocator,
            point: CirclePointQM31,
            _: u32,
        ) !core_air_components.MaskPoints {
            const pp_cols = try allocator.alloc([]CirclePointQM31, 0);
            const main_col = try allocator.alloc(CirclePointQM31, 1);
            main_col[0] = point;
            const main_cols = try allocator.dupe([]CirclePointQM31, &[_][]CirclePointQM31{main_col});
            return core_air_components.MaskPoints.initOwned(
                try allocator.dupe([][]CirclePointQM31, &[_][][]CirclePointQM31{
                    pp_cols,
                    main_cols,
                }),
            );
        }

        fn preprocessedColumnIndices(_: *const anyopaque, allocator: std.mem.Allocator) ![]usize {
            return allocator.alloc(usize, 0);
        }

        fn evaluateConstraintQuotientsAtPoint(
            _: *const anyopaque,
            _: CirclePointQM31,
            _: *const core_air_components.MaskValues,
            evaluation_accumulator: *core_air_accumulation.PointEvaluationAccumulator,
            _: u32,
        ) !void {
            evaluation_accumulator.accumulate(QM31.fromU32Unchecked(13, 0, 0, 0));
        }

        fn evaluateConstraintQuotientsOnDomain(
            _: *const anyopaque,
            _: *const Trace,
            evaluation_accumulator: *accumulation.DomainEvaluationAccumulator,
        ) !void {
            const values = [_]QM31{
                QM31.fromU32Unchecked(1, 0, 0, 0),
                QM31.fromU32Unchecked(2, 0, 0, 0),
                QM31.fromU32Unchecked(3, 0, 0, 0),
                QM31.fromU32Unchecked(4, 0, 0, 0),
            };
            var col = try SecureColumnByCoords.fromSecureSlice(std.testing.allocator, values[0..]);
            defer col.deinit(std.testing.allocator);
            try evaluation_accumulator.accumulateColumn(2, &col);
        }
    };

    const mock = Mock{ .max_log_size = 2 };
    const components_arr = [_]ComponentProver{mock.asComponent()};
    const component_provers = ComponentProvers{
        .components = components_arr[0..],
        .n_preprocessed_columns = 0,
    };

    var trace = Trace{ .polys = TreeVec([]const Poly).initOwned(try alloc.alloc([]const Poly, 0)) };
    defer trace.polys.deinit(alloc);

    var combined = try component_provers.computeCompositionEvaluation(
        alloc,
        QM31.fromU32Unchecked(7, 0, 0, 0),
        &trace,
    );
    defer combined.deinit(alloc);

    const out = try combined.toVec(alloc);
    defer alloc.free(out);
    try std.testing.expectEqual(@as(usize, 4), out.len);
    try std.testing.expect(out[0].eql(QM31.fromU32Unchecked(1, 0, 0, 0)));
    try std.testing.expect(out[3].eql(QM31.fromU32Unchecked(4, 0, 0, 0)));

    var view = try component_provers.componentsView(alloc);
    defer view.deinit(alloc);

    const components = view.asCore();
    try std.testing.expectEqual(@as(usize, 1), components.components.len);
    try std.testing.expectEqual(@as(usize, 0), components.n_preprocessed_columns);

    var mask = try components.maskPoints(
        alloc,
        circle.SECURE_FIELD_CIRCLE_GEN,
        mock.max_log_size,
        true,
    );
    defer mask.deinitDeep(alloc);
    try std.testing.expectEqual(@as(usize, 2), mask.items.len);

    var mask_values = core_air_components.MaskValues.initOwned(try alloc.alloc([][]QM31, 0));
    defer mask_values.deinitDeep(alloc);
    const eval = try components.evalCompositionPolynomialAtPoint(
        circle.SECURE_FIELD_CIRCLE_GEN,
        &mask_values,
        QM31.fromU32Unchecked(5, 0, 0, 0),
        mock.max_log_size,
    );
    try std.testing.expect(eval.eql(QM31.fromU32Unchecked(13, 0, 0, 0)));
}
