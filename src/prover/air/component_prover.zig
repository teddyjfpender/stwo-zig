const std = @import("std");
const m31 = @import("../../core/fields/m31.zig");
const qm31 = @import("../../core/fields/qm31.zig");
const pcs = @import("../../core/pcs/mod.zig");
const accumulation = @import("accumulation.zig");
const secure_column = @import("../secure_column.zig");

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
        const idx = ((position >> (@as(usize, @intCast(shift)) + 1)) << 1) + (position & 1);
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
    preprocessedColumnIndices: *const fn (ctx: *const anyopaque, allocator: std.mem.Allocator) anyerror![]usize,
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

    pub inline fn preprocessedColumnIndices(
        self: ComponentProver,
        allocator: std.mem.Allocator,
    ) anyerror![]usize {
        return self.vtable.preprocessedColumnIndices(self.ctx, allocator);
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
                    .preprocessedColumnIndices = preprocessedColumnIndices,
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

        fn preprocessedColumnIndices(_: *const anyopaque, allocator: std.mem.Allocator) ![]usize {
            return allocator.alloc(usize, 0);
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

    const trace = Trace{ .polys = TreeVec([]const Poly).initOwned(try alloc.alloc([]const Poly, 0)) };
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
}
