const std = @import("std");
const circle = @import("stwo_core").circle;
const core_air_accumulation = @import("stwo_core").air.accumulation;
const core_air_components = @import("stwo_core").air.components;
const m31 = @import("stwo_core").fields.m31;
const qm31 = @import("stwo_core").fields.qm31;
const pcs = @import("stwo_core").pcs;
const accumulation = @import("accumulation.zig");
const composition_execution = @import("composition_execution.zig");
const component_parallel = @import("component_parallel.zig");
const component_trace = @import("component_trace.zig");
const device_composition = @import("device_composition.zig");
const prepared_domain = @import("prepared_domain.zig");
const prover_twiddles = @import("../poly/twiddles.zig");
const secure_column = @import("../secure_column.zig");
const work_pool_mod = @import("../work_pool.zig");

const CirclePointQM31 = circle.CirclePointQM31;
const M31 = m31.M31;
const QM31 = qm31.QM31;
const TreeVec = pcs.TreeVec;
const SecureColumnByCoords = secure_column.SecureColumnByCoords;
const M31TwiddleTree = prover_twiddles.TwiddleTree([]const M31);

pub const ComponentProverError = component_trace.Error;
pub const Poly = component_trace.Poly;
pub const Trace = component_trace.Trace;

/// Backend-neutral base-field polynomial program exported by a frontend from
/// the same typed builder used by its reference AIR evaluator. Node order is
/// topological: every operand names an earlier node. `column` values address
/// the capability's ordered input columns.
pub const BasePolynomialOp = enum(u8) { constant, column, add, sub, mul, neg };

pub const BasePolynomialNode = struct {
    op: BasePolynomialOp,
    lhs: u32 = 0,
    rhs: u32 = 0,
    value: u32 = 0,
};

pub const OwnedBasePolynomialProgram = struct {
    allocator: std.mem.Allocator,
    nodes: []BasePolynomialNode,
    roots: []u32,
    column_count: usize,

    pub fn deinit(self: *OwnedBasePolynomialProgram) void {
        self.allocator.free(self.roots);
        self.allocator.free(self.nodes);
        self.* = undefined;
    }

    pub fn validate(self: OwnedBasePolynomialProgram) !void {
        if (self.column_count == 0 or self.nodes.len == 0 or self.roots.len == 0)
            return error.InvalidBasePolynomialProgram;
        for (self.nodes, 0..) |node, index| switch (node.op) {
            .constant => {},
            .column => if (node.value >= self.column_count)
                return error.InvalidBasePolynomialProgram,
            .add, .sub, .mul => if (node.lhs >= index or node.rhs >= index)
                return error.InvalidBasePolynomialProgram,
            .neg => if (node.lhs >= index)
                return error.InvalidBasePolynomialProgram,
        };
        for (self.roots) |root| if (root >= self.nodes.len)
            return error.InvalidBasePolynomialProgram;
    }
};

/// A committed base-polynomial component that a backend may evaluate from the
/// proof's own residency handles. The selector is the final program input;
/// preceding inputs are the contiguous main-column block. The exporter is
/// invoked only during proving and must derive its program from the production
/// evaluator rather than maintain an independent constraint transcription.
pub const BasePolynomialCapabilityV1 = struct {
    program_id: u64,
    trace_log_size: u32,
    selector_tree_index: usize,
    selector_column: usize,
    main_tree_index: usize,
    first_main_column: usize,
    main_column_count: usize,
    export_program: *const fn (
        ctx: *const anyopaque,
        allocator: std.mem.Allocator,
    ) anyerror!OwnedBasePolynomialProgram,
};

pub const MAX_LOOKUP_POLYNOMIAL_ARITY: usize = 32;

pub const LookupPolynomialEntry = struct {
    numerator: u32,
    values: [MAX_LOOKUP_POLYNOMIAL_ARITY]u32 = undefined,
    arity: u8,
};

pub const OwnedLookupPolynomialProgram = struct {
    allocator: std.mem.Allocator,
    nodes: []BasePolynomialNode,
    entries: []LookupPolynomialEntry,
    column_count: usize,
    batch_size: usize,

    pub fn deinit(self: *OwnedLookupPolynomialProgram) void {
        self.allocator.free(self.entries);
        self.allocator.free(self.nodes);
        self.* = undefined;
    }

    pub fn batchCount(self: OwnedLookupPolynomialProgram) usize {
        return (self.entries.len + self.batch_size - 1) / self.batch_size;
    }

    pub fn parameterCount(self: OwnedLookupPolynomialProgram) usize {
        var count = self.batchCount();
        for (self.entries) |entry| count += 1 + entry.arity;
        return count;
    }

    pub fn validate(self: OwnedLookupPolynomialProgram) !void {
        if (self.column_count == 0 or self.nodes.len == 0 or
            self.entries.len == 0 or (self.batch_size != 1 and self.batch_size != 2))
            return error.InvalidLookupPolynomialProgram;
        for (self.nodes, 0..) |node, index| switch (node.op) {
            .constant => {},
            .column => if (node.value >= self.column_count)
                return error.InvalidLookupPolynomialProgram,
            .add, .sub, .mul => if (node.lhs >= index or node.rhs >= index)
                return error.InvalidLookupPolynomialProgram,
            .neg => if (node.lhs >= index)
                return error.InvalidLookupPolynomialProgram,
        };
        for (self.entries) |entry| {
            if (entry.arity == 0 or entry.arity > MAX_LOOKUP_POLYNOMIAL_ARITY or
                entry.numerator >= self.nodes.len)
                return error.InvalidLookupPolynomialProgram;
            for (entry.values[0..entry.arity]) |value| if (value >= self.nodes.len)
                return error.InvalidLookupPolynomialProgram;
        }
    }
};

/// Pairs-batched LogUp transition constraints whose base tuple expressions are
/// exported from a production typed builder. Parameter order is canonical:
/// for every entry, `(z, alpha^0, ..., alpha^(arity-1))`, followed by one
/// claimed sum per batch.
pub const LookupPolynomialCapabilityV1 = struct {
    program_id: u64,
    trace_log_size: u32,
    selector_tree_index: usize,
    selector_column: usize,
    main_tree_index: usize,
    first_main_column: usize,
    main_column_count: usize,
    interaction_tree_index: usize,
    first_interaction_column: usize,
    interaction_column_count: usize,
    export_program: *const fn (
        ctx: *const anyopaque,
        allocator: std.mem.Allocator,
    ) anyerror!OwnedLookupPolynomialProgram,
    export_parameters: *const fn (
        ctx: *const anyopaque,
        allocator: std.mem.Allocator,
    ) anyerror![]QM31,
};

/// Reviewed semantic contracts that a backend may accelerate without
/// identifying a workload or trusting a coincidental vtable address. Each
/// variant names the complete AIR relation implemented by the accelerated
/// kernel; unmarked components always use the reference evaluator.
pub const BackendCompositionCapability = union(enum) {
    /// For one trace tree with columns `[a, b, c, ...]`, contributes one
    /// constraint per consecutive triple: `c - (a^2 + b^2)`, in canonical
    /// component constraint order, divided by the trace-coset vanishing
    /// polynomial.
    quadratic_sum_squares_v1: struct {
        trace_tree_index: usize,
        first_column: usize,
    },
    /// Direct base-field constraints exported from the frontend's production
    /// typed AIR builder. Random-coefficient order and vanishing denominators
    /// remain owned by the generic prover.
    base_polynomial_v1: BasePolynomialCapabilityV1,
    /// Pairs-batched LogUp transition constraints over production-exported
    /// base tuple expressions and committed secure cumulative columns.
    lookup_polynomial_v1: LookupPolynomialCapabilityV1,
};

pub const ComponentProverVTable = struct {
    nConstraints: *const fn (ctx: *const anyopaque) usize,
    maxConstraintLogDegreeBound: *const fn (ctx: *const anyopaque) u32,
    compositionLogSplit: ?*const fn (ctx: *const anyopaque) u32 = null,
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
    backend_composition_capability: ?BackendCompositionCapability = null,
    /// Optional coordinator-prepared, allocation-free domain evaluator.
    /// Structured composition scheduling is activated only when every
    /// component in the stage exposes this capability.
    prepare_domain_evaluator: ?*const fn (
        ctx: *const anyopaque,
        allocator: std.mem.Allocator,
        trace: *const Trace,
        evaluation_accumulator: *accumulation.DomainEvaluationAccumulator,
    ) anyerror!prepared_domain.PreparedDomainEvaluation = null,
    /// Optional caller-owned domain split. The composition scheduler invokes
    /// at most one such evaluator while ordinary component jobs drain from the
    /// same bounded pool, so implementations may enqueue row tasks safely.
    domain_parallel_evaluator: ?*const fn (
        ctx: *const anyopaque,
        trace: *const Trace,
        evaluation_accumulator: *accumulation.DomainEvaluationAccumulator,
        pool: *work_pool_mod.WorkPool,
    ) anyerror!void = null,
    /// When set, every component carrying this flag is evaluated in a
    /// breadth-first pool phase instead of being launched as a leaf job. This
    /// avoids nested pool waits for AIRs whose few large components all need
    /// row-level parallelism. The default retains the component-parallel
    /// scheduler used by Cairo and other heterogeneous frontends.
    pool_exclusive_domain: bool = false,

    pub inline fn nConstraints(self: ComponentProver) usize {
        return self.vtable.nConstraints(self.ctx);
    }

    pub inline fn maxConstraintLogDegreeBound(self: ComponentProver) u32 {
        return self.vtable.maxConstraintLogDegreeBound(self.ctx);
    }

    pub inline fn compositionLogSplit(self: ComponentProver) u32 {
        const get = self.vtable.compositionLogSplit orelse
            return @import("stwo_core").verifier_types.COMPOSITION_LOG_SPLIT;
        return get(self.ctx);
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

    pub inline fn evaluateConstraintQuotientsOnDomainParallel(
        self: ComponentProver,
        trace: *const Trace,
        evaluation_accumulator: *accumulation.DomainEvaluationAccumulator,
        pool: *work_pool_mod.WorkPool,
    ) anyerror!void {
        const evaluate = self.domain_parallel_evaluator orelse
            return self.evaluateConstraintQuotientsOnDomain(trace, evaluation_accumulator);
        return evaluate(self.ctx, trace, evaluation_accumulator, pool);
    }

    pub inline fn prepareConstraintQuotientsOnDomain(
        self: ComponentProver,
        allocator: std.mem.Allocator,
        trace: *const Trace,
        evaluation_accumulator: *accumulation.DomainEvaluationAccumulator,
    ) anyerror!?prepared_domain.PreparedDomainEvaluation {
        const prepare = self.prepare_domain_evaluator orelse return null;
        var result = try prepare(
            self.ctx,
            allocator,
            trace,
            evaluation_accumulator,
        );
        errdefer result.deinit();
        try result.validate();
        return result;
    }
};

pub const ComponentProvers = struct {
    components: []const ComponentProver,
    n_preprocessed_columns: usize,
    composition_stage: ?device_composition.Stage = null,
    cpu_composition_execution: ?@import("stwo_prover_api").CpuCompositionExecutionRequest = null,

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

    pub fn compositionLogSplit(self: ComponentProvers) !u32 {
        if (self.components.len == 0) return error.InvalidCompositionLogSplit;
        const split = self.components[0].compositionLogSplit();
        if (split == 0 or
            split > @import("stwo_core").verifier_types.MAX_COMPOSITION_LOG_SPLIT)
        {
            return error.InvalidCompositionLogSplit;
        }
        for (self.components[1..]) |component| {
            if (component.compositionLogSplit() != split) {
                return error.InconsistentCompositionLogSplit;
            }
        }
        if (self.compositionLogDegreeBound() <= split) {
            return error.InvalidCompositionLogSplit;
        }
        return split;
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
        return self.computeCompositionEvaluationForBackend(
            void,
            allocator,
            random_coeff,
            trace,
            &.{},
            null,
        );
    }

    pub fn computeCompositionEvaluationForBackend(
        self: ComponentProvers,
        comptime B: type,
        allocator: std.mem.Allocator,
        random_coeff: QM31,
        trace: *const Trace,
        residency_handles: []const ?*anyopaque,
        composition_twiddles: ?M31TwiddleTree,
    ) anyerror!SecureColumnByCoords {
        if (try device_composition.tryStage(self.composition_stage, .{
            .allocator = allocator,
            .random_coeff = random_coeff,
            .composition_log_degree_bound = self.compositionLogDegreeBound(),
            .total_constraints = self.totalConstraints(),
            .trace = trace,
        })) |evaluation| return evaluation;
        var resolved_execution: ?composition_execution.Execution = null;
        if (try composition_execution.tryBackend(
            B,
            allocator,
            self.components,
            random_coeff,
            trace,
            residency_handles,
            composition_twiddles,
            self.cpu_composition_execution,
            &resolved_execution,
        )) |evaluation| return evaluation;
        if (resolved_execution == null and self.cpu_composition_execution != null) {
            resolved_execution = try composition_execution.Execution.resolve(
                self.cpu_composition_execution,
            );
        }
        if (resolved_execution) |execution| {
            if (execution.explicit) return component_parallel.computeRequested(
                allocator,
                self.components,
                self.compositionLogDegreeBound(),
                self.totalConstraints(),
                random_coeff,
                trace,
                execution,
            );
        }

        const pool_eligible = self.components.len > 1 or
            (self.components.len == 1 and
                self.components[0].domain_parallel_evaluator != null);
        const pool = if (resolved_execution) |execution|
            execution.pool
        else if (pool_eligible)
            work_pool_mod.getGlobalPool()
        else
            null;
        if (pool) |active| {
            if (self.components.len > 1) return self.computeCompositionEvaluationParallel(
                allocator,
                random_coeff,
                trace,
                active,
            );
            return self.computeCompositionEvaluationSingleParallel(
                allocator,
                random_coeff,
                trace,
                active,
            );
        }

        return self.computeCompositionEvaluationSequential(
            allocator,
            random_coeff,
            trace,
        );
    }

    /// Original sequential implementation.
    fn computeCompositionEvaluationSequential(
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

    fn computeCompositionEvaluationSingleParallel(
        self: ComponentProvers,
        allocator: std.mem.Allocator,
        random_coeff: QM31,
        trace: *const Trace,
        pool: *work_pool_mod.WorkPool,
    ) anyerror!SecureColumnByCoords {
        var accumulator = try accumulation.DomainEvaluationAccumulator.init(
            allocator,
            random_coeff,
            self.compositionLogDegreeBound(),
            self.totalConstraints(),
        );
        defer accumulator.deinit();

        try self.components[0].evaluateConstraintQuotientsOnDomainParallel(
            trace,
            &accumulator,
            pool,
        );
        return accumulator.finalize();
    }

    /// Parallel implementation: each component gets its own accumulator
    /// with pre-assigned power ranges, evaluated concurrently, then merged.
    fn computeCompositionEvaluationParallel(
        self: ComponentProvers,
        allocator: std.mem.Allocator,
        random_coeff: QM31,
        trace: *const Trace,
        pool: *work_pool_mod.WorkPool,
    ) anyerror!SecureColumnByCoords {
        return component_parallel.compute(
            allocator,
            self.components,
            self.compositionLogDegreeBound(),
            self.totalConstraints(),
            random_coeff,
            trace,
            pool,
        );
    }
};

const CORE_COMPONENT_ADAPTER_VTABLE = core_air_components.ComponentVTable{
    .nConstraints = coreAdapterNConstraints,
    .maxConstraintLogDegreeBound = coreAdapterMaxConstraintLogDegreeBound,
    .compositionLogSplit = coreAdapterCompositionLogSplit,
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

fn coreAdapterCompositionLogSplit(ctx: *const anyopaque) u32 {
    return coreAdapterCast(ctx).compositionLogSplit();
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
    try std.testing.expect(components_arr[0].backend_composition_capability == null);
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

test "prover air component prover: multi-component sequential matches merged accumulators" {
    // Verify that splitting accumulation across two independent accumulators
    // (simulating what the parallel path does) produces the same result as
    // the sequential path with a single accumulator.
    const alloc = std.testing.allocator;
    const alpha = QM31.fromU32Unchecked(7, 0, 0, 0);

    const MockA = struct {
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
        fn nConstraints(_: *const anyopaque) usize {
            return 1;
        }
        fn maxConstraintLogDegreeBound(_: *const anyopaque) u32 {
            return 2;
        }
        fn traceLogDegreeBounds(_: *const anyopaque, a: std.mem.Allocator) !core_air_components.TraceLogDegreeBounds {
            const preprocessed = try a.alloc(u32, 0);
            const main_tree = try a.dupe(u32, &[_]u32{2});
            return core_air_components.TraceLogDegreeBounds.initOwned(
                try a.dupe([]u32, &[_][]u32{ preprocessed, main_tree }),
            );
        }
        fn maskPoints(_: *const anyopaque, a: std.mem.Allocator, point: CirclePointQM31, _: u32) !core_air_components.MaskPoints {
            const pp = try a.alloc([]CirclePointQM31, 0);
            const mc = try a.alloc(CirclePointQM31, 1);
            mc[0] = point;
            const mcs = try a.dupe([]CirclePointQM31, &[_][]CirclePointQM31{mc});
            return core_air_components.MaskPoints.initOwned(
                try a.dupe([][]CirclePointQM31, &[_][][]CirclePointQM31{ pp, mcs }),
            );
        }
        fn preprocessedColumnIndices(_: *const anyopaque, a: std.mem.Allocator) ![]usize {
            return a.alloc(usize, 0);
        }
        fn evaluateConstraintQuotientsAtPoint(_: *const anyopaque, _: CirclePointQM31, _: *const core_air_components.MaskValues, _: *core_air_accumulation.PointEvaluationAccumulator, _: u32) !void {}
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

    const MockB = struct {
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
        fn nConstraints(_: *const anyopaque) usize {
            return 1;
        }
        fn maxConstraintLogDegreeBound(_: *const anyopaque) u32 {
            return 2;
        }
        fn traceLogDegreeBounds(_: *const anyopaque, a: std.mem.Allocator) !core_air_components.TraceLogDegreeBounds {
            const preprocessed = try a.alloc(u32, 0);
            const main_tree = try a.dupe(u32, &[_]u32{2});
            return core_air_components.TraceLogDegreeBounds.initOwned(
                try a.dupe([]u32, &[_][]u32{ preprocessed, main_tree }),
            );
        }
        fn maskPoints(_: *const anyopaque, a: std.mem.Allocator, point: CirclePointQM31, _: u32) !core_air_components.MaskPoints {
            const pp = try a.alloc([]CirclePointQM31, 0);
            const mc = try a.alloc(CirclePointQM31, 1);
            mc[0] = point;
            const mcs = try a.dupe([]CirclePointQM31, &[_][]CirclePointQM31{mc});
            return core_air_components.MaskPoints.initOwned(
                try a.dupe([][]CirclePointQM31, &[_][][]CirclePointQM31{ pp, mcs }),
            );
        }
        fn preprocessedColumnIndices(_: *const anyopaque, a: std.mem.Allocator) ![]usize {
            return a.alloc(usize, 0);
        }
        fn evaluateConstraintQuotientsAtPoint(_: *const anyopaque, _: CirclePointQM31, _: *const core_air_components.MaskValues, _: *core_air_accumulation.PointEvaluationAccumulator, _: u32) !void {}
        fn evaluateConstraintQuotientsOnDomain(
            _: *const anyopaque,
            _: *const Trace,
            evaluation_accumulator: *accumulation.DomainEvaluationAccumulator,
        ) !void {
            const values = [_]QM31{
                QM31.fromU32Unchecked(10, 0, 0, 0),
                QM31.fromU32Unchecked(20, 0, 0, 0),
                QM31.fromU32Unchecked(30, 0, 0, 0),
                QM31.fromU32Unchecked(40, 0, 0, 0),
            };
            var col = try SecureColumnByCoords.fromSecureSlice(std.testing.allocator, values[0..]);
            defer col.deinit(std.testing.allocator);
            try evaluation_accumulator.accumulateColumn(2, &col);
        }
    };

    const mock_a = MockA{};
    const mock_b = MockB{};
    const components_arr = [_]ComponentProver{ mock_a.asComponent(), mock_b.asComponent() };
    const component_provers = ComponentProvers{
        .components = components_arr[0..],
        .n_preprocessed_columns = 0,
    };

    var trace = Trace{ .polys = TreeVec([]const Poly).initOwned(try alloc.alloc([]const Poly, 0)) };
    defer trace.polys.deinit(alloc);

    var sequential = try component_provers.computeCompositionEvaluationSequential(
        alloc,
        alpha,
        &trace,
    );
    defer sequential.deinit(alloc);
    const seq_vec = try sequential.toVec(alloc);
    defer alloc.free(seq_vec);
    const total_constraints = component_provers.totalConstraints();
    const max_log_size = component_provers.compositionLogDegreeBound();
    const powers = try accumulation.generateSecurePowers(alloc, alpha, total_constraints);
    defer alloc.free(powers);
    var acc_a = try accumulation.DomainEvaluationAccumulator.initForComponent(powers, alloc, max_log_size, 2);
    defer acc_a.deinit();
    var acc_b = try accumulation.DomainEvaluationAccumulator.initForComponent(powers, alloc, max_log_size, 1);
    defer acc_b.deinit();
    try components_arr[0].evaluateConstraintQuotientsOnDomain(&trace, &acc_a);
    try components_arr[1].evaluateConstraintQuotientsOnDomain(&trace, &acc_b);
    acc_a.merge(&acc_b);
    acc_a.next_power_index = 0;
    var merged = try acc_a.finalize();
    defer merged.deinit(alloc);
    const merged_vec = try merged.toVec(alloc);
    defer alloc.free(merged_vec);
    try std.testing.expectEqual(seq_vec.len, merged_vec.len);
    for (seq_vec, merged_vec) |s, m| {
        try std.testing.expect(s.eql(m));
    }
}
