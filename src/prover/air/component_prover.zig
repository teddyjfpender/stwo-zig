const std = @import("std");
const circle = @import("stwo_core").circle;
const core_air_accumulation = @import("stwo_core").air.accumulation;
const core_air_components = @import("stwo_core").air.components;
const m31 = @import("stwo_core").fields.m31;
const qm31 = @import("stwo_core").fields.qm31;
const pcs = @import("stwo_core").pcs;
const accumulation = @import("accumulation.zig");
const composition_work = @import("composition_work.zig");
const oods_work = @import("oods_work.zig");
const composition_execution = @import("composition_execution.zig");
const component_parallel = @import("component_parallel.zig");
const component_trace = @import("component_trace.zig");
const device_composition = @import("device_composition.zig");
const prepared_domain = @import("prepared_domain.zig");
const prover_twiddles = @import("../poly/twiddles.zig");
const secure_column = @import("../secure_column.zig");
const work_pool_mod = @import("../work_pool.zig");
const stage_profile = @import("stwo_prover_api").stage_profile;

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
const component_programs = @import("component_programs.zig");
pub const BasePolynomialOp = component_programs.BasePolynomialOp;
pub const BasePolynomialNode = component_programs.BasePolynomialNode;
pub const OwnedBasePolynomialProgram = component_programs.OwnedBasePolynomialProgram;
pub const BasePolynomialCapabilityV1 = component_programs.BasePolynomialCapabilityV1;
pub const MAX_LOOKUP_POLYNOMIAL_ARITY = component_programs.MAX_LOOKUP_POLYNOMIAL_ARITY;
pub const LookupPolynomialEntry = component_programs.LookupPolynomialEntry;
pub const OwnedLookupPolynomialProgram = component_programs.OwnedLookupPolynomialProgram;
pub const LOOKUP_POLYNOMIAL_LAYOUT_V2_FORMAT_VERSION = component_programs.LOOKUP_POLYNOMIAL_LAYOUT_V2_FORMAT_VERSION;
pub const LOOKUP_POLYNOMIAL_LAYOUT_V2_MAXIMUM_BATCH_SIZE = component_programs.LOOKUP_POLYNOMIAL_LAYOUT_V2_MAXIMUM_BATCH_SIZE;
pub const LOOKUP_POLYNOMIAL_LAYOUT_V2_INTERACTION_COORDINATES = component_programs.LOOKUP_POLYNOMIAL_LAYOUT_V2_INTERACTION_COORDINATES;
pub const LOOKUP_POLYNOMIAL_LAYOUT_V2_MAXIMUM_DEGREE = component_programs.LOOKUP_POLYNOMIAL_LAYOUT_V2_MAXIMUM_DEGREE;
pub const LOOKUP_POLYNOMIAL_LAYOUT_V2_IDENTITY_DOMAIN = component_programs.LOOKUP_POLYNOMIAL_LAYOUT_V2_IDENTITY_DOMAIN;
pub const LOOKUP_POLYNOMIAL_PROGRAM_V2_IDENTITY_DOMAIN = component_programs.LOOKUP_POLYNOMIAL_PROGRAM_V2_IDENTITY_DOMAIN;
pub const LookupPolynomialIdentity = component_programs.LookupPolynomialIdentity;
pub const LookupPolynomialProgramV2Error = component_programs.LookupPolynomialProgramV2Error;
pub const LookupPolynomialEventDegreeV2 = component_programs.LookupPolynomialEventDegreeV2;
pub const LookupPolynomialBatchV2 = component_programs.LookupPolynomialBatchV2;
pub const LookupPolynomialLayoutV2 = component_programs.LookupPolynomialLayoutV2;
pub const LookupPolynomialAuthorityV2 = component_programs.LookupPolynomialAuthorityV2;
pub const OwnedLookupPolynomialProgramV2 = component_programs.OwnedLookupPolynomialProgramV2;
pub const LookupPolynomialCapabilityV1 = component_programs.LookupPolynomialCapabilityV1;
pub const LookupPolynomialCapabilityV2 = component_programs.LookupPolynomialCapabilityV2;
pub const BackendCompositionCapability = component_programs.BackendCompositionCapability;
pub const ComponentProfileIdentity = @import("component_profile_identity.zig").ComponentProfileIdentity;

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
    profile_identity: ?ComponentProfileIdentity = null,
    backend_composition_capability: ?BackendCompositionCapability = null,
    /// Optional exact one-row formula authority for profiled domain
    /// composition. The callback is cold and allocation-explicit; ordinary
    /// proving never invokes it. Backend aggregation remains a separate owner
    /// because fresh stores, merges, and lifting depend on the selected route.
    composition_work_profile: ?*const fn (
        ctx: *const anyopaque,
        allocator: std.mem.Allocator,
    ) anyerror!composition_work.ComponentProfile = null,
    /// Optional backend-neutral authority for the two OODS component calls.
    /// The callback runs only after a profiled operation has executed; normal
    /// proving retains the original vtable path with no per-component branch.
    oods_work_profile: ?*const fn (
        ctx: *const anyopaque,
        allocator: std.mem.Allocator,
        max_log_degree_bound: u32,
        source: *const composition_work.ComponentProfile,
    ) anyerror!oods_work.ComponentProfile = null,
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

    pub fn compositionWorkProfile(
        self: ComponentProver,
        allocator: std.mem.Allocator,
    ) anyerror!?composition_work.ComponentProfile {
        const profile = self.composition_work_profile orelse return null;
        const result = try profile(self.ctx, allocator);
        try result.validate();
        if (result.constraint_count != self.nConstraints() or
            result.evaluation_log_size != self.maxConstraintLogDegreeBound())
        {
            return error.InvalidCompositionWorkProfile;
        }
        return result;
    }

    pub fn oodsWorkProfile(
        self: ComponentProver,
        allocator: std.mem.Allocator,
        max_log_degree_bound: u32,
    ) anyerror!?oods_work.ComponentProfile {
        const profile = self.oods_work_profile orelse return null;
        const source = try self.compositionWorkProfile(allocator) orelse
            return null;
        const result = try profile(
            self.ctx,
            allocator,
            max_log_degree_bound,
            &source,
        );
        try result.validate();
        if (result.constraint_count != self.nConstraints() or
            result.max_log_degree_bound != max_log_degree_bound or
            result.component_log_degree_bound != self.maxConstraintLogDegreeBound() or
            !std.mem.eql(
                u8,
                &result.composition_profile_digest,
                &source.profile_digest,
            ))
        {
            return error.InvalidOodsWorkProfile;
        }
        return result;
    }
};

/// Proof-scoped cold observer for the core component loops. Profile failures
/// never alter proof execution: they suppress publication, which makes the
/// terminal work ledger fail closed. Duplicate publication remains a hard
/// programming error at `Capture.publish`.
const OodsObserver = struct {
    components: []const ComponentProver,
    allocator: std.mem.Allocator,
    max_log_degree_bound: u32,
    builder: oods_work.Builder,
    complete: bool = true,

    fn init(
        site: oods_work.Site,
        components: []const ComponentProver,
        allocator: std.mem.Allocator,
        max_log_degree_bound: u32,
    ) OodsObserver {
        return .{
            .components = components,
            .allocator = allocator,
            .max_log_degree_bound = max_log_degree_bound,
            .builder = oods_work.Builder.init(site),
        };
    }

    pub fn afterComponent(self: *OodsObserver, ordinal: usize) !void {
        if (!self.complete) return;
        if (ordinal >= self.components.len) {
            self.complete = false;
            return;
        }
        const profile = self.components[ordinal].oodsWorkProfile(
            self.allocator,
            self.max_log_degree_bound,
        ) catch {
            self.complete = false;
            return;
        } orelse {
            self.complete = false;
            return;
        };
        self.builder.addComponent(ordinal, &profile) catch {
            self.complete = false;
        };
    }

    fn addCoordinator(
        self: *OodsObserver,
        label: []const u8,
        operations: oods_work.FieldOperations,
        geometry: []const u64,
    ) void {
        if (!self.complete) return;
        self.builder.addCoordinator(label, operations, geometry) catch {
            self.complete = false;
        };
    }

    fn publish(self: *OodsObserver, capture: *oods_work.Capture) !void {
        if (!self.complete) return;
        const receipt = self.builder.finish() catch return;
        try capture.publish(receipt);
    }
};

pub const ComponentProvers = struct {
    components: []const ComponentProver,
    n_preprocessed_columns: usize,
    composition_stage: ?device_composition.Stage = null,
    cpu_composition_execution: ?@import("stwo_prover_api").CpuCompositionExecutionRequest = null,
    /// Borrowed from the proof's existing optional stage recorder. Structured
    /// composition publishes its independent flat task profile through it.
    task_recorder: ?*stage_profile.Recorder = null,
    /// Borrowed proof-scoped receipt slot. A backend publishes only after the
    /// complete composition result has succeeded.
    composition_work_capture: ?*composition_work.Capture = null,

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

        /// Executes the established core aggregation unchanged. A profiled
        /// request adds one cold callback after each successful dynamic vtable
        /// call and publishes only after the complete mask has been assembled.
        /// Profiled wall-clock stages intentionally include this bounded
        /// evidence cost; unprofiled benchmark/proof paths take the direct
        /// core method and execute no observer work.
        pub fn maskPointsWithWorkCapture(
            self: ComponentsView,
            allocator: std.mem.Allocator,
            point: CirclePointQM31,
            max_log_degree_bound: u32,
            include_all_preprocessed_columns: bool,
            capture: ?*oods_work.Capture,
        ) !core_air_components.MaskPoints {
            const active = capture orelse return self.asCore().maskPoints(
                allocator,
                point,
                max_log_degree_bound,
                include_all_preprocessed_columns,
            );
            var observer = OodsObserver.init(
                .mask_points,
                self.prover_components,
                allocator,
                max_log_degree_bound,
            );
            var result = try self.asCore().maskPointsWithObserver(
                allocator,
                point,
                max_log_degree_bound,
                include_all_preprocessed_columns,
                &observer,
            );
            errdefer result.deinitDeep(allocator);
            try observer.publish(active);
            return result;
        }

        /// Point-composition analogue of `maskPointsWithWorkCapture`. The
        /// extraction geometry names the coordinator work that has already
        /// succeeded immediately before this call.
        pub fn evalCompositionPolynomialAtPointWithWorkCapture(
            self: ComponentsView,
            allocator: std.mem.Allocator,
            point: CirclePointQM31,
            mask_values: *const core_air_components.MaskValues,
            random_coeff: QM31,
            max_log_degree_bound: u32,
            composition_log_size: u32,
            composition_log_split: u32,
            capture: ?*oods_work.Capture,
        ) !QM31 {
            const active = capture orelse
                return self.asCore().evalCompositionPolynomialAtPoint(
                    point,
                    mask_values,
                    random_coeff,
                    max_log_degree_bound,
                );
            var observer = OodsObserver.init(
                .constraint_evaluation,
                self.prover_components,
                allocator,
                max_log_degree_bound,
            );
            observer.addCoordinator(
                "composition-chunk-extraction",
                oods_work.compositionExtractionWork(
                    composition_log_size,
                    composition_log_split,
                ) catch {
                    observer.complete = false;
                    return self.asCore().evalCompositionPolynomialAtPoint(
                        point,
                        mask_values,
                        random_coeff,
                        max_log_degree_bound,
                    );
                },
                &.{
                    @as(u64, composition_log_size),
                    @as(u64, composition_log_split),
                },
            );
            const result = try self.asCore().evalCompositionPolynomialAtPointWithObserver(
                point,
                mask_values,
                random_coeff,
                max_log_degree_bound,
                &observer,
            );
            try observer.publish(active);
            return result;
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
            self.task_recorder,
            self.composition_work_capture,
            &resolved_execution,
        )) |evaluation| return evaluation;
        if (resolved_execution == null and self.cpu_composition_execution != null) {
            resolved_execution = try composition_execution.Execution.resolveWithRecorder(
                self.cpu_composition_execution,
                self.task_recorder,
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
        return component_parallel.computeWithRecorder(
            allocator,
            self.components,
            self.compositionLogDegreeBound(),
            self.totalConstraints(),
            random_coeff,
            trace,
            pool,
            self.task_recorder,
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
