//! Prover/verifier adapter for row-aligned scheduler/execution binding.

const std = @import("std");
const core = @import("stwo_core");
const core_air_accumulation = core.air.accumulation;
const core_air_components = core.air.components;
const core_air_derive = core.air.derive;
const core_constraints = core.constraints;
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const canonic = core.poly.circle.canonic;
const prover_accumulation = @import("stwo_prover_engine").air.accumulation;
const prover_component = @import("stwo_prover_engine").air.component_prover;
const prover_poly = @import("stwo_prover_engine").poly.circle.poly;
const prover_twiddles = @import("stwo_prover_engine").poly.twiddles;
const binding = @import("scheduler_binding.zig");
const component_domain = @import("component_domain.zig");
const execution = @import("execution.zig");
const scheduler_component = @import("scheduler_component.zig");

const CirclePointQM31 = core.circle.CirclePointQM31;

pub const Component = struct {
    log_size: u32,
    scheduler_offset: usize,
    execution_offset: usize,
    provenance_offset: usize,

    const Self = @This();
    const Adapter = core_air_derive.ComponentAdapter(
        Self,
        prover_component.ComponentProver,
        prover_component.Trace,
        prover_accumulation.DomainEvaluationAccumulator,
    );

    pub fn asVerifierComponent(
        self: *const Self,
    ) core_air_components.Component {
        return Adapter.asVerifierComponent(self);
    }

    pub fn asProverComponent(
        self: *const Self,
    ) prover_component.ComponentProver {
        return Adapter.asProverComponent(self);
    }

    pub fn nConstraints(_: *const Self) usize {
        return binding.N_CONSTRAINTS;
    }

    pub fn maxConstraintLogDegreeBound(self: *const Self) u32 {
        return self.log_size + 1;
    }

    pub fn traceLogDegreeBounds(
        self: *const Self,
        allocator: std.mem.Allocator,
    ) !core_air_components.TraceLogDegreeBounds {
        try self.validateConfiguration();
        const preprocessed = try allocator.alloc(u32, 0);
        errdefer allocator.free(preprocessed);
        const main = try allocator.alloc(u32, self.mainEnd());
        errdefer allocator.free(main);
        @memset(main, self.log_size);
        return core_air_components.TraceLogDegreeBounds.initOwned(
            try allocator.dupe([]u32, &.{ preprocessed, main }),
        );
    }

    pub fn maskPoints(
        self: *const Self,
        allocator: std.mem.Allocator,
        point: CirclePointQM31,
        max_log_degree_bound: u32,
    ) !core_air_components.MaskPoints {
        try self.validateConfiguration();
        if (max_log_degree_bound < self.log_size)
            return error.InvalidProofShape;
        const preprocessed = try component_domain.currentPointColumns(
            allocator,
            0,
            point,
        );
        errdefer component_domain.freePointColumns(
            allocator,
            preprocessed,
        );
        const main = try component_domain.currentPointColumns(
            allocator,
            self.mainEnd(),
            point,
        );
        errdefer component_domain.freePointColumns(allocator, main);
        return core_air_components.MaskPoints.initOwned(
            try allocator.dupe([][]CirclePointQM31, &.{
                preprocessed,
                main,
            }),
        );
    }

    pub fn preprocessedColumnIndices(
        _: *const Self,
        allocator: std.mem.Allocator,
    ) ![]usize {
        return allocator.alloc(usize, 0);
    }

    pub fn evaluateRow(
        self: *const Self,
        scheduler_values: []const QM31,
        execution_values: []const QM31,
        provenance_values: []const QM31,
    ) !binding.Evaluation(QM31) {
        try self.validateConfiguration();
        return binding.evaluate(
            QM31,
            scheduler_values,
            execution_values,
            provenance_values,
        );
    }

    pub fn evaluateConstraintQuotientsAtPoint(
        self: *const Self,
        point: CirclePointQM31,
        mask: *const core_air_components.MaskValues,
        accumulator: *core_air_accumulation.PointEvaluationAccumulator,
        max_log_degree_bound: u32,
    ) !void {
        try self.validateConfiguration();
        if (max_log_degree_bound < self.log_size or mask.items.len < 2)
            return error.InvalidProofShape;
        const main = mask.items[1];
        var scheduler_values: [scheduler_component.N_MAIN_COLUMNS]QM31 = undefined;
        var execution_values: [execution.N_MAIN_COLUMNS]QM31 = undefined;
        var provenance_values: [binding.N_PROVENANCE_COLUMNS]QM31 = undefined;
        try sampledColumns(
            &scheduler_values,
            main,
            self.scheduler_offset,
        );
        try sampledColumns(
            &execution_values,
            main,
            self.execution_offset,
        );
        try sampledColumns(
            &provenance_values,
            main,
            self.provenance_offset,
        );
        const evaluation = try self.evaluateRow(
            &scheduler_values,
            &execution_values,
            &provenance_values,
        );
        const inverse = try core_constraints.cosetVanishing(
            QM31,
            canonic.CanonicCoset.new(self.log_size).coset(),
            point.repeatedDouble(
                max_log_degree_bound - self.log_size,
            ),
        ).inv();
        for (evaluation.values) |constraint|
            accumulator.accumulate(constraint.mul(inverse));
    }

    pub fn evaluateConstraintQuotientsOnDomain(
        self: *const Self,
        trace: *const prover_component.Trace,
        accumulator: *prover_accumulation.DomainEvaluationAccumulator,
    ) !void {
        try self.validateConfiguration();
        if (trace.polys.items.len < 2)
            return error.InvalidProofShape;
        const main = trace.polys.items[1];
        if (main.len < self.mainEnd())
            return error.InvalidProofShape;

        const allocator = accumulator.allocator;
        const evaluation_log_size =
            self.maxConstraintLogDegreeBound();
        const domain =
            canonic.CanonicCoset.new(evaluation_log_size).circleDomain();
        const evaluation_size = domain.size();
        const evaluations = try allocator.alloc(
            []const M31,
            scheduler_component.N_MAIN_COLUMNS +
                execution.N_MAIN_COLUMNS +
                binding.N_PROVENANCE_COLUMNS,
        );
        defer allocator.free(evaluations);
        var extensions = std.ArrayList([]M31).empty;
        defer {
            for (extensions.items) |values| allocator.free(values);
            extensions.deinit(allocator);
        }
        var at = try extendRange(
            allocator,
            main[self.scheduler_offset..][0..scheduler_component.N_MAIN_COLUMNS],
            evaluations,
            0,
            self.log_size,
            evaluation_log_size,
            evaluation_size,
            &extensions,
        );
        at = try extendRange(
            allocator,
            main[self.execution_offset..][0..execution.N_MAIN_COLUMNS],
            evaluations,
            at,
            self.log_size,
            evaluation_log_size,
            evaluation_size,
            &extensions,
        );
        at = try extendRange(
            allocator,
            main[self.provenance_offset..][0..binding.N_PROVENANCE_COLUMNS],
            evaluations,
            at,
            self.log_size,
            evaluation_log_size,
            evaluation_size,
            &extensions,
        );
        std.debug.assert(at == evaluations.len);
        if (extensions.items.len != 0) {
            var twiddles = try prover_twiddles.precomputeM31(
                allocator,
                domain.half_coset,
            );
            defer prover_twiddles.deinitM31(
                allocator,
                &twiddles,
            );
            try prover_poly.evaluateBuffersWithTwiddles(
                extensions.items,
                domain,
                prover_twiddles.TwiddleTree([]const M31).init(
                    twiddles.root_coset,
                    twiddles.twiddles,
                    twiddles.itwiddles,
                ),
            );
        }

        const inverses =
            try component_domain.quotientDenominators(
                allocator,
                self.log_size,
                evaluation_log_size,
                domain,
            );
        defer allocator.free(inverses);
        var columns = try accumulator.columns(
            allocator,
            &.{.{
                .log_size = evaluation_log_size,
                .n_cols = binding.N_CONSTRAINTS,
            }},
        );
        defer allocator.free(columns);
        const output = &columns[0];
        const shift: std.math.Log2Int(usize) =
            @intCast(self.log_size);
        for (0..evaluation_size) |row| {
            var scheduler_values: [scheduler_component.N_MAIN_COLUMNS]QM31 = undefined;
            var execution_values: [execution.N_MAIN_COLUMNS]QM31 = undefined;
            var provenance_values: [binding.N_PROVENANCE_COLUMNS]QM31 = undefined;
            domainColumns(
                &scheduler_values,
                evaluations[0..scheduler_component.N_MAIN_COLUMNS],
                row,
            );
            domainColumns(
                &execution_values,
                evaluations[scheduler_component.N_MAIN_COLUMNS..][0..execution.N_MAIN_COLUMNS],
                row,
            );
            domainColumns(
                &provenance_values,
                evaluations[scheduler_component.N_MAIN_COLUMNS +
                    execution.N_MAIN_COLUMNS ..],
                row,
            );
            const evaluation = try self.evaluateRow(
                &scheduler_values,
                &execution_values,
                &provenance_values,
            );
            var folded = QM31.zero();
            for (evaluation.values, 0..) |constraint, index| {
                const powers = output.random_coeff_powers;
                folded = folded.add(
                    powers[powers.len - 1 - index].mul(constraint),
                );
            }
            output.accumulate(
                row,
                folded.mulM31(inverses[row >> shift]),
            );
        }
    }

    pub fn evaluateSampled(
        self: *const Self,
        main: [][]QM31,
    ) !binding.Evaluation(QM31) {
        try self.validateConfiguration();
        var scheduler_values: [scheduler_component.N_MAIN_COLUMNS]QM31 = undefined;
        var execution_values: [execution.N_MAIN_COLUMNS]QM31 = undefined;
        var provenance_values: [binding.N_PROVENANCE_COLUMNS]QM31 = undefined;
        try sampledColumns(
            &scheduler_values,
            main,
            self.scheduler_offset,
        );
        try sampledColumns(
            &execution_values,
            main,
            self.execution_offset,
        );
        try sampledColumns(
            &provenance_values,
            main,
            self.provenance_offset,
        );
        return self.evaluateRow(
            &scheduler_values,
            &execution_values,
            &provenance_values,
        );
    }

    fn mainEnd(self: *const Self) usize {
        return @max(
            self.scheduler_offset + scheduler_component.N_MAIN_COLUMNS,
            @max(
                self.execution_offset + execution.N_MAIN_COLUMNS,
                self.provenance_offset + binding.N_PROVENANCE_COLUMNS,
            ),
        );
    }

    fn validateConfiguration(self: *const Self) !void {
        if (self.log_size < 4 or self.log_size > 24)
            return error.InvalidSchedulerBindingLogSize;
        const scheduler_end =
            self.scheduler_offset + scheduler_component.N_MAIN_COLUMNS;
        const execution_end =
            self.execution_offset + execution.N_MAIN_COLUMNS;
        const provenance_end =
            self.provenance_offset + binding.N_PROVENANCE_COLUMNS;
        if (self.scheduler_offset < execution_end and
            self.execution_offset < scheduler_end)
            return error.OverlappingSchedulerBindingColumns;
        if ((self.scheduler_offset < provenance_end and
            self.provenance_offset < scheduler_end) or
            (self.execution_offset < provenance_end and
                self.provenance_offset < execution_end))
            return error.OverlappingSchedulerBindingColumns;
    }
};

fn extendRange(
    allocator: std.mem.Allocator,
    polynomials: []const prover_component.Poly,
    evaluations: [][]const M31,
    start: usize,
    source_log_size: u32,
    evaluation_log_size: u32,
    evaluation_size: usize,
    extensions: *std.ArrayList([]M31),
) !usize {
    var at = start;
    for (polynomials) |polynomial| {
        evaluations[at] = try component_domain.evaluationValues(
            allocator,
            polynomial,
            source_log_size,
            evaluation_log_size,
            evaluation_size,
            extensions,
        );
        at += 1;
    }
    return at;
}

fn sampledColumns(
    output: []QM31,
    columns: [][]QM31,
    offset: usize,
) !void {
    if (columns.len < offset + output.len)
        return error.InvalidProofShape;
    for (output, columns[offset..][0..output.len]) |
        *value,
        column,
    | {
        if (column.len < 1) return error.InvalidProofShape;
        value.* = column[0];
    }
}

fn domainColumns(
    output: []QM31,
    evaluations: []const []const M31,
    row: usize,
) void {
    for (output, evaluations) |*value, values|
        value.* = QM31.fromBase(values[row]);
}
