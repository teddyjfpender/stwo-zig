//! Candidate-native degree-five Poseidon2 component.
//!
//! This is an append-only proof component for the 239-column degree-five
//! materialization.  It deliberately does not replace the frozen 445-column
//! sparse-memory component or activate any production registry entry.  The
//! candidate compiler remains the single authority for the direct polynomial
//! DAG; this module supplies the exact STARK component geometry and evaluates
//! that DAG together with the existing two-pair Poseidon LogUp relation.

const std = @import("std");
const core_air_accumulation = @import("stwo_core").air.accumulation;
const core_air_components = @import("stwo_core").air.components;
const core_air_derive = @import("stwo_core").air.derive;
const core_constraints = @import("stwo_core").constraints;
const circle = @import("stwo_core").circle;
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const canonic = @import("stwo_core").poly.circle.canonic;
const utils = @import("stwo_core").utils;
const prover_air_accumulation = @import("stwo_prover_engine").air.accumulation;
const prover_component = @import("stwo_prover_engine").air.component_prover;
const prepared_domain = @import("stwo_prover_engine").air.prepared_domain;
const prover_task_graph = @import("stwo_prover_engine").task_graph;
const candidate_mod = @import("typed_poseidon2_degree_bounded_candidate.zig");
const direct_program = @import("materialization_direct_program.zig");
const poseidon = @import("typed_poseidon2.zig");
const types = @import("types.zig");
const entry = @import("../lookups/entry.zig");
const logup = @import("../logup.zig");
const relations_mod = @import("../relation_challenges.zig");
const sampling_mod = @import("../memory_commitment/hash_component_sampling.zig");
const prepared_program = @import("typed_poseidon2_degree5_prepared_program.zig");
const prepared_telemetry = @import("typed_poseidon2_degree5_prepared_telemetry.zig");

const CirclePointQM31 = circle.CirclePointQM31;

pub const PRODUCTION_ACTIVATION = false;
pub const PROFILE = candidate_mod.Profile.degree5;
pub const MAIN_COLUMNS: usize = 239;
pub const INTERACTION_COLUMNS: usize = candidate_mod.INTERACTION_COLUMNS;
pub const PERMUTATION_CONSTRAINTS: usize = 224;
pub const SHELL_CONSTRAINTS: usize = 3;
pub const DIRECT_CONSTRAINTS: usize =
    PERMUTATION_CONSTRAINTS + SHELL_CONSTRAINTS;
pub const LOGUP_CONSTRAINTS: usize = 2;
pub const CONSTRAINTS: usize = DIRECT_CONSTRAINTS + LOGUP_CONSTRAINTS;
pub const QUOTIENT_EXPANSION_BITS: u32 = 2;
pub const COMPOSITION_LOG_SPLIT: u32 = PROFILE.compositionLogSplit();
pub const MAX_DIRECT_NODES: usize = 2_842;
pub const PreparedProgram = prepared_program.Program;
pub const PreparedTelemetrySnapshot = prepared_telemetry.Snapshot;

pub const PreparedConstraintValues = struct {
    base: [DIRECT_CONSTRAINTS]M31,
    secure: [LOGUP_CONSTRAINTS]QM31,
};

pub fn resetPreparedTelemetry() void {
    prepared_telemetry.reset();
}

pub fn preparedTelemetrySnapshot() PreparedTelemetrySnapshot {
    return prepared_telemetry.snapshot();
}

const materialized_column_namespace: u64 = @as(u64, 1) << 63;
const value_index_mask: u64 = std.math.maxInt(u32);

pub const Error = error{
    CandidateProfileMismatch,
    DirectNodeCapacityExceeded,
    InvalidCandidateColumn,
    InvalidCandidateComponent,
    InvalidDirectNode,
    InvalidProofShape,
    UnsupportedDirectNode,
};

pub const Component = struct {
    candidate: *const candidate_mod.Candidate,
    log_size: u32,
    n_rows: u32,
    is_first_col_idx: usize,
    is_active_col_idx: usize,
    main_col_offset: usize,
    interaction_col_offset: usize,
    relations: *const relations_mod.Relations,
    claims: [LOGUP_CONSTRAINTS]QM31,

    const Adapter = core_air_derive.ComponentAdapter(
        @This(),
        prover_component.ComponentProver,
        prover_component.Trace,
        prover_air_accumulation.DomainEvaluationAccumulator,
    );

    pub fn init(
        candidate: *const candidate_mod.Candidate,
        log_size: u32,
        n_rows: u32,
        is_first_col_idx: usize,
        is_active_col_idx: usize,
        main_col_offset: usize,
        interaction_col_offset: usize,
        relations: *const relations_mod.Relations,
        claims: [LOGUP_CONSTRAINTS]QM31,
    ) !Component {
        const result = Component{
            .candidate = candidate,
            .log_size = log_size,
            .n_rows = n_rows,
            .is_first_col_idx = is_first_col_idx,
            .is_active_col_idx = is_active_col_idx,
            .main_col_offset = main_col_offset,
            .interaction_col_offset = interaction_col_offset,
            .relations = relations,
            .claims = claims,
        };
        try result.validate();
        return result;
    }

    pub fn validate(self: *const Component) !void {
        try self.candidate.validate();
        if (self.candidate.profile != PROFILE or
            self.candidate.geometry.main_columns != MAIN_COLUMNS or
            self.candidate.geometry.interaction_columns != INTERACTION_COLUMNS or
            self.candidate.geometry.permutation_direct_constraints !=
                PERMUTATION_CONSTRAINTS or
            self.candidate.geometry.component_direct_constraints !=
                DIRECT_CONSTRAINTS or
            self.candidate.geometry.quotient_expansion_bits !=
                QUOTIENT_EXPANSION_BITS or
            self.candidate.geometry.composition_log_split !=
                COMPOSITION_LOG_SPLIT or
            self.candidate.direct_program.nodes().len > MAX_DIRECT_NODES or
            self.candidate.direct_program.roots().len !=
                PERMUTATION_CONSTRAINTS or
            self.log_size == 0 or
            self.log_size + QUOTIENT_EXPANSION_BITS >=
                circle.M31_CIRCLE_LOG_ORDER or
            @as(u64, self.n_rows) > (@as(u64, 1) << @intCast(self.log_size)))
        {
            return error.InvalidCandidateComponent;
        }
    }

    pub fn asVerifierComponent(self: *const Component) core_air_components.Component {
        return Adapter.asVerifierComponent(self);
    }

    pub fn asProverComponent(self: *const Component) prover_component.ComponentProver {
        var component = Adapter.asProverComponent(self);
        component.prepare_domain_evaluator = prepareDomainEvaluatorErased;
        return component;
    }

    fn prepareDomainEvaluatorErased(
        ctx: *const anyopaque,
        allocator: std.mem.Allocator,
        trace: *const prover_component.Trace,
        accumulator: *prover_air_accumulation.DomainEvaluationAccumulator,
    ) anyerror!prepared_domain.PreparedDomainEvaluation {
        const self: *const Component = @ptrCast(@alignCast(ctx));
        return prepared_impl.prepare(self, allocator, trace, accumulator);
    }

    pub fn nConstraints(_: *const Component) usize {
        return CONSTRAINTS;
    }

    pub fn maxConstraintLogDegreeBound(self: *const Component) u32 {
        return self.log_size + QUOTIENT_EXPANSION_BITS;
    }

    pub fn compositionLogSplit(_: *const Component) u32 {
        return COMPOSITION_LOG_SPLIT;
    }

    /// OODS samples one split composition chunk.  The full quotient domain is
    /// `maxConstraintLogDegreeBound()`, while the sample/mask domain is lower
    /// by the protocol's composition split.
    pub fn samplingLogDegreeBound(self: *const Component) u32 {
        return self.maxConstraintLogDegreeBound() - COMPOSITION_LOG_SPLIT;
    }

    pub fn traceLogDegreeBounds(
        self: *const Component,
        allocator: std.mem.Allocator,
    ) !core_air_components.TraceLogDegreeBounds {
        const preprocessed = try filledLogs(allocator, 2, self.log_size);
        errdefer allocator.free(preprocessed);
        const main = try filledLogs(allocator, MAIN_COLUMNS, self.log_size);
        errdefer allocator.free(main);
        const interaction = try filledLogs(
            allocator,
            INTERACTION_COLUMNS,
            self.log_size,
        );
        errdefer allocator.free(interaction);
        return core_air_components.TraceLogDegreeBounds.initOwned(
            try allocator.dupe([]u32, &.{ preprocessed, main, interaction }),
        );
    }

    pub fn maskPoints(
        self: *const Component,
        allocator: std.mem.Allocator,
        point: CirclePointQM31,
        max_log_degree_bound: u32,
    ) !core_air_components.MaskPoints {
        if (max_log_degree_bound != self.samplingLogDegreeBound())
            return error.InvalidProofShape;
        const preprocessed = try sampling.currentPointColumns(allocator, 2, point);
        errdefer sampling.freePointColumns(allocator, preprocessed);
        const main = try sampling.currentPointColumns(
            allocator,
            MAIN_COLUMNS,
            point,
        );
        errdefer sampling.freePointColumns(allocator, main);
        const interaction = try sampling.currentAndPreviousPointColumns(
            allocator,
            INTERACTION_COLUMNS,
            point,
            logup.prevRowPoint(max_log_degree_bound, point),
        );
        errdefer sampling.freePointColumns(allocator, interaction);
        return core_air_components.MaskPoints.initOwned(
            try allocator.dupe([][]CirclePointQM31, &.{
                preprocessed,
                main,
                interaction,
            }),
        );
    }

    pub fn preprocessedColumnIndices(
        self: *const Component,
        allocator: std.mem.Allocator,
    ) ![]usize {
        return allocator.dupe(
            usize,
            &.{ self.is_first_col_idx, self.is_active_col_idx },
        );
    }

    pub fn evaluateConstraintQuotientsAtPoint(
        self: *const Component,
        point: CirclePointQM31,
        mask: *const core_air_components.MaskValues,
        accumulator: *core_air_accumulation.PointEvaluationAccumulator,
        max_log_degree_bound: u32,
    ) !void {
        if (max_log_degree_bound != self.samplingLogDegreeBound() or
            mask.items.len < 3)
        {
            return error.InvalidProofShape;
        }
        const preprocessed = mask.items[0];
        const main_mask = mask.items[1];
        const interaction_mask = mask.items[2];
        if (preprocessed.len <= self.is_first_col_idx or
            preprocessed.len <= self.is_active_col_idx or
            preprocessed[self.is_first_col_idx].len < 1 or
            preprocessed[self.is_active_col_idx].len < 1 or
            main_mask.len < self.main_col_offset + MAIN_COLUMNS or
            interaction_mask.len <
                self.interaction_col_offset + INTERACTION_COLUMNS)
        {
            return error.InvalidProofShape;
        }
        const main = try sampling.sampleMain(
            MAIN_COLUMNS,
            main_mask,
            self.main_col_offset,
        );
        var sums: [LOGUP_CONSTRAINTS]QM31 = undefined;
        var previous: [LOGUP_CONSTRAINTS]QM31 = undefined;
        try sampling.sampleInteraction(
            LOGUP_CONSTRAINTS,
            interaction_mask,
            self.interaction_col_offset,
            &sums,
            &previous,
        );
        const constraints = try self.evaluateConstraints(
            main,
            preprocessed[self.is_active_col_idx][0],
            preprocessed[self.is_first_col_idx][0],
            sums,
            previous,
        );
        const denominator_inverse = try core_constraints.cosetVanishing(
            QM31,
            canonic.CanonicCoset.new(self.log_size).coset(),
            point.repeatedDouble(max_log_degree_bound - self.log_size),
        ).inv();
        for (constraints) |constraint| {
            accumulator.accumulate(constraint.mul(denominator_inverse));
        }
    }

    pub fn evaluateConstraintQuotientsOnDomain(
        self: *const Component,
        trace: *const prover_component.Trace,
        accumulator: *prover_air_accumulation.DomainEvaluationAccumulator,
    ) !void {
        var prepared = try prepared_impl.prepare(
            self,
            accumulator.allocator,
            trace,
            accumulator,
        );
        defer prepared.deinit();
        var cancellation = prover_task_graph.CancellationToken{};
        var task_context = prepared_impl.serialTaskContext(
            prepared.context,
            &cancellation,
        );
        try prepared.run(&task_context);
    }

    pub fn evaluateConstraints(
        self: *const Component,
        main: [MAIN_COLUMNS]QM31,
        is_active: QM31,
        is_first: QM31,
        sums: [LOGUP_CONSTRAINTS]QM31,
        previous: [LOGUP_CONSTRAINTS]QM31,
    ) ![CONSTRAINTS]QM31 {
        var result: [CONSTRAINTS]QM31 = undefined;
        var scratch: [MAX_DIRECT_NODES]QM31 = undefined;
        try evaluateDirect(self.candidate, main, &scratch);
        for (self.candidate.direct_program.roots(), 0..) |root, index| {
            if (root.node >= self.candidate.direct_program.nodes().len)
                return error.InvalidDirectNode;
            result[index] = scratch[root.node];
        }
        result[PERMUTATION_CONSTRAINTS] = main[0].sub(is_active);
        result[PERMUTATION_CONSTRAINTS + 1] = main[MAIN_COLUMNS - 2];
        result[PERMUTATION_CONSTRAINTS + 2] = main[MAIN_COLUMNS - 1];
        const pairs = try rowPairs(self.candidate, main, self.relations);
        for (0..LOGUP_CONSTRAINTS) |index| {
            result[DIRECT_CONSTRAINTS + index] = logup.pairConstraint(
                sums[index],
                previous[index],
                is_first,
                self.claims[index],
                pairs[index],
            );
        }
        return result;
    }

    /// Quotient-domain hot path compiled from the same authenticated
    /// candidate consumed by `evaluateConstraints`. The verifier/OODS path
    /// deliberately continues to replay the canonical program above.
    pub fn evaluateConstraintsPrepared(
        self: *const Component,
        main: [MAIN_COLUMNS]QM31,
        program: *const PreparedProgram,
        is_active: QM31,
        is_first: QM31,
        sums: [LOGUP_CONSTRAINTS]QM31,
        previous: [LOGUP_CONSTRAINTS]QM31,
    ) ![CONSTRAINTS]QM31 {
        var result: [CONSTRAINTS]QM31 = undefined;
        var scratch: [MAX_DIRECT_NODES]QM31 = undefined;
        const roots = program.evaluate(&main, &scratch);
        @memcpy(result[0..PERMUTATION_CONSTRAINTS], &roots);
        result[PERMUTATION_CONSTRAINTS] = main[0].sub(is_active);
        result[PERMUTATION_CONSTRAINTS + 1] = main[MAIN_COLUMNS - 2];
        result[PERMUTATION_CONSTRAINTS + 2] = main[MAIN_COLUMNS - 1];
        const pairs = try rowPairsPrepared(program, main, self.relations);
        for (0..LOGUP_CONSTRAINTS) |index| {
            result[DIRECT_CONSTRAINTS + index] = logup.pairConstraint(
                sums[index],
                previous[index],
                is_first,
                self.claims[index],
                pairs[index],
            );
        }
        return result;
    }

    /// Base-field quotient-domain direct evaluation with an explicit secure
    /// boundary at LogUp and random-constraint folding. This is algebraically
    /// identical to lifting every committed value before direct evaluation,
    /// while avoiding secure-field arithmetic for base-field polynomials.
    pub fn evaluateConstraintsPreparedBase(
        self: *const Component,
        main: [MAIN_COLUMNS]M31,
        program: *const PreparedProgram,
        is_active: M31,
        is_first: M31,
        sums: [LOGUP_CONSTRAINTS]QM31,
        previous: [LOGUP_CONSTRAINTS]QM31,
    ) !PreparedConstraintValues {
        var result: PreparedConstraintValues = undefined;
        var scratch: [MAX_DIRECT_NODES]M31 = undefined;
        const roots = program.evaluateBase(&main, &scratch);
        @memcpy(result.base[0..PERMUTATION_CONSTRAINTS], &roots);
        result.base[PERMUTATION_CONSTRAINTS] = main[0].sub(is_active);
        result.base[PERMUTATION_CONSTRAINTS + 1] = main[MAIN_COLUMNS - 2];
        result.base[PERMUTATION_CONSTRAINTS + 2] = main[MAIN_COLUMNS - 1];

        var secure_main: [MAIN_COLUMNS]QM31 = undefined;
        for (main, &secure_main) |value, *secure| {
            secure.* = QM31.fromBase(value);
        }
        const pairs = try rowPairsPrepared(program, secure_main, self.relations);
        for (0..LOGUP_CONSTRAINTS) |index| {
            result.secure[index] = logup.pairConstraint(
                sums[index],
                previous[index],
                QM31.fromBase(is_first),
                self.claims[index],
                pairs[index],
            );
        }
        return result;
    }
};

fn evaluateDirect(
    candidate: *const candidate_mod.Candidate,
    main: [MAIN_COLUMNS]QM31,
    scratch: *[MAX_DIRECT_NODES]QM31,
) !void {
    const nodes = candidate.direct_program.nodes();
    if (nodes.len > scratch.len) return error.DirectNodeCapacityExceeded;
    for (nodes, 0..) |node, index| {
        scratch[index] = switch (node.op) {
            .constant => QM31.fromBase(M31.fromU64(node.value)),
            .committed => try committedValue(candidate, main, node.value),
            .fixed_committed => blk: {
                if (node.lhs != @intFromEnum(direct_program.CommitmentTree.main) or
                    node.value >= MAIN_COLUMNS)
                {
                    return error.InvalidCandidateColumn;
                }
                break :blk main[@intCast(node.value)];
            },
            .row_mask => return error.UnsupportedDirectNode,
            .add => try binaryValue(scratch, node, index, .add),
            .sub => try binaryValue(scratch, node, index, .sub),
            .mul => try binaryValue(scratch, node, index, .mul),
            .neg => blk: {
                if (node.lhs >= index) return error.InvalidDirectNode;
                break :blk scratch[node.lhs].neg();
            },
        };
    }
}

fn committedValue(
    candidate: *const candidate_mod.Candidate,
    main: [MAIN_COLUMNS]QM31,
    encoded: u64,
) !QM31 {
    if (encoded & ~(materialized_column_namespace | value_index_mask) != 0)
        return error.InvalidCandidateColumn;
    const value: types.ValueId = @enumFromInt(
        @as(u32, @intCast(encoded & value_index_mask)),
    );
    const column = physicalColumn(candidate, value) orelse
        return error.InvalidCandidateColumn;
    const materialized = encoded & materialized_column_namespace != 0;
    if (materialized != (column >= candidate_mod.MATERIALIZATION_COLUMN_START and
        column < MAIN_COLUMNS - 2))
    {
        return error.InvalidCandidateColumn;
    }
    return main[column];
}

pub fn physicalColumn(
    candidate: *const candidate_mod.Candidate,
    value: types.ValueId,
) ?usize {
    if (value == candidate.gate) return 0;
    const inputs = poseidon.values(candidate.definition.inputs);
    for (inputs, 0..) |input, lane| if (value == input) return 1 + lane;
    for (candidate.selected_values, 0..) |selected, ordinal| {
        if (value == selected)
            return candidate_mod.MATERIALIZATION_COLUMN_START + ordinal;
    }
    return null;
}

fn rowPairs(
    candidate: *const candidate_mod.Candidate,
    main: [MAIN_COLUMNS]QM31,
    relations: *const relations_mod.Relations,
) ![LOGUP_CONSTRAINTS]logup.RowPair {
    const list = try entriesGeneric(QM31, candidate, main);
    return .{
        try list.pair(0, relations),
        try list.pair(1, relations),
    };
}

fn rowPairsPrepared(
    program: *const PreparedProgram,
    main: [MAIN_COLUMNS]QM31,
    relations: *const relations_mod.Relations,
) ![LOGUP_CONSTRAINTS]logup.RowPair {
    const list = entriesPreparedGeneric(QM31, program, main);
    return .{
        try list.pair(0, relations),
        try list.pair(1, relations),
    };
}

/// Canonical four-event Poseidon relation program over the candidate-native
/// physical row. Runtime backend exporters invoke this same function with a
/// recording scalar; the verifier invokes it with `QM31`.
pub fn entriesGeneric(
    comptime S: type,
    candidate: *const candidate_mod.Candidate,
    main: [MAIN_COLUMNS]S,
) !entry.Builder(S).List {
    var output: [candidate_mod.WIDTH]S = undefined;
    const outputs = poseidon.values(candidate.definition.outputs);
    for (outputs, &output) |value, *destination| {
        const column = physicalColumn(candidate, value) orelse
            return error.InvalidCandidateColumn;
        destination.* = main[column];
    }
    return entriesWithOutputGeneric(S, main, output);
}

fn entriesPreparedGeneric(
    comptime S: type,
    program: *const PreparedProgram,
    main: [MAIN_COLUMNS]S,
) entry.Builder(S).List {
    var output: [candidate_mod.WIDTH]S = undefined;
    for (program.output_columns, &output) |column, *destination| {
        destination.* = main[@intCast(column)];
    }
    return entriesWithOutputGeneric(S, main, output);
}

fn entriesWithOutputGeneric(
    comptime S: type,
    main: [MAIN_COLUMNS]S,
    output: [candidate_mod.WIDTH]S,
) entry.Builder(S).List {
    const Builder = entry.Builder(S);
    const enabler = main[0];
    const wide = main[MAIN_COLUMNS - 2];
    const io = main[MAIN_COLUMNS - 1];
    const one = S.one();
    const input = main[1..][0..candidate_mod.WIDTH].*;
    var narrow = [_]S{S.zero()} ** candidate_mod.WIDTH;
    narrow[0] = output[0];
    var wide_output = [_]S{S.zero()} ** candidate_mod.WIDTH;
    @memcpy(wide_output[0..8], output[0..8]);
    var io_tuple: [2 * candidate_mod.WIDTH]S = undefined;
    @memcpy(io_tuple[0..candidate_mod.WIDTH], &input);
    @memcpy(io_tuple[candidate_mod.WIDTH..], &output);

    var list = Builder.List{};
    appendEntryGeneric(S, &list, .poseidon2, enabler.mul(one.sub(io)).neg(), &input);
    appendEntryGeneric(
        S,
        &list,
        .poseidon2,
        enabler.mul(one.sub(wide).sub(io)),
        &narrow,
    );
    appendEntryGeneric(S, &list, .poseidon2, enabler.mul(wide), &wide_output);
    appendEntryGeneric(S, &list, .poseidon2_io, enabler.mul(io), &io_tuple);
    return list;
}

fn appendEntryGeneric(
    comptime S: type,
    list: *entry.Builder(S).List,
    domain: entry.Domain,
    numerator: S,
    values: []const S,
) void {
    var item = entry.Builder(S).Entry{
        .domain = domain,
        .numerator = numerator,
        .arity = @intCast(values.len),
    };
    @memcpy(item.values[0..values.len], values);
    list.append(item);
}

const BinaryOperation = enum { add, sub, mul };

fn binaryValue(
    scratch: *const [MAX_DIRECT_NODES]QM31,
    node: direct_program.Node,
    index: usize,
    operation: BinaryOperation,
) !QM31 {
    if (node.lhs >= index or node.rhs >= index)
        return error.InvalidDirectNode;
    return switch (operation) {
        .add => scratch[node.lhs].add(scratch[node.rhs]),
        .sub => scratch[node.lhs].sub(scratch[node.rhs]),
        .mul => scratch[node.lhs].mul(scratch[node.rhs]),
    };
}

fn filledLogs(
    allocator: std.mem.Allocator,
    count: usize,
    value: u32,
) ![]u32 {
    const result = try allocator.alloc(u32, count);
    @memset(result, value);
    return result;
}

const sampling = sampling_mod.Namespace(.{
    .std = std,
    .M31 = M31,
    .QM31 = QM31,
    .CirclePointQM31 = CirclePointQM31,
});

const prepared_impl = @import("typed_poseidon2_degree5_prepared_domain.zig").Namespace(.{
    .std = std,
    .M31 = M31,
    .QM31 = QM31,
    .core_constraints = core_constraints,
    .canonic = canonic,
    .utils = utils,
    .prover_air_accumulation = prover_air_accumulation,
    .prover_component = prover_component,
    .prepared_domain = prepared_domain,
    .prover_task_graph = prover_task_graph,
    .Component = Component,
    .PreparedProgram = PreparedProgram,
    .MAIN_COLUMNS = MAIN_COLUMNS,
    .INTERACTION_COLUMNS = INTERACTION_COLUMNS,
    .DIRECT_CONSTRAINTS = DIRECT_CONSTRAINTS,
    .LOGUP_CONSTRAINTS = LOGUP_CONSTRAINTS,
    .CONSTRAINTS = CONSTRAINTS,
    .QUOTIENT_EXPANSION_BITS = QUOTIENT_EXPANSION_BITS,
    .sampling = sampling,
});

comptime {
    if (MAIN_COLUMNS != PROFILE.expected().main_columns or
        PERMUTATION_CONSTRAINTS != PROFILE.expected().direct_constraints or
        DIRECT_CONSTRAINTS != 227 or
        CONSTRAINTS != 229 or
        INTERACTION_COLUMNS != 8 or
        QUOTIENT_EXPANSION_BITS != PROFILE.quotientExpansionBits() or
        COMPOSITION_LOG_SPLIT != PROFILE.compositionLogSplit())
    {
        @compileError("degree-five Poseidon component geometry drifted");
    }
}
