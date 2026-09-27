//! Concrete native PCS/FRI adapter for typed universal-control row 0.
//!
//! The adapter has no handwritten semantic authority. Its direct root and
//! relation fractions are evaluated by cold-authenticated programs compiled
//! from `control.Definition`; this file owns only framework geometry,
//! vanishing-quotient placement, and the exact LogUp transition recurrence.

const std = @import("std");
const stwo_core = @import("stwo_core");
const core_air_accumulation = stwo_core.air.accumulation;
const core_air_components = stwo_core.air.components;
const core_air_derive = stwo_core.air.derive;
const core_constraints = stwo_core.constraints;
const circle = stwo_core.circle;
const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const canonic = stwo_core.poly.circle.canonic;
const utils = stwo_core.utils;
const prover_air_accumulation = @import("stwo_prover_engine").air.accumulation;
const prover_component = @import("stwo_prover_engine").air.component_prover;
const prover_circle = @import("stwo_prover_engine").poly.circle;
const prover_twiddles = @import("stwo_prover_engine").poly.twiddles;
const control = @import("control.zig");
const control_relation = @import("control_relation.zig");
const direct_program = @import("direct_constraint_program.zig");
const framework = @import("framework_interaction.zig");
const logup = @import("../../air/logup.zig");
const proof_kind_mod = @import("proof_kind.zig");
const universal = @import("universal_challenges.zig");

const CirclePointQM31 = circle.CirclePointQM31;
const Framework = framework.Runtime(control_relation.Runtime);

pub const DIRECT_COUNT = control.DIRECT_CONSTRAINT_COUNT;
pub const LOGUP_COUNT = control.INTERACTION_BATCH_COUNT;
pub const CONSTRAINT_COUNT = DIRECT_COUNT + LOGUP_COUNT;
pub const TRANSCRIPT_FORMAT_VERSION: u32 = 1;
pub const TRANSCRIPT_DOMAIN: u32 = 0x5243_3030; // "RC00"

comptime {
    if (DIRECT_COUNT != 1 or LOGUP_COUNT != 2)
        @compileError("control proof adapter geometry drifted");
}

/// Binds every verifier-owned fact needed before relation challenges are
/// drawn. The preprocessing root itself is mixed by the PCS commit call.
pub fn mixStatementPrefix(
    channel: anytype,
    log_size: u32,
    proof_kind: proof_kind_mod.ProofKind,
) void {
    channel.mixU32s(&[_]u32{
        TRANSCRIPT_DOMAIN,
        TRANSCRIPT_FORMAT_VERSION,
        log_size,
        @intFromEnum(proof_kind),
        control.PREPROCESSED_COLUMN_COUNT,
        control.INTERACTION_COLUMN_COUNT,
        CONSTRAINT_COUNT,
    });
    channel.mixU32s(&digestWords(control.SEMANTIC_DIGEST));
    channel.mixU32s(&digestWords(
        @import("../../air/lang/relation.zig").registryOrderDigest(),
    ));
}

/// Matches pinned Stark-V ordering: claimed sums and their exact interaction
/// log-size geometry are absorbed before the interaction Merkle root.
pub fn mixInteractionClaim(
    channel: anytype,
    log_size: u32,
    claimed_sum: QM31,
) void {
    channel.mixFelts(&.{claimed_sum});
    channel.mixU64(control.INTERACTION_COLUMN_COUNT);
    for (0..control.INTERACTION_COLUMN_COUNT) |_| channel.mixU64(log_size);
}

pub const Component = struct {
    log_size: u32,
    parameters: [control.PROOF_KIND_PARAMETER_COUNT]M31,
    relations: *const universal.UniversalRelations,
    claimed_sum: QM31,
    claimed_sum_shift: QM31,
    direct: direct_program.Program,
    relation_plan: control_relation.Plan,

    const Adapter = core_air_derive.ComponentAdapter(
        @This(),
        prover_component.ComponentProver,
        prover_component.Trace,
        prover_air_accumulation.DomainEvaluationAccumulator,
    );

    /// Cold admission boundary. Both executable programs are sealed against
    /// the typed semantic digest before any proof-row evaluation can begin.
    pub fn init(
        definition: *const control.Definition,
        log_size: u32,
        proof_kind: proof_kind_mod.ProofKind,
        relations: *const universal.UniversalRelations,
        claimed_sum: QM31,
    ) !Component {
        if (log_size == 0 or log_size >= 31) return error.InvalidProofShape;
        try definition.validate();
        try relations.validate();
        const relation_plan = try control_relation.authenticate(definition);
        try relation_plan.validateAgainst(
            &definition.arena,
            control.SEMANTIC_DIGEST,
            definition.events,
        );
        const direct = try direct_program.authenticate(
            &definition.arena,
            control.SEMANTIC_DIGEST,
            control.LOGICAL_INPUT_COUNT,
        );
        const selectors = proof_kind.selectors();
        const n = M31.fromU64(@as(u64, 1) << @intCast(log_size));
        return .{
            .log_size = log_size,
            .parameters = selectors[0..control.PROOF_KIND_PARAMETER_COUNT].*,
            .relations = relations,
            .claimed_sum = claimed_sum,
            .claimed_sum_shift = try claimed_sum.divM31(n),
            .direct = direct,
            .relation_plan = relation_plan,
        };
    }

    pub fn asVerifierComponent(self: *const @This()) core_air_components.Component {
        return Adapter.asVerifierComponent(self);
    }

    pub fn asProverComponent(self: *const @This()) prover_component.ComponentProver {
        return Adapter.asProverComponent(self);
    }

    pub fn nConstraints(_: *const @This()) usize {
        return CONSTRAINT_COUNT;
    }

    pub fn maxConstraintLogDegreeBound(self: *const @This()) u32 {
        // Pairs-batched LogUp is cubic, hence one quotient blowup bit.
        return self.log_size + 1;
    }

    /// The standalone pilot commits the ten verifier-owned columns as tree 0
    /// and the eight framework interaction coordinates as tree 1. There is no
    /// dummy main tree because control has no physical main columns.
    pub fn traceLogDegreeBounds(
        self: *const @This(),
        allocator: std.mem.Allocator,
    ) !core_air_components.TraceLogDegreeBounds {
        const preprocessed = try filledLogs(
            allocator,
            control.PREPROCESSED_COLUMN_COUNT,
            self.log_size,
        );
        errdefer allocator.free(preprocessed);
        const interaction = try filledLogs(
            allocator,
            control.INTERACTION_COLUMN_COUNT,
            self.log_size,
        );
        errdefer allocator.free(interaction);
        return core_air_components.TraceLogDegreeBounds.initOwned(
            try allocator.dupe([]u32, &[_][]u32{ preprocessed, interaction }),
        );
    }

    pub fn maskPoints(
        _: *const @This(),
        allocator: std.mem.Allocator,
        point: CirclePointQM31,
        max_log_degree_bound: u32,
    ) !core_air_components.MaskPoints {
        const preprocessed = try currentPointColumns(
            allocator,
            control.PREPROCESSED_COLUMN_COUNT,
            point,
        );
        errdefer freeMaskColumns(allocator, preprocessed);

        const interaction = try allocator.alloc(
            []CirclePointQM31,
            control.INTERACTION_COLUMN_COUNT,
        );
        var initialized: usize = 0;
        errdefer {
            for (interaction[0..initialized]) |column| allocator.free(column);
            allocator.free(interaction);
        }
        for (interaction[0 .. 4 * (LOGUP_COUNT - 1)]) |*column| {
            column.* = try allocator.dupe(
                CirclePointQM31,
                &[_]CirclePointQM31{point},
            );
            initialized += 1;
        }
        const previous = logup.prevRowPoint(max_log_degree_bound, point);
        for (interaction[4 * (LOGUP_COUNT - 1) ..]) |*column| {
            column.* = try allocator.dupe(
                CirclePointQM31,
                &[_]CirclePointQM31{ previous, point },
            );
            initialized += 1;
        }
        return core_air_components.MaskPoints.initOwned(
            try allocator.dupe(
                [][]CirclePointQM31,
                &[_][][]CirclePointQM31{ preprocessed, interaction },
            ),
        );
    }

    pub fn preprocessedColumnIndices(
        _: *const @This(),
        allocator: std.mem.Allocator,
    ) ![]usize {
        const indices = try allocator.alloc(
            usize,
            control.PREPROCESSED_COLUMN_COUNT,
        );
        for (indices, 0..) |*value, index| value.* = index;
        return indices;
    }

    pub fn evaluateConstraintQuotientsAtPoint(
        self: *const @This(),
        point: CirclePointQM31,
        mask: *const core_air_components.MaskValues,
        accumulator: *core_air_accumulation.PointEvaluationAccumulator,
        max_log_degree_bound: u32,
    ) !void {
        // Generic proving appends the composition tree to the sampled-value
        // mask before this callback; the component owns only the first two.
        if (max_log_degree_bound < self.log_size or mask.items.len < 2)
            return error.InvalidProofShape;
        const preprocessed = mask.items[0];
        const interaction = mask.items[1];
        try validatePointMask(preprocessed, interaction);

        var row: control_relation.Runtime.SecureRow = undefined;
        for (row[0..control.PREPROCESSED_COLUMN_COUNT], preprocessed) |
            *value,
            column,
        | value.* = column[0];
        for (
            row[control.PREPROCESSED_COLUMN_COUNT..],
            self.parameters,
        ) |*value, parameter| value.* = QM31.fromBase(parameter);

        var direct_scratch: [direct_program.MAX_NODES]QM31 = undefined;
        var direct_roots: [DIRECT_COUNT]QM31 = undefined;
        try self.direct.evaluateSecureInto(
            &row,
            &direct_scratch,
            &direct_roots,
        );
        const pairs = try self.relation_plan.preparedSecureRowPairs(
            row,
            self.relations,
        );
        const partial = try sampledSecure(interaction, 0, 0);
        const final_previous = try sampledSecure(interaction, 4, 0);
        const final_current = try sampledSecure(interaction, 4, 1);

        const folded_point = point.repeatedDouble(
            max_log_degree_bound - self.log_size,
        );
        const denominator_inverse = try core_constraints.cosetVanishing(
            QM31,
            canonic.CanonicCoset.new(self.log_size).coset(),
            folded_point,
        ).inv();
        accumulator.accumulate(direct_roots[0].mul(denominator_inverse));
        accumulator.accumulate(frameworkConstraint(
            partial,
            QM31.zero(),
            QM31.zero(),
            QM31.zero(),
            pairs[0],
        ).mul(denominator_inverse));
        accumulator.accumulate(frameworkConstraint(
            final_current,
            final_previous,
            partial,
            self.claimed_sum_shift,
            pairs[1],
        ).mul(denominator_inverse));
    }

    pub fn evaluateConstraintQuotientsOnDomain(
        self: *const @This(),
        trace: *const prover_component.Trace,
        accumulator: *prover_air_accumulation.DomainEvaluationAccumulator,
    ) !void {
        if (trace.polys.items.len != 2 or
            trace.polys.items[0].len != control.PREPROCESSED_COLUMN_COUNT or
            trace.polys.items[1].len != control.INTERACTION_COLUMN_COUNT)
        {
            return error.InvalidProofShape;
        }

        const allocator = accumulator.allocator;
        const eval_log_size = self.log_size + 1;
        const eval_domain = canonic.CanonicCoset.new(eval_log_size).circleDomain();
        const eval_size = eval_domain.size();
        var evaluations: [
            control.PREPROCESSED_COLUMN_COUNT +
                control.INTERACTION_COLUMN_COUNT
        ][]const M31 = undefined;
        var extension_buffers = std.ArrayList([]M31).empty;
        defer {
            for (extension_buffers.items) |values| allocator.free(values);
            extension_buffers.deinit(allocator);
        }

        var source_index: usize = 0;
        for (trace.polys.items) |tree| {
            for (tree) |poly| {
                evaluations[source_index] = try evaluationOnDomain(
                    allocator,
                    poly,
                    self.log_size,
                    eval_log_size,
                    eval_size,
                    &extension_buffers,
                );
                source_index += 1;
            }
        }
        if (source_index != evaluations.len) return error.InvalidProofShape;
        if (extension_buffers.items.len != 0) {
            var twiddles = try prover_twiddles.precomputeM31(
                allocator,
                eval_domain.half_coset,
            );
            defer prover_twiddles.deinitM31(allocator, &twiddles);
            const view = prover_twiddles.TwiddleTree([]const M31).init(
                twiddles.root_coset,
                twiddles.twiddles,
                twiddles.itwiddles,
            );
            try prover_circle.poly.evaluateBuffersWithTwiddles(
                extension_buffers.items,
                eval_domain,
                view,
            );
        }

        const trace_coset = canonic.CanonicCoset.new(self.log_size).coset();
        const denominator_inverse = [_]M31{
            try core_constraints.cosetVanishing(
                M31,
                trace_coset,
                eval_domain.at(0),
            ).inv(),
            try core_constraints.cosetVanishing(
                M31,
                trace_coset,
                eval_domain.at(1),
            ).inv(),
        };
        var accumulators = try accumulator.columns(
            allocator,
            &[_]prover_air_accumulation.ColumnRequest{.{
                .log_size = eval_log_size,
                .n_cols = CONSTRAINT_COUNT,
            }},
        );
        defer allocator.free(accumulators);
        var column_accumulator = &accumulators[0];

        const preprocessed_start: usize = 0;
        const interaction_start: usize = control.PREPROCESSED_COLUMN_COUNT;
        const denominator_shift: std.math.Log2Int(usize) =
            @intCast(self.log_size);
        for (0..eval_size) |row_index| {
            const previous_row = utils.previousBitReversedCircleDomainIndex(
                row_index,
                self.log_size,
                eval_log_size,
            );
            var row: control_relation.Row = undefined;
            for (row[0..control.PREPROCESSED_COLUMN_COUNT], 0..) |
                *value,
                column,
            | value.* = evaluations[preprocessed_start + column][row_index];
            row[control.PREPROCESSED_COLUMN_COUNT..].* = self.parameters;

            var direct_scratch: [direct_program.MAX_NODES]M31 = undefined;
            var direct_roots: [DIRECT_COUNT]M31 = undefined;
            try self.direct.evaluateBaseInto(
                &row,
                &direct_scratch,
                &direct_roots,
            );
            const pairs = try self.relation_plan.preparedRowPairs(
                row,
                self.relations,
            );
            const partial = secureAt(
                evaluations[interaction_start .. interaction_start + 4],
                row_index,
            );
            const final_previous = secureAt(
                evaluations[interaction_start + 4 .. interaction_start + 8],
                previous_row,
            );
            const final_current = secureAt(
                evaluations[interaction_start + 4 .. interaction_start + 8],
                row_index,
            );
            const roots = [_]QM31{
                QM31.fromBase(direct_roots[0]),
                frameworkConstraint(
                    partial,
                    QM31.zero(),
                    QM31.zero(),
                    QM31.zero(),
                    pairs[0],
                ),
                frameworkConstraint(
                    final_current,
                    final_previous,
                    partial,
                    self.claimed_sum_shift,
                    pairs[1],
                ),
            };
            const powers = column_accumulator.random_coeff_powers;
            if (powers.len < CONSTRAINT_COUNT) return error.InvalidProofShape;
            var combined = QM31.zero();
            for (roots, 0..) |root, constraint_index| {
                combined = combined.add(
                    powers[powers.len - 1 - constraint_index].mul(root),
                );
            }
            column_accumulator.accumulate(
                row_index,
                combined.mulM31(
                    denominator_inverse[row_index >> denominator_shift],
                ),
            );
        }
    }

    /// Allocation-free base-field row evaluator used by local admission tests.
    pub fn evaluateBaseRowInto(
        self: *const @This(),
        row: control_relation.Row,
        first_partial: QM31,
        final_previous: QM31,
        final_current: QM31,
        roots: *[CONSTRAINT_COUNT]QM31,
    ) !void {
        var direct_scratch: [direct_program.MAX_NODES]M31 = undefined;
        var direct_roots: [DIRECT_COUNT]M31 = undefined;
        try self.direct.evaluateBaseInto(&row, &direct_scratch, &direct_roots);
        const pairs = try self.relation_plan.preparedRowPairs(
            row,
            self.relations,
        );
        roots.* = .{
            QM31.fromBase(direct_roots[0]),
            frameworkConstraint(
                first_partial,
                QM31.zero(),
                QM31.zero(),
                QM31.zero(),
                pairs[0],
            ),
            frameworkConstraint(
                final_current,
                final_previous,
                first_partial,
                self.claimed_sum_shift,
                pairs[1],
            ),
        };
    }
};

inline fn frameworkConstraint(
    current: QM31,
    previous_row: QM31,
    previous_column: QM31,
    shift: QM31,
    pair: logup.RowPair,
) QM31 {
    const numerator = pair.n1.mul(pair.d2).add(pair.n2.mul(pair.d1));
    const denominator = pair.d1.mul(pair.d2);
    return current.sub(previous_row).sub(previous_column).add(shift)
        .mul(denominator).sub(numerator);
}

fn validatePointMask(
    preprocessed: [][]QM31,
    interaction: [][]QM31,
) !void {
    if (preprocessed.len != control.PREPROCESSED_COLUMN_COUNT or
        interaction.len != control.INTERACTION_COLUMN_COUNT)
    {
        return error.InvalidProofShape;
    }
    for (preprocessed) |column| if (column.len != 1)
        return error.InvalidProofShape;
    for (interaction[0..4]) |column| if (column.len != 1)
        return error.InvalidProofShape;
    for (interaction[4..8]) |column| if (column.len != 2)
        return error.InvalidProofShape;
}

fn sampledSecure(
    columns: [][]QM31,
    base: usize,
    point_index: usize,
) !QM31 {
    var coordinates: [4]QM31 = undefined;
    for (0..4) |coordinate| {
        if (columns[base + coordinate].len <= point_index)
            return error.InvalidProofShape;
        coordinates[coordinate] = columns[base + coordinate][point_index];
    }
    return QM31.fromPartialEvals(coordinates);
}

fn secureAt(columns: []const []const M31, row: usize) QM31 {
    return QM31.fromM31(
        columns[0][row],
        columns[1][row],
        columns[2][row],
        columns[3][row],
    );
}

fn evaluationOnDomain(
    allocator: std.mem.Allocator,
    poly: prover_component.Poly,
    trace_log_size: u32,
    eval_log_size: u32,
    eval_size: usize,
    buffers: *std.ArrayList([]M31),
) ![]const M31 {
    try poly.validate();
    if (poly.log_size == eval_log_size) return poly.values;
    const coefficients = poly.coefficients orelse return error.InvalidProofShape;
    if (coefficients.logSize() != trace_log_size)
        return error.InvalidProofShape;
    const values = try allocator.alloc(M31, eval_size);
    errdefer allocator.free(values);
    const source = coefficients.coefficients();
    @memcpy(values[0..source.len], source);
    @memset(values[source.len..], M31.zero());
    try buffers.append(allocator, values);
    return values;
}

fn filledLogs(
    allocator: std.mem.Allocator,
    count: usize,
    log_size: u32,
) ![]u32 {
    const result = try allocator.alloc(u32, count);
    @memset(result, log_size);
    return result;
}

fn currentPointColumns(
    allocator: std.mem.Allocator,
    count: usize,
    point: CirclePointQM31,
) ![][]CirclePointQM31 {
    const columns = try allocator.alloc([]CirclePointQM31, count);
    var initialized: usize = 0;
    errdefer {
        for (columns[0..initialized]) |column| allocator.free(column);
        allocator.free(columns);
    }
    for (columns) |*column| {
        column.* = try allocator.dupe(
            CirclePointQM31,
            &[_]CirclePointQM31{point},
        );
        initialized += 1;
    }
    return columns;
}

fn freeMaskColumns(
    allocator: std.mem.Allocator,
    columns: [][]CirclePointQM31,
) void {
    for (columns) |column| allocator.free(column);
    allocator.free(columns);
}

fn digestWords(value: [32]u8) [8]u32 {
    var result: [8]u32 = undefined;
    for (&result, 0..) |*word, index| {
        word.* = std.mem.readInt(
            u32,
            value[index * @sizeOf(u32) ..][0..@sizeOf(u32)],
            .little,
        );
    }
    return result;
}

test "R-012 typed control adapter enforces exact source LogUp recurrence" {
    const control_witness = @import("control_witness.zig");

    var definition = try control.build(std.testing.allocator);
    defer definition.deinit();
    const relations = universal.UniversalRelations.dummy();
    const logical_rows = [_]control_relation.Row{
        control_witness.logicalRow(.{
            .segment_mask = 1,
            .binary_mask = 0,
            .verifier_id = 0,
            .sequence = 0,
            .tag = 7,
            .args = .{ 11, 13, 17, 19 },
            .terminal_mask = 0,
        }, .segment_leaf),
        control_witness.logicalRow(.{
            .segment_mask = 1,
            .binary_mask = 0,
            .verifier_id = 0,
            .sequence = 1,
            .tag = 23,
            .args = .{ 29, 31, 37, 41 },
            .terminal_mask = 1,
        }, .segment_leaf),
    };
    var interaction = try Framework.generatePrepared(
        std.testing.allocator,
        &(try control_relation.authenticate(&definition)),
        &logical_rows,
        4,
        &relations,
    );
    defer interaction.deinit(std.testing.allocator);
    const component = try Component.init(
        &definition,
        4,
        .segment_leaf,
        &relations,
        interaction.claimed_sum,
    );

    const size: usize = 1 << 4;
    for (0..size) |logical_row| {
        var row = [_]M31{M31.zero()} ** control.LOGICAL_INPUT_COUNT;
        if (logical_row < logical_rows.len) {
            row = logical_rows[logical_row];
        } else {
            row[control.PREPROCESSED_COLUMN_COUNT..].* = component.parameters;
        }
        const committed = framework.committedRow(logical_row, 4);
        const previous = framework.committedRow((logical_row + size - 1) % size, 4);
        var roots: [CONSTRAINT_COUNT]QM31 = undefined;
        try component.evaluateBaseRowInto(
            row,
            committedSecure(&interaction.columns, 0, committed),
            committedSecure(&interaction.columns, 1, previous),
            committedSecure(&interaction.columns, 1, committed),
            &roots,
        );
        for (roots) |root| try std.testing.expect(root.isZero());
    }

    interaction.columns[4][framework.committedRow(1, 4)] =
        interaction.columns[4][framework.committedRow(1, 4)].add(M31.one());
    var roots: [CONSTRAINT_COUNT]QM31 = undefined;
    try component.evaluateBaseRowInto(
        logical_rows[1],
        committedSecure(&interaction.columns, 0, framework.committedRow(1, 4)),
        committedSecure(&interaction.columns, 1, framework.committedRow(0, 4)),
        committedSecure(&interaction.columns, 1, framework.committedRow(1, 4)),
        &roots,
    );
    try std.testing.expect(!roots[2].isZero());

    var bounds = try component.traceLogDegreeBounds(std.testing.allocator);
    defer bounds.deinitDeep(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 2), bounds.items.len);
    try std.testing.expectEqual(
        @as(usize, control.INTERACTION_COLUMN_COUNT),
        bounds.items[1].len,
    );
}

fn committedSecure(
    columns: *const [control.INTERACTION_COLUMN_COUNT][]M31,
    secure_column: usize,
    row: usize,
) QM31 {
    return QM31.fromM31Array(.{
        columns[4 * secure_column][row],
        columns[4 * secure_column + 1][row],
        columns[4 * secure_column + 2][row],
        columns[4 * secure_column + 3][row],
    });
}
