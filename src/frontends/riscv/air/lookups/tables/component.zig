//! Generic prover/verifier AIR adapter for exact preprocessed lookup tables.

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
const logup = @import("../../logup.zig");
const relations_mod = @import("../../relation_challenges.zig");
const interaction = @import("interaction.zig");
const schema = @import("schema.zig");

const CirclePointQM31 = circle.CirclePointQM31;
const EMPTY_PREVIOUS: [interaction.N_COLUMNS][]const M31 = .{&.{}} ** interaction.N_COLUMNS;

pub const ConstructionMetadata = struct {
    kind: schema.Kind,
    log_size: u32,
    tuple_columns: usize,
    preprocessed_columns: usize,
    main_columns: usize,
    interaction_columns: usize,
    previous_masks: usize,
    constraints: usize,

    pub fn forKind(kind: schema.Kind) ConstructionMetadata {
        return .{
            .kind = kind,
            .log_size = schema.logSize(kind),
            .tuple_columns = schema.arity(kind),
            .preprocessed_columns = 1 + schema.arity(kind),
            .main_columns = 1,
            .interaction_columns = interaction.N_COLUMNS,
            .previous_masks = interaction.N_COLUMNS,
            .constraints = 1,
        };
    }
};

pub const LookupTableComponent = struct {
    kind: schema.Kind,
    is_first_col_idx: usize,
    tuple_col_indices: [schema.MAX_ARITY]usize,
    main_col_offset: usize,
    interaction_col_offset: usize,
    relations: *const relations_mod.Relations,
    claim: QM31,
    previous: [interaction.N_COLUMNS][]const M31 = EMPTY_PREVIOUS,

    const Adapter = core_air_derive.ComponentAdapter(
        @This(),
        prover_component.ComponentProver,
        prover_component.Trace,
        prover_air_accumulation.DomainEvaluationAccumulator,
    );

    pub fn initVerifier(
        kind: schema.Kind,
        is_first_col_idx: usize,
        tuple_col_indices: []const usize,
        main_col_offset: usize,
        interaction_col_offset: usize,
        relations: *const relations_mod.Relations,
        claim: QM31,
    ) !LookupTableComponent {
        return init(
            kind,
            is_first_col_idx,
            tuple_col_indices,
            main_col_offset,
            interaction_col_offset,
            relations,
            claim,
            EMPTY_PREVIOUS,
            false,
        );
    }

    pub fn initProver(
        kind: schema.Kind,
        is_first_col_idx: usize,
        tuple_col_indices: []const usize,
        main_col_offset: usize,
        interaction_col_offset: usize,
        relations: *const relations_mod.Relations,
        claim: QM31,
        previous: [interaction.N_COLUMNS][]const M31,
    ) !LookupTableComponent {
        return init(
            kind,
            is_first_col_idx,
            tuple_col_indices,
            main_col_offset,
            interaction_col_offset,
            relations,
            claim,
            previous,
            true,
        );
    }

    fn init(
        kind: schema.Kind,
        is_first_col_idx: usize,
        tuple_col_indices: []const usize,
        main_col_offset: usize,
        interaction_col_offset: usize,
        relations: *const relations_mod.Relations,
        claim: QM31,
        previous: [interaction.N_COLUMNS][]const M31,
        require_previous: bool,
    ) !LookupTableComponent {
        if (tuple_col_indices.len != schema.arity(kind)) return error.InvalidTraceShape;
        var stored_indices = [_]usize{0} ** schema.MAX_ARITY;
        for (tuple_col_indices, 0..) |column, index| {
            if (column == is_first_col_idx) return error.InvalidTraceShape;
            for (tuple_col_indices[0..index]) |prior| {
                if (column == prior) return error.InvalidTraceShape;
            }
            stored_indices[index] = column;
        }
        if (require_previous) {
            const expected_size = schema.size(kind);
            for (previous) |column| {
                if (column.len != expected_size) return error.InvalidTraceShape;
            }
        }
        return .{
            .kind = kind,
            .is_first_col_idx = is_first_col_idx,
            .tuple_col_indices = stored_indices,
            .main_col_offset = main_col_offset,
            .interaction_col_offset = interaction_col_offset,
            .relations = relations,
            .claim = claim,
            .previous = previous,
        };
    }

    pub fn metadata(self: *const @This()) ConstructionMetadata {
        return ConstructionMetadata.forKind(self.kind);
    }

    pub fn asProverComponent(self: *const @This()) prover_component.ComponentProver {
        return Adapter.asProverComponent(self);
    }

    pub fn asVerifierComponent(self: *const @This()) core_air_components.Component {
        return Adapter.asVerifierComponent(self);
    }

    pub fn nConstraints(_: *const @This()) usize {
        return 1;
    }

    pub fn maxConstraintLogDegreeBound(self: *const @This()) u32 {
        return schema.logSize(self.kind) + 1;
    }

    pub fn traceLogDegreeBounds(
        self: *const @This(),
        allocator: std.mem.Allocator,
    ) !core_air_components.TraceLogDegreeBounds {
        const log_size = schema.logSize(self.kind);
        const n_preprocessed = 1 + schema.arity(self.kind);
        const preprocessed = try allocator.alloc(u32, n_preprocessed);
        errdefer allocator.free(preprocessed);
        @memset(preprocessed, log_size);
        const main = try allocator.dupe(u32, &.{log_size});
        errdefer allocator.free(main);
        const secure = try allocator.alloc(u32, interaction.N_COLUMNS);
        errdefer allocator.free(secure);
        @memset(secure, log_size);
        return core_air_components.TraceLogDegreeBounds.initOwned(
            try allocator.dupe([]u32, &.{ preprocessed, main, secure }),
        );
    }

    pub fn maskPoints(
        self: *const @This(),
        allocator: std.mem.Allocator,
        point: CirclePointQM31,
        max_log_degree_bound: u32,
    ) !core_air_components.MaskPoints {
        if (max_log_degree_bound < schema.logSize(self.kind)) return error.InvalidProofShape;
        const preprocessed = try currentPointColumns(
            allocator,
            1 + schema.arity(self.kind),
            point,
        );
        errdefer freePointColumns(allocator, preprocessed);
        const main = try currentPointColumns(allocator, 1, point);
        errdefer freePointColumns(allocator, main);
        // The PCS folds a log-(k+1) commitment at a point derived from the
        // maximal composition domain. Shifting the request by that maximal
        // step becomes exactly one trace-row shift after folding.
        const previous_point = logup.prevRowPoint(max_log_degree_bound, point);
        const secure = try allocator.alloc([]CirclePointQM31, interaction.N_COLUMNS);
        var initialized_secure: usize = 0;
        errdefer {
            for (secure[0..initialized_secure]) |column| allocator.free(column);
            allocator.free(secure);
        }
        for (secure) |*column| {
            column.* = try allocator.dupe(CirclePointQM31, &.{ point, previous_point });
            initialized_secure += 1;
        }
        return core_air_components.MaskPoints.initOwned(
            try allocator.dupe([][]CirclePointQM31, &.{ preprocessed, main, secure }),
        );
    }

    pub fn preprocessedColumnIndices(
        self: *const @This(),
        allocator: std.mem.Allocator,
    ) ![]usize {
        const result = try allocator.alloc(usize, 1 + schema.arity(self.kind));
        result[0] = self.is_first_col_idx;
        @memcpy(result[1..], self.tuple_col_indices[0..schema.arity(self.kind)]);
        return result;
    }

    pub fn evaluateConstraintQuotientsAtPoint(
        self: *const @This(),
        point: CirclePointQM31,
        mask: *const core_air_components.MaskValues,
        accumulator: *core_air_accumulation.PointEvaluationAccumulator,
        max_log_degree_bound: u32,
    ) !void {
        const log_size = schema.logSize(self.kind);
        if (max_log_degree_bound < log_size or mask.items.len < 3)
            return error.InvalidProofShape;
        const preprocessed = mask.items[0];
        const main = mask.items[1];
        const secure = mask.items[2];
        if (preprocessed.len <= self.is_first_col_idx or
            main.len <= self.main_col_offset or
            main[self.main_col_offset].len < 1 or
            secure.len < self.interaction_col_offset + interaction.N_COLUMNS)
            return error.InvalidProofShape;

        var tuple: [schema.MAX_ARITY]QM31 = undefined;
        for (self.tuple_col_indices[0..schema.arity(self.kind)], tuple[0..schema.arity(self.kind)]) |column_index, *value| {
            if (preprocessed.len <= column_index or preprocessed[column_index].len < 1)
                return error.InvalidProofShape;
            value.* = preprocessed[column_index][0];
        }
        if (preprocessed[self.is_first_col_idx].len < 1) return error.InvalidProofShape;
        const current = try sampledSecure(secure, self.interaction_col_offset, 0);
        const previous = try sampledSecure(secure, self.interaction_col_offset, 1);
        const constraint = try self.evaluateRow(
            tuple[0..schema.arity(self.kind)],
            main[self.main_col_offset][0],
            current,
            previous,
            preprocessed[self.is_first_col_idx][0],
        );
        const fold = max_log_degree_bound - log_size;
        const denominator_inv = try core_constraints.cosetVanishing(
            QM31,
            canonic.CanonicCoset.new(log_size).coset(),
            point.repeatedDouble(fold),
        ).inv();
        accumulator.accumulate(constraint.mul(denominator_inv));
    }

    pub fn evaluateConstraintQuotientsOnDomain(
        self: *const @This(),
        trace: *const prover_component.Trace,
        accumulator: *prover_air_accumulation.DomainEvaluationAccumulator,
    ) !void {
        if (trace.polys.items.len < 3) return error.InvalidProofShape;
        const allocator = accumulator.allocator;
        const log_size = schema.logSize(self.kind);
        const eval_log_size = log_size + 1;
        const eval_domain = canonic.CanonicCoset.new(eval_log_size).circleDomain();
        const eval_size = eval_domain.size();
        const n_tuple = schema.arity(self.kind);
        const n_committed = 1 + n_tuple + 1 + interaction.N_COLUMNS;
        const n_sources = n_committed;
        const preprocessed = trace.polys.items[0];
        const main = trace.polys.items[1];
        const secure = trace.polys.items[2];
        if (preprocessed.len <= self.is_first_col_idx or
            main.len <= self.main_col_offset or
            secure.len < self.interaction_col_offset + interaction.N_COLUMNS)
            return error.InvalidProofShape;

        const committed = try allocator.alloc(prover_component.Poly, n_committed);
        defer allocator.free(committed);
        var committed_index: usize = 0;
        committed[committed_index] = preprocessed[self.is_first_col_idx];
        committed_index += 1;
        for (self.tuple_col_indices[0..n_tuple]) |column_index| {
            if (preprocessed.len <= column_index) return error.InvalidProofShape;
            committed[committed_index] = preprocessed[column_index];
            committed_index += 1;
        }
        committed[committed_index] = main[self.main_col_offset];
        committed_index += 1;
        for (0..interaction.N_COLUMNS) |coordinate| {
            committed[committed_index] = secure[self.interaction_col_offset + coordinate];
            committed_index += 1;
        }
        std.debug.assert(committed_index == n_committed);

        const evaluations = try allocator.alloc([]const M31, n_sources);
        defer allocator.free(evaluations);
        var source: usize = 0;
        for (committed) |poly| {
            try poly.validate();
            if (poly.log_size != eval_log_size) return error.InvalidProofShape;
            evaluations[source] = poly.values;
            source += 1;
        }

        std.debug.assert(source == n_sources);

        const trace_coset = canonic.CanonicCoset.new(log_size).coset();
        var denominator_inv: [2]M31 = undefined;
        for (&denominator_inv, 0..) |*inverse, index| {
            inverse.* = try core_constraints.cosetVanishing(
                M31,
                trace_coset,
                eval_domain.at(index),
            ).inv();
        }
        var accumulators = try accumulator.columns(
            allocator,
            &.{.{ .log_size = eval_log_size, .n_cols = 1 }},
        );
        defer allocator.free(accumulators);
        const column_accumulator = &accumulators[0];
        const tuple_start: usize = 1;
        const main_index = tuple_start + n_tuple;
        const interaction_start = main_index + 1;
        for (0..eval_size) |row| {
            const previous_row = utils.previousBitReversedCircleDomainIndex(
                row,
                log_size,
                eval_log_size,
            );
            var tuple: [schema.MAX_ARITY]QM31 = undefined;
            for (tuple[0..n_tuple], evaluations[tuple_start..][0..n_tuple]) |*value, column| {
                value.* = QM31.fromBase(column[row]);
            }
            const constraint = try self.evaluateRow(
                tuple[0..n_tuple],
                QM31.fromBase(evaluations[main_index][row]),
                secureAt(evaluations[interaction_start..][0..interaction.N_COLUMNS], row),
                secureAt(
                    evaluations[interaction_start..][0..interaction.N_COLUMNS],
                    previous_row,
                ),
                QM31.fromBase(evaluations[0][row]),
            );
            column_accumulator.accumulate(
                row,
                column_accumulator.random_coeff_powers[0]
                    .mul(constraint)
                    .mulM31(denominator_inv[row >> @intCast(log_size)]),
            );
        }
    }

    pub fn evaluateRow(
        self: *const @This(),
        tuple: []const QM31,
        signed_multiplicity: QM31,
        current: QM31,
        previous: QM31,
        is_first: QM31,
    ) !QM31 {
        return interaction.evaluate(
            self.kind,
            tuple,
            signed_multiplicity,
            current,
            previous,
            is_first,
            self.claim,
            self.relations,
        );
    }
};

fn currentPointColumns(
    allocator: std.mem.Allocator,
    n_columns: usize,
    point: CirclePointQM31,
) ![][]CirclePointQM31 {
    const result = try allocator.alloc([]CirclePointQM31, n_columns);
    var initialized: usize = 0;
    errdefer {
        for (result[0..initialized]) |column| allocator.free(column);
        allocator.free(result);
    }
    for (result) |*column| {
        column.* = try allocator.dupe(CirclePointQM31, &.{point});
        initialized += 1;
    }
    return result;
}

fn freePointColumns(allocator: std.mem.Allocator, columns: [][]CirclePointQM31) void {
    for (columns) |column| allocator.free(column);
    allocator.free(columns);
}

fn sampledSecure(columns: [][]QM31, offset: usize, point: usize) !QM31 {
    var coordinates: [interaction.N_COLUMNS]QM31 = undefined;
    for (&coordinates, 0..) |*value, index| {
        if (columns.len <= offset + index or columns[offset + index].len <= point)
            return error.InvalidProofShape;
        value.* = columns[offset + index][point];
    }
    return QM31.fromPartialEvals(coordinates);
}

fn secureAt(columns: []const []const M31, row: usize) QM31 {
    return QM31.fromM31(columns[0][row], columns[1][row], columns[2][row], columns[3][row]);
}

fn secureTuple(tuple: schema.Tuple) [schema.MAX_ARITY]QM31 {
    var result: [schema.MAX_ARITY]QM31 = .{QM31.zero()} ** schema.MAX_ARITY;
    for (tuple.slice(), result[0..tuple.len]) |value, *dst| dst.* = QM31.fromBase(value);
    return result;
}

test "lookup table component: construction metadata pins all schemas" {
    const expected_logs = [_]u32{ 18, 20, 19, 20, 16, 15 };
    const expected_arities = [_]usize{ 4, 1, 2, 3, 2, 2 };
    for (0..schema.KIND_COUNT) |index| {
        const kind: schema.Kind = @enumFromInt(index);
        const metadata = ConstructionMetadata.forKind(kind);
        try std.testing.expectEqual(expected_logs[index], metadata.log_size);
        try std.testing.expectEqual(expected_arities[index], metadata.tuple_columns);
        try std.testing.expectEqual(1 + expected_arities[index], metadata.preprocessed_columns);
        try std.testing.expectEqual(@as(usize, 1), metadata.main_columns);
        try std.testing.expectEqual(@as(usize, 4), metadata.interaction_columns);
        try std.testing.expectEqual(@as(usize, 4), metadata.previous_masks);
        try std.testing.expectEqual(@as(usize, 1), metadata.constraints);
    }
}

test "lookup table component: verifier construction exposes exact masks and columns" {
    const allocator = std.testing.allocator;
    const relations = relations_mod.Relations.dummy();
    const component = try LookupTableComponent.initVerifier(
        .range_check_8_8_4,
        3,
        &.{ 7, 8, 9 },
        11,
        13,
        &relations,
        QM31.zero(),
    );
    const verifier = component.asVerifierComponent();
    try std.testing.expectEqual(@as(usize, 1), verifier.nConstraints());
    try std.testing.expectEqual(@as(u32, 21), verifier.maxConstraintLogDegreeBound());
    const indices = try verifier.preprocessedColumnIndices(allocator);
    defer allocator.free(indices);
    try std.testing.expectEqualSlices(usize, &.{ 3, 7, 8, 9 }, indices);

    var bounds = try verifier.traceLogDegreeBounds(allocator);
    defer bounds.deinitDeep(allocator);
    try std.testing.expectEqual(@as(usize, 3), bounds.items.len);
    try std.testing.expectEqual(@as(usize, 4), bounds.items[0].len);
    try std.testing.expectEqual(@as(usize, 1), bounds.items[1].len);
    try std.testing.expectEqual(@as(usize, 4), bounds.items[2].len);

    var masks = try verifier.maskPoints(
        allocator,
        circle.SECURE_FIELD_CIRCLE_GEN,
        verifier.maxConstraintLogDegreeBound(),
    );
    defer masks.deinitDeep(allocator);
    try std.testing.expectEqual(@as(usize, 4), masks.items[0].len);
    try std.testing.expectEqual(@as(usize, 1), masks.items[1].len);
    for (masks.items[2]) |column| try std.testing.expectEqual(@as(usize, 2), column.len);
}

test "lookup table component: singleton identity rejects all placement mutations" {
    const allocator = std.testing.allocator;
    const relations = relations_mod.Relations.dummy();
    const kind: schema.Kind = .range_check_8_8;
    const tuple0 = try schema.tupleAt(kind, 1);
    const tuple1 = try schema.tupleAt(kind, 258);
    const signed_multiplicity = M31.one().neg();
    const pairs = [_]logup.RowPair{
        try interaction.rowPair(kind, tuple0, signed_multiplicity, &relations),
        try interaction.rowPair(kind, tuple1, signed_multiplicity, &relations),
    };
    var cumulative = try logup.cumulativeColumn(allocator, &pairs);
    defer cumulative.deinit(allocator);
    const component = try LookupTableComponent.initVerifier(
        kind,
        0,
        &.{ 1, 2 },
        0,
        0,
        &relations,
        cumulative.claimed,
    );
    const secure0 = secureTuple(tuple0);
    const secure1 = secureTuple(tuple1);
    const multiplicity = QM31.fromBase(signed_multiplicity);

    try std.testing.expect((try component.evaluateRow(
        secure0[0..tuple0.len],
        multiplicity,
        cumulative.sums[0],
        cumulative.sums[1],
        QM31.one(),
    )).isZero());
    try std.testing.expect((try component.evaluateRow(
        secure1[0..tuple1.len],
        multiplicity,
        cumulative.sums[1],
        cumulative.sums[0],
        QM31.zero(),
    )).isZero());

    var bad_tuple = secure0;
    bad_tuple[0] = bad_tuple[0].add(QM31.one());
    try std.testing.expect(!(try component.evaluateRow(
        bad_tuple[0..tuple0.len],
        multiplicity,
        cumulative.sums[0],
        cumulative.sums[1],
        QM31.one(),
    )).isZero());
    try std.testing.expect(!(try component.evaluateRow(
        secure0[0..tuple0.len],
        multiplicity.add(QM31.one()),
        cumulative.sums[0],
        cumulative.sums[1],
        QM31.one(),
    )).isZero());

    var bad_claim = component;
    bad_claim.claim = bad_claim.claim.add(QM31.one());
    try std.testing.expect(!(try bad_claim.evaluateRow(
        secure0[0..tuple0.len],
        multiplicity,
        cumulative.sums[0],
        cumulative.sums[1],
        QM31.one(),
    )).isZero());
    try std.testing.expect(!(try component.evaluateRow(
        secure1[0..tuple1.len],
        multiplicity,
        cumulative.sums[1],
        cumulative.sums[1],
        QM31.zero(),
    )).isZero());
}

test "lookup table component: OODS adapter enforces predecessor ordering" {
    const allocator = std.testing.allocator;
    const relations = relations_mod.Relations.dummy();
    const kind: schema.Kind = .range_check_8_8;
    const table_tuple = try schema.tupleAt(kind, 258);
    const signed_multiplicity = M31.one().neg();
    const pairs = [_]logup.RowPair{
        try interaction.rowPair(kind, table_tuple, signed_multiplicity, &relations),
    };
    var cumulative = try logup.cumulativeColumn(allocator, &pairs);
    defer cumulative.deinit(allocator);
    const component = try LookupTableComponent.initVerifier(
        kind,
        0,
        &.{ 1, 2 },
        0,
        0,
        &relations,
        cumulative.claimed,
    );

    var is_first_values = [_]QM31{QM31.one()};
    var tuple0_values = [_]QM31{QM31.fromBase(table_tuple.values[0])};
    var tuple1_values = [_]QM31{QM31.fromBase(table_tuple.values[1])};
    var preprocessed = [_][]QM31{
        &is_first_values,
        &tuple0_values,
        &tuple1_values,
    };
    var multiplicity_values = [_]QM31{QM31.fromBase(signed_multiplicity)};
    var main = [_][]QM31{&multiplicity_values};
    const current_coordinates = cumulative.sums[0].toM31Array();
    const previous_coordinates = cumulative.sums[0].toM31Array();
    var coordinate0 = [_]QM31{
        QM31.fromBase(current_coordinates[0]),
        QM31.fromBase(previous_coordinates[0]),
    };
    var coordinate1 = [_]QM31{
        QM31.fromBase(current_coordinates[1]),
        QM31.fromBase(previous_coordinates[1]),
    };
    var coordinate2 = [_]QM31{
        QM31.fromBase(current_coordinates[2]),
        QM31.fromBase(previous_coordinates[2]),
    };
    var coordinate3 = [_]QM31{
        QM31.fromBase(current_coordinates[3]),
        QM31.fromBase(previous_coordinates[3]),
    };
    var secure = [_][]QM31{ &coordinate0, &coordinate1, &coordinate2, &coordinate3 };
    var trees = [_][][]QM31{ &preprocessed, &main, &secure };
    const mask = core_air_components.MaskValues.initOwned(&trees);
    const point = circle.SECURE_FIELD_CIRCLE_GEN.mul(29);
    var honest = core_air_accumulation.PointEvaluationAccumulator.init(QM31.one());
    try component.evaluateConstraintQuotientsAtPoint(
        point,
        &mask,
        &honest,
        component.maxConstraintLogDegreeBound(),
    );
    try std.testing.expect(honest.finalize().isZero());

    coordinate0[1] = coordinate0[1].add(QM31.one());
    var reordered = core_air_accumulation.PointEvaluationAccumulator.init(QM31.one());
    try component.evaluateConstraintQuotientsAtPoint(
        point,
        &mask,
        &reordered,
        component.maxConstraintLogDegreeBound(),
    );
    try std.testing.expect(!reordered.finalize().isZero());
}

test "lookup table component: constructors fail closed on ambiguous bindings" {
    const relations = relations_mod.Relations.dummy();
    try std.testing.expectError(
        error.InvalidTraceShape,
        LookupTableComponent.initVerifier(.range_check_8_8, 0, &.{1}, 0, 0, &relations, QM31.zero()),
    );
    try std.testing.expectError(
        error.InvalidTraceShape,
        LookupTableComponent.initVerifier(.range_check_8_8, 0, &.{ 1, 1 }, 0, 0, &relations, QM31.zero()),
    );
    try std.testing.expectError(
        error.InvalidTraceShape,
        LookupTableComponent.initVerifier(.range_check_8_8, 0, &.{ 0, 1 }, 0, 0, &relations, QM31.zero()),
    );
    try std.testing.expectError(
        error.InvalidTraceShape,
        LookupTableComponent.initProver(
            .range_check_m31,
            0,
            &.{ 1, 2 },
            0,
            0,
            &relations,
            QM31.zero(),
            EMPTY_PREVIOUS,
        ),
    );
}

test "lookup table component: prover construction binds exact previous buffers" {
    const allocator = std.testing.allocator;
    const relations = relations_mod.Relations.dummy();
    const kind: schema.Kind = .range_check_m31;
    const previous_column = try allocator.alloc(M31, schema.size(kind));
    defer allocator.free(previous_column);
    @memset(previous_column, M31.zero());
    const previous = [_][]const M31{
        previous_column,
        previous_column,
        previous_column,
        previous_column,
    };
    const component = try LookupTableComponent.initProver(
        kind,
        0,
        &.{ 1, 2 },
        3,
        4,
        &relations,
        QM31.zero(),
        previous,
    );
    const prover = component.asProverComponent();
    try std.testing.expectEqual(@as(usize, 1), prover.nConstraints());
    try std.testing.expectEqual(@as(u32, 16), prover.maxConstraintLogDegreeBound());
}
