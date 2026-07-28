//! Prover/verifier AIR adapter for exact opcode-family lookup placement.
//!
//! Direct instruction constraints and the main-column declaration remain owned
//! by the semantic component. This adapter borrows those already-opened columns
//! by global offset and owns only its interaction columns. Declaring the main
//! columns here too would duplicate the main tree because core AIR orchestration
//! only aliases preprocessed columns. Every declaration-order relation batch is
//! reconstructed through `opcode_entries.fromMain`.

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
const infra = @import("../../infra_trace.zig");
const logup = @import("../logup.zig");
const relations_mod = @import("../relation_challenges.zig");
const trace = @import("../../runner/trace.zig");
const entry = @import("entry.zig");
const opcode_entries = @import("opcode_entries.zig");
const opcode_interaction = @import("opcode_interaction.zig");

const CirclePointQM31 = circle.CirclePointQM31;
const EMPTY_PREVIOUS: [entry.MAX_BATCHES][4][]const M31 =
    .{.{ &.{}, &.{}, &.{}, &.{} }} ** entry.MAX_BATCHES;

pub const Evaluation = struct {
    values: [entry.MAX_BATCHES]QM31 = .{QM31.zero()} ** entry.MAX_BATCHES,
    len: usize = 0,

    pub fn allZero(self: Evaluation) bool {
        for (self.values[0..self.len]) |value| {
            if (!value.isZero()) return false;
        }
        return true;
    }
};

pub const OpcodeLookupComponent = struct {
    family: trace.OpcodeFamily,
    log_size: u32,
    is_first_col_idx: usize,
    main_col_offset: usize,
    interaction_col_offset: usize,
    relations: *const relations_mod.Relations,
    claims: [entry.MAX_BATCHES]QM31,
    previous: [entry.MAX_BATCHES][4][]const M31 = EMPTY_PREVIOUS,

    const Adapter = core_air_derive.ComponentAdapter(
        @This(),
        prover_component.ComponentProver,
        prover_component.Trace,
        prover_air_accumulation.DomainEvaluationAccumulator,
    );

    pub fn initVerifier(
        family: trace.OpcodeFamily,
        log_size: u32,
        is_first_col_idx: usize,
        main_col_offset: usize,
        interaction_col_offset: usize,
        relations: *const relations_mod.Relations,
        claims: []const QM31,
    ) !OpcodeLookupComponent {
        return init(
            family,
            log_size,
            is_first_col_idx,
            main_col_offset,
            interaction_col_offset,
            relations,
            claims,
            EMPTY_PREVIOUS,
            false,
        );
    }

    pub fn initProver(
        family: trace.OpcodeFamily,
        log_size: u32,
        is_first_col_idx: usize,
        main_col_offset: usize,
        interaction_col_offset: usize,
        relations: *const relations_mod.Relations,
        claims: []const QM31,
        previous: [entry.MAX_BATCHES][4][]const M31,
    ) !OpcodeLookupComponent {
        return init(
            family,
            log_size,
            is_first_col_idx,
            main_col_offset,
            interaction_col_offset,
            relations,
            claims,
            previous,
            true,
        );
    }

    fn init(
        family: trace.OpcodeFamily,
        log_size: u32,
        is_first_col_idx: usize,
        main_col_offset: usize,
        interaction_col_offset: usize,
        relations: *const relations_mod.Relations,
        claims: []const QM31,
        previous: [entry.MAX_BATCHES][4][]const M31,
        require_previous: bool,
    ) !OpcodeLookupComponent {
        const n_batches = opcode_entries.batchCount(family);
        if (claims.len != n_batches) return error.InvalidTraceShape;
        if (require_previous) {
            const size = @as(usize, 1) << @intCast(log_size);
            for (previous[0..n_batches]) |set| {
                for (set) |column| {
                    if (column.len != size) return error.InvalidTraceShape;
                }
            }
        }
        var stored_claims = [_]QM31{QM31.zero()} ** entry.MAX_BATCHES;
        @memcpy(stored_claims[0..n_batches], claims);
        return .{
            .family = family,
            .log_size = log_size,
            .is_first_col_idx = is_first_col_idx,
            .main_col_offset = main_col_offset,
            .interaction_col_offset = interaction_col_offset,
            .relations = relations,
            .claims = stored_claims,
            .previous = previous,
        };
    }

    pub fn asProverComponent(self: *const @This()) prover_component.ComponentProver {
        return Adapter.asProverComponent(self);
    }

    pub fn asVerifierComponent(self: *const @This()) core_air_components.Component {
        return Adapter.asVerifierComponent(self);
    }

    pub fn nConstraints(self: *const @This()) usize {
        return opcode_entries.batchCount(self.family);
    }

    pub fn maxConstraintLogDegreeBound(self: *const @This()) u32 {
        return self.log_size + 1;
    }

    pub fn traceLogDegreeBounds(
        self: *const @This(),
        allocator: std.mem.Allocator,
    ) !core_air_components.TraceLogDegreeBounds {
        const preprocessed = try allocator.dupe(u32, &.{self.log_size});
        errdefer allocator.free(preprocessed);
        // The semantic component owns these shared main columns. Main-tree
        // bounds are concatenated by core orchestration, so aliases must not be
        // declared a second time.
        const main = try allocator.alloc(u32, 0);
        errdefer allocator.free(main);
        const secure = try allocator.alloc(u32, opcode_entries.interactionColumnCount(self.family));
        errdefer allocator.free(secure);
        @memset(secure, self.log_size);
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
        if (max_log_degree_bound < self.log_size) return error.InvalidProofShape;
        const preprocessed = try currentPointColumns(allocator, 1, point);
        errdefer freePointColumns(allocator, preprocessed);
        // The semantic owner already requests the shared main columns at the
        // current point. Returning them here would append duplicate masks.
        const main = try currentPointColumns(allocator, 0, point);
        errdefer freePointColumns(allocator, main);
        const previous_point = logup.prevRowPoint(max_log_degree_bound, point);
        const secure = try currentAndPreviousPointColumns(
            allocator,
            opcode_entries.interactionColumnCount(self.family),
            point,
            previous_point,
        );
        errdefer freePointColumns(allocator, secure);
        return core_air_components.MaskPoints.initOwned(
            try allocator.dupe([][]CirclePointQM31, &.{ preprocessed, main, secure }),
        );
    }

    pub fn preprocessedColumnIndices(
        self: *const @This(),
        allocator: std.mem.Allocator,
    ) ![]usize {
        return allocator.dupe(usize, &.{self.is_first_col_idx});
    }

    pub fn evaluateConstraintQuotientsAtPoint(
        self: *const @This(),
        point: CirclePointQM31,
        mask: *const core_air_components.MaskValues,
        accumulator: *core_air_accumulation.PointEvaluationAccumulator,
        max_log_degree_bound: u32,
    ) !void {
        if (max_log_degree_bound < self.log_size or mask.items.len < 3)
            return error.InvalidProofShape;
        const preprocessed = mask.items[0];
        const main = mask.items[1];
        const secure = mask.items[2];
        const n_main = trace.nColumnsForFamily(self.family);
        const n_interaction = opcode_entries.interactionColumnCount(self.family);
        if (preprocessed.len <= self.is_first_col_idx or
            preprocessed[self.is_first_col_idx].len < 1 or
            main.len < self.main_col_offset + n_main or
            secure.len < self.interaction_col_offset + n_interaction)
            return error.InvalidProofShape;

        var sampled: [trace.MAX_FAMILY_COLUMNS]QM31 = undefined;
        for (sampled[0..n_main], main[self.main_col_offset..][0..n_main]) |*value, column| {
            if (column.len < 1) return error.InvalidProofShape;
            value.* = column[0];
        }
        var current = [_]QM31{QM31.zero()} ** entry.MAX_BATCHES;
        var previous = [_]QM31{QM31.zero()} ** entry.MAX_BATCHES;
        for (0..self.nConstraints()) |batch| {
            current[batch] = try sampledSecure(secure, self.interaction_col_offset + 4 * batch, 0);
            previous[batch] = try sampledSecure(secure, self.interaction_col_offset + 4 * batch, 1);
        }
        const evaluation = try self.evaluateRow(
            sampled[0..n_main],
            current[0..self.nConstraints()],
            previous[0..self.nConstraints()],
            preprocessed[self.is_first_col_idx][0],
        );
        const fold = max_log_degree_bound - self.log_size;
        const denominator_inv = try core_constraints.cosetVanishing(
            QM31,
            canonic.CanonicCoset.new(self.log_size).coset(),
            point.repeatedDouble(fold),
        ).inv();
        for (evaluation.values[0..evaluation.len]) |constraint| {
            accumulator.accumulate(constraint.mul(denominator_inv));
        }
    }

    pub fn evaluateConstraintQuotientsOnDomain(
        self: *const @This(),
        trace_data: *const prover_component.Trace,
        accumulator: *prover_air_accumulation.DomainEvaluationAccumulator,
    ) !void {
        if (trace_data.polys.items.len < 3) return error.InvalidProofShape;
        const allocator = accumulator.allocator;
        const eval_log_size = self.log_size + 1;
        const eval_domain = canonic.CanonicCoset.new(eval_log_size).circleDomain();
        const eval_size = eval_domain.size();
        const n_main = trace.nColumnsForFamily(self.family);
        const n_interaction = opcode_entries.interactionColumnCount(self.family);
        const preprocessed = trace_data.polys.items[0];
        const main = trace_data.polys.items[1];
        const secure = trace_data.polys.items[2];
        if (preprocessed.len <= self.is_first_col_idx or
            main.len < self.main_col_offset + n_main or
            secure.len < self.interaction_col_offset + n_interaction)
            return error.InvalidProofShape;

        const n_sources = 1 + n_main + n_interaction;
        const evaluations = try allocator.alloc([]const M31, n_sources);
        defer allocator.free(evaluations);
        var source: usize = 0;
        evaluations[source] = try committedValues(preprocessed[self.is_first_col_idx], eval_log_size);
        source += 1;
        for (main[self.main_col_offset..][0..n_main]) |poly| {
            evaluations[source] = try committedValues(poly, eval_log_size);
            source += 1;
        }
        for (secure[self.interaction_col_offset..][0..n_interaction]) |poly| {
            evaluations[source] = try committedValues(poly, eval_log_size);
            source += 1;
        }

        std.debug.assert(source == n_sources);

        const denominator_inv = try quotientDenominators(
            allocator,
            self.log_size,
            eval_log_size,
            eval_domain,
        );
        defer allocator.free(denominator_inv);
        var accumulators = try accumulator.columns(
            allocator,
            &.{.{ .log_size = eval_log_size, .n_cols = self.nConstraints() }},
        );
        defer allocator.free(accumulators);
        const column_accumulator = &accumulators[0];
        const main_start: usize = 1;
        const interaction_start = main_start + n_main;
        for (0..eval_size) |row| {
            const previous_row = utils.previousBitReversedCircleDomainIndex(
                row,
                self.log_size,
                eval_log_size,
            );
            var sampled: [trace.MAX_FAMILY_COLUMNS]QM31 = undefined;
            for (sampled[0..n_main], evaluations[main_start..][0..n_main]) |*value, column| {
                value.* = QM31.fromBase(column[row]);
            }
            var current = [_]QM31{QM31.zero()} ** entry.MAX_BATCHES;
            var previous = [_]QM31{QM31.zero()} ** entry.MAX_BATCHES;
            for (0..self.nConstraints()) |batch| {
                current[batch] = secureAt(evaluations[interaction_start + 4 * batch ..][0..4], row);
                previous[batch] = secureAt(
                    evaluations[interaction_start + 4 * batch ..][0..4],
                    previous_row,
                );
            }
            const evaluation = try self.evaluateRow(
                sampled[0..n_main],
                current[0..self.nConstraints()],
                previous[0..self.nConstraints()],
                QM31.fromBase(evaluations[0][row]),
            );
            var folded = QM31.zero();
            for (evaluation.values[0..evaluation.len], 0..) |constraint, index| {
                const powers = column_accumulator.random_coeff_powers;
                folded = folded.add(powers[powers.len - 1 - index].mul(constraint));
            }
            column_accumulator.accumulate(
                row,
                folded.mulM31(denominator_inv[row >> @intCast(self.log_size)]),
            );
        }
    }

    pub fn evaluateRow(
        self: *const @This(),
        main: []const QM31,
        current: []const QM31,
        previous: []const QM31,
        is_first: QM31,
    ) !Evaluation {
        const n_batches = self.nConstraints();
        if (main.len != trace.nColumnsForFamily(self.family) or
            current.len != n_batches or previous.len != n_batches)
            return error.InvalidTraceShape;
        const entries = try opcode_entries.fromMain(self.family, main);
        if (entries.batchCount() != n_batches) return error.InvalidBatchCount;
        var result = Evaluation{ .len = n_batches };
        for (0..n_batches) |batch| {
            result.values[batch] = logup.pairConstraint(
                current[batch],
                previous[batch],
                is_first,
                self.claims[batch],
                try entries.pair(batch, self.relations),
            );
        }
        return result;
    }
};

fn committedValues(poly: prover_component.Poly, expected_log_size: u32) ![]const M31 {
    try poly.validate();
    if (poly.log_size != expected_log_size) return error.InvalidProofShape;
    return poly.values;
}

fn sampledSecure(columns: [][]QM31, offset: usize, point: usize) !QM31 {
    if (columns.len < offset + 4) return error.InvalidProofShape;
    var coordinates: [4]QM31 = undefined;
    for (&coordinates, 0..) |*value, index| {
        if (columns[offset + index].len <= point) return error.InvalidProofShape;
        value.* = columns[offset + index][point];
    }
    return QM31.fromPartialEvals(coordinates);
}

fn secureAt(columns: []const []const M31, row: usize) QM31 {
    return QM31.fromM31(columns[0][row], columns[1][row], columns[2][row], columns[3][row]);
}

fn quotientDenominators(
    allocator: std.mem.Allocator,
    log_size: u32,
    eval_log_size: u32,
    eval_domain: anytype,
) ![]M31 {
    const extension_bits: u5 = @intCast(eval_log_size - log_size);
    const result = try allocator.alloc(M31, @as(usize, 1) << extension_bits);
    errdefer allocator.free(result);
    const coset = canonic.CanonicCoset.new(log_size).coset();
    for (result, 0..) |*inverse, index| {
        inverse.* = try core_constraints.cosetVanishing(
            M31,
            coset,
            eval_domain.at(utils.bitReverseIndex(index, extension_bits)),
        ).inv();
    }
    return result;
}

fn currentPointColumns(
    allocator: std.mem.Allocator,
    count: usize,
    point: CirclePointQM31,
) ![][]CirclePointQM31 {
    const result = try allocator.alloc([]CirclePointQM31, count);
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

fn currentAndPreviousPointColumns(
    allocator: std.mem.Allocator,
    count: usize,
    point: CirclePointQM31,
    previous: CirclePointQM31,
) ![][]CirclePointQM31 {
    const result = try allocator.alloc([]CirclePointQM31, count);
    var initialized: usize = 0;
    errdefer {
        for (result[0..initialized]) |column| allocator.free(column);
        allocator.free(result);
    }
    for (result) |*column| {
        column.* = try allocator.dupe(CirclePointQM31, &.{ point, previous });
        initialized += 1;
    }
    return result;
}

fn freePointColumns(allocator: std.mem.Allocator, columns: [][]CirclePointQM31) void {
    for (columns) |column| allocator.free(column);
    allocator.free(columns);
}

fn activeAddiRow() trace.TraceRow {
    return .{
        .clk = 1,
        .pc = 0x1000,
        .opcode = .ADDI,
        .rd = 1,
        .rs1 = 0,
        .rs2 = 0,
        .imm = 1,
        .rs1_val = 0,
        .rs2_val = 0,
        .rd_val = 1,
        .rd_prev_val = 0,
        .rd_prev_clk = 0,
        .mem_addr = 0,
        .mem_val = 0,
        .is_load = false,
        .is_store = false,
        .branch_taken = false,
        .next_pc = 0x1004,
        .inst_word = 0x0010_0093,
    };
}

test "opcode lookup component: every family has exact variable-width metadata" {
    const relations = relations_mod.Relations.dummy();
    for (0..trace.N_FAMILIES) |index| {
        const family: trace.OpcodeFamily = @enumFromInt(index);
        const n_batches = opcode_entries.batchCount(family);
        const claims = [_]QM31{QM31.zero()} ** entry.MAX_BATCHES;
        const component = try OpcodeLookupComponent.initVerifier(
            family,
            4,
            0,
            0,
            0,
            &relations,
            claims[0..n_batches],
        );
        try std.testing.expectEqual(n_batches, component.nConstraints());
        var bounds = try component.traceLogDegreeBounds(std.testing.allocator);
        defer bounds.deinitDeep(std.testing.allocator);
        try std.testing.expectEqual(
            opcode_entries.interactionColumnCount(family),
            bounds.items[2].len,
        );
        try std.testing.expectEqual(@as(usize, 0), bounds.items[1].len);
        _ = component.asVerifierComponent();
    }
}

test "opcode lookup component: generated active row satisfies every batch" {
    const allocator = std.testing.allocator;
    const family: trace.OpcodeFamily = .base_alu_imm;
    const log_size: u32 = 4;
    const size = @as(usize, 1) << @intCast(log_size);
    const n_main = trace.nColumnsForFamily(family);
    var main_storage: [trace.MAX_FAMILY_COLUMNS][]M31 = undefined;
    for (main_storage[0..n_main]) |*column| {
        column.* = try allocator.alloc(M31, size);
        @memset(column.*, M31.zero());
    }
    defer for (main_storage[0..n_main]) |column| allocator.free(column);
    const placement = try infra.BitReversalTable.init(allocator, log_size);
    defer placement.deinit(allocator);
    trace.fillFamilyColumns(&main_storage, placement.map(0), activeAddiRow(), family);
    const relations = relations_mod.Relations.dummy();
    var generated = try opcode_interaction.generate(
        allocator,
        family,
        main_storage[0..n_main],
        log_size,
        &relations,
    );
    defer generated.deinit(allocator);
    const component = try OpcodeLookupComponent.initProver(
        family,
        log_size,
        0,
        0,
        0,
        &relations,
        generated.claims[0..generated.n_batches],
        generated.previous,
    );
    _ = component.asProverComponent();
    var sampled: [trace.MAX_FAMILY_COLUMNS]QM31 = undefined;
    const committed_row = placement.map(0);
    for (main_storage[0..n_main], sampled[0..n_main]) |column, *value| {
        value.* = QM31.fromBase(column[committed_row]);
    }
    var current = [_]QM31{QM31.zero()} ** entry.MAX_BATCHES;
    var previous = [_]QM31{QM31.zero()} ** entry.MAX_BATCHES;
    for (0..generated.n_batches) |batch| {
        current[batch] = secureAt(generated.columns[4 * batch ..][0..4], committed_row);
        previous[batch] = secureAt(&generated.previous[batch], committed_row);
    }
    const honest = try component.evaluateRow(
        sampled[0..n_main],
        current[0..generated.n_batches],
        previous[0..generated.n_batches],
        QM31.one(),
    );
    try std.testing.expect(honest.allZero());
    current[0] = current[0].add(QM31.one());
    const mutated = try component.evaluateRow(
        sampled[0..n_main],
        current[0..generated.n_batches],
        previous[0..generated.n_batches],
        QM31.one(),
    );
    try std.testing.expect(!mutated.allZero());
}

test "opcode lookup component: prover construction rejects incomplete predecessor masks" {
    const relations = relations_mod.Relations.dummy();
    const n_batches = opcode_entries.batchCount(.div);
    const claims = [_]QM31{QM31.zero()} ** entry.MAX_BATCHES;
    try std.testing.expectError(
        error.InvalidTraceShape,
        OpcodeLookupComponent.initProver(
            .div,
            4,
            0,
            0,
            0,
            &relations,
            claims[0..n_batches],
            EMPTY_PREVIOUS,
        ),
    );
}

test "opcode lookup component: OODS uses exact global offsets" {
    const allocator = std.testing.allocator;
    const family: trace.OpcodeFamily = .base_alu_imm;
    const log_size: u32 = 4;
    const size = @as(usize, 1) << @intCast(log_size);
    const n_main = trace.nColumnsForFamily(family);
    const n_interaction = opcode_entries.interactionColumnCount(family);
    const main_offset: usize = 3;
    const interaction_offset: usize = 5;
    const is_first_col_idx: usize = 2;
    var main_columns: [trace.MAX_FAMILY_COLUMNS][]M31 = undefined;
    for (main_columns[0..n_main]) |*column| {
        column.* = try allocator.alloc(M31, size);
        @memset(column.*, M31.zero());
    }
    defer for (main_columns[0..n_main]) |column| allocator.free(column);
    const placement = try infra.BitReversalTable.init(allocator, log_size);
    defer placement.deinit(allocator);
    trace.fillFamilyColumns(&main_columns, placement.map(0), activeAddiRow(), family);
    const relations = relations_mod.Relations.dummy();
    var generated = try opcode_interaction.generate(
        allocator,
        family,
        main_columns[0..n_main],
        log_size,
        &relations,
    );
    defer generated.deinit(allocator);
    const component = try OpcodeLookupComponent.initVerifier(
        family,
        log_size,
        is_first_col_idx,
        main_offset,
        interaction_offset,
        &relations,
        generated.claims[0..generated.n_batches],
    );

    var preprocessed_storage = [_][1]QM31{.{QM31.fromU32Unchecked(17, 3, 5, 7)}} ** 4;
    preprocessed_storage[is_first_col_idx][0] = QM31.one();
    var preprocessed: [preprocessed_storage.len][]QM31 = undefined;
    for (&preprocessed, &preprocessed_storage) |*column, *values| column.* = values;

    var main_storage = [_][1]QM31{.{QM31.fromU32Unchecked(19, 2, 11, 13)}} **
        (trace.MAX_FAMILY_COLUMNS + main_offset + 2);
    const committed_row = placement.map(0);
    for (main_columns[0..n_main], main_storage[main_offset..][0..n_main]) |column, *value| {
        value[0] = QM31.fromBase(column[committed_row]);
    }
    var main: [main_storage.len][]QM31 = undefined;
    for (&main, &main_storage) |*column, *values| column.* = values;

    var interaction_storage = [_][2]QM31{.{
        QM31.fromU32Unchecked(23, 17, 5, 3),
        QM31.fromU32Unchecked(29, 19, 7, 2),
    }} ** (opcode_interaction.MAX_COLUMNS + interaction_offset + 2);
    for (0..generated.n_batches) |batch| {
        for (0..4) |coordinate| {
            interaction_storage[interaction_offset + 4 * batch + coordinate][0] =
                QM31.fromBase(generated.columns[4 * batch + coordinate][committed_row]);
            interaction_storage[interaction_offset + 4 * batch + coordinate][1] =
                QM31.fromBase(generated.previous[batch][coordinate][committed_row]);
        }
    }
    var secure: [interaction_storage.len][]QM31 = undefined;
    for (&secure, &interaction_storage) |*column, *values| column.* = values;
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

    interaction_storage[interaction_offset][0] =
        interaction_storage[interaction_offset][0].add(QM31.one());
    var mutated = core_air_accumulation.PointEvaluationAccumulator.init(QM31.one());
    try component.evaluateConstraintQuotientsAtPoint(
        point,
        &mask,
        &mutated,
        component.maxConstraintLogDegreeBound(),
    );
    try std.testing.expect(!mutated.finalize().isZero());
    try std.testing.expectEqual(n_interaction, 4 * generated.n_batches);
}

fn allocateAdapterMetadata(
    allocator: std.mem.Allocator,
    component: *const OpcodeLookupComponent,
) !void {
    var bounds = try component.traceLogDegreeBounds(allocator);
    defer bounds.deinitDeep(allocator);
    var masks = try component.maskPoints(
        allocator,
        circle.SECURE_FIELD_CIRCLE_GEN,
        component.maxConstraintLogDegreeBound() + 2,
    );
    defer masks.deinitDeep(allocator);
    const indices = try component.preprocessedColumnIndices(allocator);
    defer allocator.free(indices);
    const expected_previous = logup.prevRowPoint(
        component.maxConstraintLogDegreeBound() + 2,
        circle.SECURE_FIELD_CIRCLE_GEN,
    );
    for (masks.items[2]) |column| {
        try std.testing.expectEqual(@as(usize, 2), column.len);
        try std.testing.expect(column[1].x.eql(expected_previous.x));
        try std.testing.expect(column[1].y.eql(expected_previous.y));
    }
}

test "opcode lookup component: metadata allocations roll back completely" {
    const relations = relations_mod.Relations.dummy();
    const claims = [_]QM31{QM31.zero()} ** entry.MAX_BATCHES;
    const component = try OpcodeLookupComponent.initVerifier(
        .div,
        4,
        7,
        11,
        13,
        &relations,
        claims[0..opcode_entries.batchCount(.div)],
    );
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocateAdapterMetadata,
        .{&component},
    );
}
