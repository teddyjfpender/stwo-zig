//! Focused contract tests for coordinator-prepared opcode lookup evaluation.

const std = @import("std");
const core_air_accumulation = @import("stwo_core").air.accumulation;
const core_air_components = @import("stwo_core").air.components;
const circle = @import("stwo_core").circle;
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const pcs = @import("stwo_core").pcs;
const prover_air_accumulation = @import("stwo_prover_engine").air.accumulation;
const prover_component = @import("stwo_prover_engine").air.component_prover;
const infra = @import("../../infra_trace.zig");
const logup = @import("../logup.zig");
const relations_mod = @import("../relation_challenges.zig");
const trace = @import("../../runner/trace.zig");
const component_mod = @import("opcode_component.zig");
const entry = @import("entry.zig");
const opcode_entries = @import("opcode_entries.zig");
const opcode_interaction = @import("opcode_interaction.zig");
const support = @import("opcode_component_prepared_test_support.zig");
const row_window = @import("../lang/row_window.zig");

const OpcodeLookupComponent = component_mod.OpcodeLookupComponent;

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
        try component.mask_binding.validate();
        try std.testing.expectEqual(
            row_window.ComponentMaskBinding.Mode.compatibility,
            component.mask_binding.mode,
        );
        try std.testing.expectEqual(
            trace.nColumnsForFamily(family),
            component.mask_binding.borrowed_main_current_columns,
        );
        const source_hex = std.fmt.bytesToHex(
            component.mask_binding.geometry_source_digest,
            .lower,
        );
        try std.testing.expectEqualStrings(
            row_window.EXPECTED_NATIVE_PLAN_DIGEST_HEX[index],
            &source_hex,
        );
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

test "opcode lookup component: compiler-owned mask binding rejects corruption" {
    const relations = relations_mod.Relations.dummy();
    const claims = [_]QM31{QM31.zero()} ** entry.MAX_BATCHES;
    const component = try OpcodeLookupComponent.initVerifier(
        .div,
        4,
        0,
        0,
        0,
        &relations,
        claims[0..opcode_entries.batchCount(.div)],
    );
    var corrupted = component;
    corrupted.mask_binding.binding_digest[0] ^= 1;
    try std.testing.expectError(
        error.InvalidWindowDigest,
        corrupted.traceLogDegreeBounds(std.testing.allocator),
    );
    corrupted = component;
    corrupted.mask_binding.owned_interaction_current_previous_columns -= 4;
    try std.testing.expectError(
        error.InvalidWindowDigest,
        corrupted.maskPoints(
            std.testing.allocator,
            circle.SECURE_FIELD_CIRCLE_GEN,
            6,
        ),
    );
}

test "opcode lookup component: large domains expose coordinator-prepared leaf work" {
    const relations = relations_mod.Relations.dummy();
    const family: trace.OpcodeFamily = .base_alu_imm;
    const claims = [_]QM31{QM31.zero()} ** entry.MAX_BATCHES;
    const component = try OpcodeLookupComponent.initProver(
        family,
        12,
        0,
        0,
        0,
        &relations,
        claims[0..opcode_entries.batchCount(family)],
    );
    const prover = component.asProverComponent();
    try std.testing.expect(prover.prepare_domain_evaluator != null);
    try std.testing.expect(prover.domain_parallel_evaluator == null);
    try std.testing.expect(!prover.pool_exclusive_domain);
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
    );
    var sampled: [trace.MAX_FAMILY_COLUMNS]QM31 = undefined;
    const committed_row = placement.map(0);
    for (main_storage[0..n_main], sampled[0..n_main]) |column, *value| {
        value.* = QM31.fromBase(column[committed_row]);
    }
    var current = [_]QM31{QM31.zero()} ** entry.MAX_BATCHES;
    var previous = [_]QM31{QM31.zero()} ** entry.MAX_BATCHES;
    const previous_row = placement.map(size - 1);
    for (0..generated.n_batches) |batch| {
        current[batch] = secureAt(generated.columns[4 * batch ..][0..4], committed_row);
        previous[batch] = secureAt(generated.columns[4 * batch ..][0..4], previous_row);
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

test "opcode lookup component: prover construction rejects wrong claim count" {
    const relations = relations_mod.Relations.dummy();
    const claims = [_]QM31{QM31.zero()} ** entry.MAX_BATCHES;
    try std.testing.expectError(
        error.InvalidTraceShape,
        OpcodeLookupComponent.initProver(.div, 4, 0, 0, 0, &relations, claims[0..1]),
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

    var pp_storage = [_][1]QM31{.{QM31.fromU32Unchecked(17, 3, 5, 7)}} ** 4;
    pp_storage[is_first_col_idx][0] = QM31.one();
    var preprocessed: [pp_storage.len][]QM31 = undefined;
    for (&preprocessed, &pp_storage) |*column, *values| column.* = values;
    var main_storage = [_][1]QM31{.{QM31.fromU32Unchecked(19, 2, 11, 13)}} **
        (trace.MAX_FAMILY_COLUMNS + main_offset + 2);
    const committed_row = placement.map(0);
    const previous_row = placement.map(size - 1);
    for (main_columns[0..n_main], main_storage[main_offset..][0..n_main]) |column, *value| {
        value[0] = QM31.fromBase(column[committed_row]);
    }
    var main: [main_storage.len][]QM31 = undefined;
    for (&main, &main_storage) |*column, *values| column.* = values;
    var interaction_storage = [_][2]QM31{.{
        QM31.fromU32Unchecked(23, 17, 5, 3),
        QM31.fromU32Unchecked(29, 19, 7, 2),
    }} ** (opcode_interaction.MAX_COLUMNS + interaction_offset + 2);
    for (0..generated.n_batches) |batch| for (0..4) |coordinate| {
        interaction_storage[interaction_offset + 4 * batch + coordinate][0] =
            QM31.fromBase(generated.columns[4 * batch + coordinate][committed_row]);
        interaction_storage[interaction_offset + 4 * batch + coordinate][1] =
            QM31.fromBase(generated.columns[4 * batch + coordinate][previous_row]);
    };
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

const OpcodeFixture = support.OpcodeFixture;

fn expectPrepareError(
    expected: anyerror,
    component: *const OpcodeLookupComponent,
    trace_data: *const prover_component.Trace,
    accumulator_log_size: u32,
) !void {
    var accumulator = try prover_air_accumulation.DomainEvaluationAccumulator.init(
        std.testing.allocator,
        QM31.one(),
        accumulator_log_size,
        component.nConstraints(),
    );
    defer accumulator.deinit();
    try std.testing.expectError(
        expected,
        component.asProverComponent().prepareConstraintQuotientsOnDomain(
            std.testing.allocator,
            trace_data,
            &accumulator,
        ),
    );
}

test "opcode prepared domain: adversarial committed shapes fail closed" {
    const allocator = std.testing.allocator;
    const family: trace.OpcodeFamily = .base_alu_imm;
    const log_size: u32 = 4;
    var fixture: OpcodeFixture = undefined;
    try fixture.init(allocator, family, log_size);
    defer fixture.deinit();
    const relations = relations_mod.Relations.dummy();
    const claims = [_]QM31{QM31.zero()} ** entry.MAX_BATCHES;
    const component = try OpcodeLookupComponent.initProver(
        family,
        log_size,
        0,
        0,
        0,
        &relations,
        claims[0..opcode_entries.batchCount(family)],
    );

    var short_trees = [_][]const prover_component.Poly{
        fixture.trees[0],
        fixture.trees[1],
    };
    const short_trace = prover_component.Trace{
        .polys = pcs.TreeVec([]const prover_component.Poly).initOwned(&short_trees),
    };
    try expectPrepareError(
        error.InvalidProofShape,
        &component,
        &short_trace,
        fixture.eval_log_size,
    );
    var overflowing_offset = component;
    overflowing_offset.main_col_offset = std.math.maxInt(usize);
    try expectPrepareError(
        error.InvalidProofShape,
        &overflowing_offset,
        &fixture.trace_data,
        fixture.eval_log_size,
    );
    overflowing_offset = component;
    overflowing_offset.interaction_col_offset = std.math.maxInt(usize);
    try expectPrepareError(
        error.InvalidProofShape,
        &overflowing_offset,
        &fixture.trace_data,
        fixture.eval_log_size,
    );
    var impossible_log = component;
    impossible_log.log_size = std.math.maxInt(u32);
    try expectPrepareError(
        error.InvalidProofShape,
        &impossible_log,
        &fixture.trace_data,
        fixture.eval_log_size,
    );
    {
        const saved = fixture.main[0];
        defer fixture.main[0] = saved;
        fixture.main[0] = .{
            .log_size = fixture.eval_log_size - 1,
            .values = saved.values[0 .. fixture.eval_size / 2],
        };
        try expectPrepareError(
            error.InvalidProofShape,
            &component,
            &fixture.trace_data,
            fixture.eval_log_size,
        );
    }
    {
        const saved = fixture.secure[0];
        defer fixture.secure[0] = saved;
        fixture.secure[0].values = saved.values[0 .. saved.values.len - 1];
        try expectPrepareError(
            error.InvalidColumnLength,
            &component,
            &fixture.trace_data,
            fixture.eval_log_size,
        );
    }
}

fn secureAt(columns: []const []const M31, row: usize) QM31 {
    return QM31.fromM31(columns[0][row], columns[1][row], columns[2][row], columns[3][row]);
}
