const std = @import("std");
const core_air_accumulation = @import("stwo_core").air.accumulation;
const core_air_components = @import("stwo_core").air.components;
const circle = @import("stwo_core").circle;
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const pcs = @import("stwo_core").pcs;
const prover_air_accumulation = @import("stwo_prover_engine").air.accumulation;
const prover_component = @import("stwo_prover_engine").air.component_prover;
const SemanticComponent = @import("semantic_component.zig").SemanticComponent;
const semantic_eval = @import("semantic_eval.zig");
const trace = @import("../runner/trace.zig");

test "semantic component owns exact main bounds for every compatible family" {
    const allocator = std.testing.allocator;
    for (0..trace.N_FAMILIES) |index| {
        const family: trace.OpcodeFamily = @enumFromInt(index);
        if (!semantic_eval.isTraceCompatible(family)) {
            try std.testing.expectError(
                error.IncompatibleCommittedTrace,
                SemanticComponent.init(family, 4, 7, 11),
            );
            continue;
        }
        const component = try SemanticComponent.init(family, 4, 7, 11);
        try std.testing.expectEqual(semantic_eval.mainColumnCount(family), component.mainColumnCount());
        try std.testing.expectEqual(semantic_eval.constraintCount(family), component.nConstraints());
        _ = component.asVerifierComponent();
        _ = component.asProverComponent();

        var bounds = try component.traceLogDegreeBounds(allocator);
        defer bounds.deinitDeep(allocator);
        try std.testing.expectEqual(@as(usize, 3), bounds.items.len);
        try std.testing.expectEqual(@as(usize, 1), bounds.items[0].len);
        try std.testing.expectEqual(component.mainColumnCount(), bounds.items[1].len);
        try std.testing.expectEqual(@as(usize, 0), bounds.items[2].len);
        for (bounds.items[0]) |log_size| try std.testing.expectEqual(@as(u32, 4), log_size);
        for (bounds.items[1]) |log_size| try std.testing.expectEqual(@as(u32, 4), log_size);

        const indices = try component.preprocessedColumnIndices(allocator);
        defer allocator.free(indices);
        try std.testing.expectEqualSlices(usize, &.{7}, indices);
    }
}

test "semantic component delegates identical row semantics for every family" {
    var columns = [_]QM31{QM31.zero()} ** trace.MAX_FAMILY_COLUMNS;
    for (0..trace.N_FAMILIES) |index| {
        const family: trace.OpcodeFamily = @enumFromInt(index);
        if (!semantic_eval.isTraceCompatible(family)) continue;
        const component = try SemanticComponent.init(family, 4, 0, 0);
        const main = columns[0..component.mainColumnCount()];
        const expected = try semantic_eval.evaluate(family, main, QM31.zero());
        const actual = try component.evaluateRow(main, QM31.zero());
        try std.testing.expectEqual(expected.len, actual.len);
        for (expected.values[0..expected.len], actual.values[0..actual.len]) |lhs, rhs| {
            try std.testing.expect(lhs.eql(rhs));
        }
        try std.testing.expect(actual.allZero());
        try std.testing.expect(!(try component.evaluateRow(main, QM31.one())).allZero());
    }
}

test "semantic component OODS uses exact global offsets and rejects bad shapes" {
    const family: trace.OpcodeFamily = .base_alu_imm;
    const log_size: u32 = 4;
    const active_index: usize = 2;
    const main_offset: usize = 3;
    const component = try SemanticComponent.init(family, log_size, active_index, main_offset);
    const n_main = component.mainColumnCount();

    var preprocessed_storage = [_][1]QM31{.{QM31.fromU32Unchecked(17, 3, 5, 7)}} ** 4;
    preprocessed_storage[active_index][0] = QM31.zero();
    var preprocessed: [preprocessed_storage.len][]QM31 = undefined;
    for (&preprocessed, &preprocessed_storage) |*column, *values| column.* = values;
    var main_storage = [_][1]QM31{.{QM31.fromU32Unchecked(19, 2, 11, 13)}} **
        (trace.MAX_FAMILY_COLUMNS + main_offset + 2);
    for (main_storage[main_offset..][0..n_main]) |*value| value[0] = QM31.zero();
    var main: [main_storage.len][]QM31 = undefined;
    for (&main, &main_storage) |*column, *values| column.* = values;
    var interaction = [_][]QM31{};
    var trees = [_][][]QM31{ &preprocessed, &main, &interaction };
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

    preprocessed_storage[active_index][0] = QM31.one();
    var mutated = core_air_accumulation.PointEvaluationAccumulator.init(QM31.one());
    try component.evaluateConstraintQuotientsAtPoint(
        point,
        &mask,
        &mutated,
        component.maxConstraintLogDegreeBound(),
    );
    try std.testing.expect(!mutated.finalize().isZero());

    var ignored = core_air_accumulation.PointEvaluationAccumulator.init(QM31.one());
    try std.testing.expectError(
        error.InvalidProofShape,
        component.evaluateConstraintQuotientsAtPoint(point, &mask, &ignored, log_size - 1),
    );
    var short_trees = [_][][]QM31{
        &preprocessed,
        main[0 .. main_offset + n_main - 1],
        &interaction,
    };
    const short_mask = core_air_components.MaskValues.initOwned(&short_trees);
    try std.testing.expectError(
        error.InvalidProofShape,
        component.evaluateConstraintQuotientsAtPoint(
            point,
            &short_mask,
            &ignored,
            component.maxConstraintLogDegreeBound(),
        ),
    );
}

test "semantic component on-domain path observes the active selector" {
    const allocator = std.testing.allocator;
    const log_size: u32 = 4;
    const eval_log_size: u32 = log_size + 1;
    const eval_size = @as(usize, 1) << @intCast(eval_log_size);
    const active_index: usize = 2;
    const main_offset: usize = 3;
    const component = try SemanticComponent.init(.base_alu_imm, log_size, active_index, main_offset);
    const zero_values = try allocator.alloc(M31, eval_size);
    defer allocator.free(zero_values);
    @memset(zero_values, M31.zero());
    const one_values = try allocator.alloc(M31, eval_size);
    defer allocator.free(one_values);
    @memset(one_values, M31.one());
    const zero_poly = prover_component.Poly{ .log_size = eval_log_size, .values = zero_values };
    const one_poly = prover_component.Poly{ .log_size = eval_log_size, .values = one_values };
    var preprocessed = [_]prover_component.Poly{zero_poly} ** (active_index + 1);
    var main = [_]prover_component.Poly{zero_poly} **
        (trace.MAX_FAMILY_COLUMNS + main_offset);
    var interaction = [_]prover_component.Poly{};
    var trees = [_][]const prover_component.Poly{ &preprocessed, &main, &interaction };
    const trace_data = prover_component.Trace{
        .polys = pcs.TreeVec([]const prover_component.Poly).initOwned(&trees),
    };

    var honest = try prover_air_accumulation.DomainEvaluationAccumulator.init(
        allocator,
        QM31.one(),
        eval_log_size,
        component.nConstraints(),
    );
    defer honest.deinit();
    try component.evaluateConstraintQuotientsOnDomain(&trace_data, &honest);
    var honest_result = try honest.finalize();
    defer honest_result.deinit(allocator);
    for (0..honest_result.len()) |row| try std.testing.expect(honest_result.at(row).isZero());

    preprocessed[active_index] = one_poly;
    var mutated = try prover_air_accumulation.DomainEvaluationAccumulator.init(
        allocator,
        QM31.one(),
        eval_log_size,
        component.nConstraints(),
    );
    defer mutated.deinit();
    try component.evaluateConstraintQuotientsOnDomain(&trace_data, &mutated);
    var mutated_result = try mutated.finalize();
    defer mutated_result.deinit(allocator);
    var saw_nonzero = false;
    for (0..mutated_result.len()) |row| saw_nonzero = saw_nonzero or !mutated_result.at(row).isZero();
    try std.testing.expect(saw_nonzero);

    var short_trees = [_][]const prover_component.Poly{
        &preprocessed,
        main[0 .. main_offset + component.mainColumnCount() - 1],
        &interaction,
    };
    const short_trace = prover_component.Trace{
        .polys = pcs.TreeVec([]const prover_component.Poly).initOwned(&short_trees),
    };
    var shape = try prover_air_accumulation.DomainEvaluationAccumulator.init(
        allocator,
        QM31.one(),
        eval_log_size,
        component.nConstraints(),
    );
    defer shape.deinit();
    try std.testing.expectError(
        error.InvalidProofShape,
        component.evaluateConstraintQuotientsOnDomain(&short_trace, &shape),
    );
}

fn allocateMetadata(
    allocator: std.mem.Allocator,
    component: *const SemanticComponent,
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
}

test "semantic component metadata allocations roll back completely" {
    const component = try SemanticComponent.init(.base_alu_imm, 4, 7, 11);
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocateMetadata,
        .{&component},
    );
}
