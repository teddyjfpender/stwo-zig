//! RLCA/RRCA/RLA/RRA specialization of the shared family component.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const prover_air_accumulation = @import("stwo_prover_engine").air.accumulation;
const prover_component = @import("stwo_prover_engine").air.component_prover;
const execution = @import("execution.zig");
const family_component = @import("family_component.zig");
const rotate_accumulator = @import("rotate_accumulator.zig");
const runner = @import("../runner/mod.zig");

pub const N_CONSTRAINTS: usize = rotate_accumulator.N_BOUND_CONSTRAINTS + 1;
pub const Component = family_component.Component(rotate_accumulator);

test "accumulator rotate component rejects a carry mutation" {
    const component = Component{
        .log_size = 4,
        .is_active_main_column = execution.N_MAIN_COLUMNS,
        .execution_offset = 0,
        .main_offset = execution.N_MAIN_COLUMNS + 1,
    };
    try std.testing.expectEqual(N_CONSTRAINTS, component.nConstraints());
    _ = component.asVerifierComponent();
    _ = component.asProverComponent();

    var memory = try runner.Memory.init(std.testing.allocator);
    defer memory.deinit();
    memory.write(0, 0x17);
    var cpu = runner.Cpu{ .a = 0x80 };
    const step = try runner.step(&cpu, &memory);
    var values: [rotate_accumulator.N_MAIN_COLUMNS]QM31 = undefined;
    for (
        &values,
        rotate_accumulator.columns(
            try rotate_accumulator.ValidatedStep.init(step),
        ),
    ) |*value, source| {
        value.* = QM31.fromBase(source);
    }
    var machine_values: [execution.N_MAIN_COLUMNS]QM31 = undefined;
    for (&machine_values, execution.columns(step, 0)) |*value, source| {
        value.* = QM31.fromBase(source);
    }
    const machine = try execution.Row(QM31).fromColumns(&machine_values);
    try std.testing.expect(
        (try component.evaluateRow(&values, machine, QM31.one())).allZero(),
    );
    values[27] = QM31.zero();
    try std.testing.expect(
        !(try component.evaluateRow(&values, machine, QM31.one())).allZero(),
    );
}

test "accumulator rotate component prover-domain path rejects a carry mutation" {
    const allocator = std.testing.allocator;
    const component = Component{
        .log_size = 4,
        .is_active_main_column = execution.N_MAIN_COLUMNS,
        .execution_offset = 0,
        .main_offset = execution.N_MAIN_COLUMNS + 1,
    };
    const evaluation_log_size: u32 = 5;
    const evaluation_size: usize = 1 << evaluation_log_size;

    var memory = try runner.Memory.init(allocator);
    defer memory.deinit();
    memory.write(0, 0x17);
    var cpu = runner.Cpu{ .a = 0x80 };
    const step = try runner.step(&cpu, &memory);
    const witness = rotate_accumulator.columns(
        try rotate_accumulator.ValidatedStep.init(step),
    );
    const machine_witness = execution.columns(step, 0);

    var active_values = [_]M31{M31.one()} ** evaluation_size;
    var execution_values: [execution.N_MAIN_COLUMNS][evaluation_size]M31 =
        undefined;
    var execution_polynomials: [execution.N_MAIN_COLUMNS]prover_component.Poly =
        undefined;
    for (
        &execution_values,
        &execution_polynomials,
        machine_witness,
    ) |*values, *polynomial, value| {
        @memset(values, value);
        polynomial.* = .{ .log_size = evaluation_log_size, .values = values };
    }
    var main_values: [rotate_accumulator.N_MAIN_COLUMNS][evaluation_size]M31 =
        undefined;
    var main_polynomials: [rotate_accumulator.N_MAIN_COLUMNS]prover_component.Poly =
        undefined;
    for (&main_values, &main_polynomials, witness) |*values, *polynomial, value| {
        @memset(values, value);
        polynomial.* = .{ .log_size = evaluation_log_size, .values = values };
    }
    const active_polynomial = prover_component.Poly{
        .log_size = evaluation_log_size,
        .values = &active_values,
    };
    var preprocessed = [_]prover_component.Poly{};
    var combined: [execution.N_MAIN_COLUMNS + 1 + rotate_accumulator.N_MAIN_COLUMNS]prover_component.Poly =
        undefined;
    @memcpy(combined[0..execution.N_MAIN_COLUMNS], &execution_polynomials);
    combined[execution.N_MAIN_COLUMNS] = active_polynomial;
    @memcpy(combined[execution.N_MAIN_COLUMNS + 1 ..], &main_polynomials);
    var trees = [_][]const prover_component.Poly{ &preprocessed, &combined };
    const trace = prover_component.Trace{
        .polys = @import("stwo_core").pcs.TreeVec(
            []const prover_component.Poly,
        ).initOwned(&trees),
    };

    var honest = try prover_air_accumulation.DomainEvaluationAccumulator.init(
        allocator,
        QM31.one(),
        evaluation_log_size,
        N_CONSTRAINTS,
    );
    defer honest.deinit();
    try component.evaluateConstraintQuotientsOnDomain(&trace, &honest);
    var honest_result = try honest.finalize();
    defer honest_result.deinit(allocator);
    for (0..honest_result.len()) |row| {
        try std.testing.expect(honest_result.at(row).isZero());
    }

    @memset(&main_values[27], M31.zero());
    var mutated = try prover_air_accumulation.DomainEvaluationAccumulator.init(
        allocator,
        QM31.one(),
        evaluation_log_size,
        N_CONSTRAINTS,
    );
    defer mutated.deinit();
    try component.evaluateConstraintQuotientsOnDomain(&trace, &mutated);
    var mutated_result = try mutated.finalize();
    defer mutated_result.deinit(allocator);
    var saw_nonzero = false;
    for (0..mutated_result.len()) |row| {
        saw_nonzero = saw_nonzero or !mutated_result.at(row).isZero();
    }
    try std.testing.expect(saw_nonzero);
}
