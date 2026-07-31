//! LD r16 specialization of the shared execution-bound family component.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const accumulation = @import("stwo_prover_engine").air.accumulation;
const prover_component = @import("stwo_prover_engine").air.component_prover;
const execution = @import("execution.zig");
const family_component = @import("family_component.zig");
const load16 = @import("load16.zig");
const runner = @import("../runner/mod.zig");

pub const N_CONSTRAINTS: usize = load16.N_BOUND_CONSTRAINTS + 1;
pub const Component = family_component.Component(load16);

test "LOAD16 component rejects value and address mutations" {
    const component = Component{
        .log_size = 4,
        .is_active_main_column = execution.N_MAIN_COLUMNS,
        .execution_offset = 0,
        .main_offset = execution.N_MAIN_COLUMNS + 1,
    };
    try std.testing.expectEqual(N_CONSTRAINTS, component.nConstraints());
    try std.testing.expectEqual(@as(u32, 5), component.maxConstraintLogDegreeBound());
    _ = component.asVerifierComponent();
    _ = component.asProverComponent();

    var memory = try runner.Memory.init(std.testing.allocator);
    defer memory.deinit();
    memory.write(0, 0x08);
    memory.write(1, 0x00);
    memory.write(2, 0x80);
    var cpu = runner.Cpu{ .sp = 0x1234 };
    const step = try runner.step(&cpu, &memory);
    var values: [load16.N_MAIN_COLUMNS]QM31 = undefined;
    for (
        &values,
        load16.columns(try load16.ValidatedStep.init(step)),
    ) |*value, source| value.* = QM31.fromBase(source);
    var machine_values: [execution.N_MAIN_COLUMNS]QM31 = undefined;
    for (&machine_values, execution.columns(step, 0)) |*value, source|
        value.* = QM31.fromBase(source);
    const machine = try execution.Row(QM31).fromColumns(&machine_values);
    try std.testing.expect(
        (try component.evaluateRow(&values, machine, QM31.one())).allZero(),
    );
    values[7] = QM31.one();
    try std.testing.expect(
        !(try component.evaluateRow(&values, machine, QM31.one())).allZero(),
    );
    values[7] = QM31.zero();
    values[23] = QM31.one();
    try std.testing.expect(
        !(try component.evaluateRow(&values, machine, QM31.one())).allZero(),
    );
}

test "LOAD16 component domain rejects an absolute SP write mutation" {
    const allocator = std.testing.allocator;
    const component = Component{
        .log_size = 4,
        .is_active_main_column = execution.N_MAIN_COLUMNS,
        .execution_offset = 0,
        .main_offset = execution.N_MAIN_COLUMNS + 1,
    };
    const evaluation_log_size: comptime_int = 5;
    const evaluation_size = 1 << evaluation_log_size;

    var memory = try runner.Memory.init(allocator);
    defer memory.deinit();
    memory.write(0, 0x08);
    memory.write(1, 0x00);
    memory.write(2, 0x80);
    var cpu = runner.Cpu{ .sp = 0x1234 };
    const step = try runner.step(&cpu, &memory);
    const witness = load16.columns(try load16.ValidatedStep.init(step));
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
    var main_values: [load16.N_MAIN_COLUMNS][evaluation_size]M31 = undefined;
    var main_polynomials: [load16.N_MAIN_COLUMNS]prover_component.Poly =
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
    var combined: [execution.N_MAIN_COLUMNS + 1 + load16.N_MAIN_COLUMNS]prover_component.Poly =
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

    const challenge = QM31.fromU32Unchecked(3, 5, 7, 11);
    var honest = try accumulation.DomainEvaluationAccumulator.init(
        allocator,
        challenge,
        evaluation_log_size,
        N_CONSTRAINTS,
    );
    defer honest.deinit();
    try component.evaluateConstraintQuotientsOnDomain(&trace, &honest);
    var honest_result = try honest.finalize();
    defer honest_result.deinit(allocator);
    for (0..honest_result.len()) |row|
        try std.testing.expect(honest_result.at(row).isZero());

    const bus3_value =
        2 * execution.N_STATE_COLUMNS + 3 * execution.N_BUS_COLUMNS + 1;
    @memset(&execution_values[bus3_value], M31.fromCanonical(0x35));
    var mutated = try accumulation.DomainEvaluationAccumulator.init(
        allocator,
        challenge,
        evaluation_log_size,
        N_CONSTRAINTS,
    );
    defer mutated.deinit();
    try component.evaluateConstraintQuotientsOnDomain(&trace, &mutated);
    var mutated_result = try mutated.finalize();
    defer mutated_result.deinit(allocator);
    var saw_nonzero = false;
    for (0..mutated_result.len()) |row|
        saw_nonzero = saw_nonzero or !mutated_result.at(row).isZero();
    try std.testing.expect(saw_nonzero);
}
