//! RETI/DI/EI specialization of the shared execution-bound component.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const accumulation = @import("stwo_prover_engine").air.accumulation;
const prover_component = @import("stwo_prover_engine").air.component_prover;
const execution = @import("execution.zig");
const family_component = @import("family_component.zig");
const interrupt = @import("interrupt.zig");
const runner = @import("../runner/mod.zig");

pub const N_CONSTRAINTS: usize = interrupt.N_BOUND_CONSTRAINTS + 1;
pub const Component = family_component.Component(interrupt);

const test_component = Component{
    .log_size = 4,
    .is_active_main_column = execution.N_MAIN_COLUMNS,
    .execution_offset = 0,
    .main_offset = execution.N_MAIN_COLUMNS + 1,
};

fn interruptStep(opcode: u8) !runner.StepTrace {
    var memory = try runner.Memory.init(std.testing.allocator);
    defer memory.deinit();
    memory.write(0x4000, opcode);
    memory.write(0xffff, 0x34);
    memory.write(0, 0x12);
    var cpu = runner.Cpu{
        .f = 0xb0,
        .sp = 0xffff,
        .pc = 0x4000,
        .ime = false,
        .ime_enable_pending = opcode == 0xd9,
    };
    return runner.step(&cpu, &memory);
}

test "interrupt component rejects RETI state and EI pending mutations" {
    try std.testing.expectEqual(N_CONSTRAINTS, test_component.nConstraints());
    _ = test_component.asVerifierComponent();
    _ = test_component.asProverComponent();

    const reti = try interruptStep(0xd9);
    var values: [interrupt.N_MAIN_COLUMNS]QM31 = undefined;
    for (
        &values,
        interrupt.columns(try interrupt.ValidatedStep.init(reti)),
    ) |*value, source| value.* = QM31.fromBase(source);
    var machine_values: [execution.N_MAIN_COLUMNS]QM31 = undefined;
    for (&machine_values, execution.columns(reti, 0)) |*value, source|
        value.* = QM31.fromBase(source);
    var machine = try execution.Row(QM31).fromColumns(&machine_values);
    try std.testing.expect(
        (try test_component.evaluateRow(&values, machine, QM31.one())).allZero(),
    );
    inline for ([_]execution.StateIndex{ .pc, .sp, .ime }) |field| {
        machine = try execution.Row(QM31).fromColumns(&machine_values);
        machine.after.values[@intFromEnum(field)] =
            machine.after.values[@intFromEnum(field)].add(QM31.one());
        try std.testing.expect(
            !(try test_component.evaluateRow(
                &values,
                machine,
                QM31.one(),
            )).allZero(),
        );
    }

    const ei = try interruptStep(0xfb);
    for (
        &values,
        interrupt.columns(try interrupt.ValidatedStep.init(ei)),
    ) |*value, source| value.* = QM31.fromBase(source);
    for (&machine_values, execution.columns(ei, 0)) |*value, source|
        value.* = QM31.fromBase(source);
    machine = try execution.Row(QM31).fromColumns(&machine_values);
    machine.after.values[
        @intFromEnum(execution.StateIndex.ime_enable_pending)
    ] = QM31.zero();
    try std.testing.expect(
        !(try test_component.evaluateRow(
            &values,
            machine,
            QM31.one(),
        )).allZero(),
    );
}

test "interrupt component domain rejects a RETI stack-read mutation" {
    const allocator = std.testing.allocator;
    const log_size: u32 = 5;
    const size: usize = 1 << log_size;
    const step = try interruptStep(0xd9);
    const witness = interrupt.columns(try interrupt.ValidatedStep.init(step));
    const machine_witness = execution.columns(step, 0);

    var active_values = [_]M31{M31.one()} ** size;
    var execution_values: [execution.N_MAIN_COLUMNS][size]M31 = undefined;
    var execution_polynomials: [execution.N_MAIN_COLUMNS]prover_component.Poly =
        undefined;
    for (
        &execution_values,
        &execution_polynomials,
        machine_witness,
    ) |*values, *polynomial, value| {
        @memset(values, value);
        polynomial.* = .{ .log_size = log_size, .values = values };
    }
    var main_values: [interrupt.N_MAIN_COLUMNS][size]M31 = undefined;
    var main_polynomials: [interrupt.N_MAIN_COLUMNS]prover_component.Poly =
        undefined;
    for (&main_values, &main_polynomials, witness) |*values, *poly, value| {
        @memset(values, value);
        poly.* = .{ .log_size = log_size, .values = values };
    }
    const active = prover_component.Poly{
        .log_size = log_size,
        .values = &active_values,
    };
    var preprocessed = [_]prover_component.Poly{};
    var combined: [execution.N_MAIN_COLUMNS + 1 + interrupt.N_MAIN_COLUMNS]prover_component.Poly =
        undefined;
    @memcpy(combined[0..execution.N_MAIN_COLUMNS], &execution_polynomials);
    combined[execution.N_MAIN_COLUMNS] = active;
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
        log_size,
        N_CONSTRAINTS,
    );
    defer honest.deinit();
    try test_component.evaluateConstraintQuotientsOnDomain(&trace, &honest);
    var honest_result = try honest.finalize();
    defer honest_result.deinit(allocator);
    for (0..honest_result.len()) |row|
        try std.testing.expect(honest_result.at(row).isZero());

    const stack_read_value =
        2 * execution.N_STATE_COLUMNS + execution.N_BUS_COLUMNS + 1;
    @memset(
        &execution_values[stack_read_value],
        M31.fromCanonical(0x35),
    );
    var mutated = try accumulation.DomainEvaluationAccumulator.init(
        allocator,
        challenge,
        log_size,
        N_CONSTRAINTS,
    );
    defer mutated.deinit();
    try test_component.evaluateConstraintQuotientsOnDomain(&trace, &mutated);
    var result = try mutated.finalize();
    defer result.deinit(allocator);
    var rejected = false;
    for (0..result.len()) |row|
        rejected = rejected or !result.at(row).isZero();
    try std.testing.expect(rejected);
}
