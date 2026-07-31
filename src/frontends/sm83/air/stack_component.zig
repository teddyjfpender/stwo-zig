//! PUSH/POP specialization of the shared execution-bound family component.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const accumulation = @import("stwo_prover_engine").air.accumulation;
const prover_component = @import("stwo_prover_engine").air.component_prover;
const execution = @import("execution.zig");
const family_component = @import("family_component.zig");
const stack = @import("stack.zig");
const runner = @import("../runner/mod.zig");

pub const N_CONSTRAINTS: usize = stack.N_BOUND_CONSTRAINTS + 1;
pub const Component = family_component.Component(stack);

const test_component = Component{
    .log_size = 4,
    .is_active_main_column = execution.N_MAIN_COLUMNS,
    .execution_offset = 0,
    .main_offset = execution.N_MAIN_COLUMNS + 1,
};

fn stackStep(opcode: u8) !runner.StepTrace {
    var memory = try runner.Memory.init(std.testing.allocator);
    defer memory.deinit();
    memory.write(0x4000, opcode);
    memory.write(0xffff, 0x3f);
    memory.write(0, 0xa5);
    var cpu = runner.Cpu{
        .a = 0x12,
        .b = 0x12,
        .c = 0x34,
        .f = 0xf0,
        .sp = if (opcode == 0xc5) 0 else 0xffff,
        .pc = 0x4000,
    };
    return runner.step(&cpu, &memory);
}

test "stack component rejects AF SP and result mutations" {
    try std.testing.expectEqual(N_CONSTRAINTS, test_component.nConstraints());
    _ = test_component.asVerifierComponent();
    _ = test_component.asProverComponent();

    const step = try stackStep(0xf1);
    var values: [stack.N_MAIN_COLUMNS]QM31 = undefined;
    for (
        &values,
        stack.columns(try stack.ValidatedStep.init(step)),
    ) |*value, source| value.* = QM31.fromBase(source);
    var machine_values: [execution.N_MAIN_COLUMNS]QM31 = undefined;
    for (&machine_values, execution.columns(step, 0)) |*value, source|
        value.* = QM31.fromBase(source);
    var machine = try execution.Row(QM31).fromColumns(&machine_values);
    try std.testing.expect(
        (try test_component.evaluateRow(&values, machine, QM31.one())).allZero(),
    );
    machine.after.values[@intFromEnum(execution.StateIndex.f)] =
        QM31.fromBase(M31.fromCanonical(0x3f));
    try std.testing.expect(
        !(try test_component.evaluateRow(&values, machine, QM31.one())).allZero(),
    );
    machine = try execution.Row(QM31).fromColumns(&machine_values);
    machine.after.values[@intFromEnum(execution.StateIndex.sp)] =
        QM31.fromBase(M31.zero());
    try std.testing.expect(
        !(try test_component.evaluateRow(&values, machine, QM31.one())).allZero(),
    );
    machine = try execution.Row(QM31).fromColumns(&machine_values);
    machine.after.values[@intFromEnum(execution.StateIndex.a)] =
        QM31.fromBase(M31.fromCanonical(0xa4));
    try std.testing.expect(
        !(try test_component.evaluateRow(&values, machine, QM31.one())).allZero(),
    );
}

test "stack component domain rejects PUSH order and POP value mutations" {
    const allocator = std.testing.allocator;
    const log_size: u32 = 5;
    const size: usize = 1 << log_size;
    const push = try stackStep(0xc5);
    const pop = try stackStep(0xf1);
    const push_main = stack.columns(try stack.ValidatedStep.init(push));
    const pop_main = stack.columns(try stack.ValidatedStep.init(pop));
    const push_machine = execution.columns(push, 0);
    const pop_machine = execution.columns(pop, 0);

    var active_values = [_]M31{M31.one()} ** size;
    var execution_values: [execution.N_MAIN_COLUMNS][size]M31 = undefined;
    var execution_polynomials: [execution.N_MAIN_COLUMNS]prover_component.Poly =
        undefined;
    for (&execution_values, &execution_polynomials, 0..) |*values, *poly, column| {
        for (values, 0..) |*value, row|
            value.* = if (row & 1 == 0)
                push_machine[column]
            else
                pop_machine[column];
        poly.* = .{ .log_size = log_size, .values = values };
    }
    var main_values: [stack.N_MAIN_COLUMNS][size]M31 = undefined;
    var main_polynomials: [stack.N_MAIN_COLUMNS]prover_component.Poly = undefined;
    for (&main_values, &main_polynomials, 0..) |*values, *poly, column| {
        for (values, 0..) |*value, row|
            value.* = if (row & 1 == 0) push_main[column] else pop_main[column];
        poly.* = .{ .log_size = log_size, .values = values };
    }
    const active = prover_component.Poly{
        .log_size = log_size,
        .values = &active_values,
    };
    var preprocessed = [_]prover_component.Poly{};
    var combined: [execution.N_MAIN_COLUMNS + 1 + stack.N_MAIN_COLUMNS]prover_component.Poly =
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

    const bus = 2 * execution.N_STATE_COLUMNS;
    for (0..size) |row| {
        if (row & 1 == 0) {
            for (0..execution.N_BUS_COLUMNS) |column| {
                std.mem.swap(
                    M31,
                    &execution_values[bus + 2 * execution.N_BUS_COLUMNS + column][row],
                    &execution_values[bus + 3 * execution.N_BUS_COLUMNS + column][row],
                );
            }
        } else {
            execution_values[bus + execution.N_BUS_COLUMNS + 1][row] =
                M31.fromCanonical(0x3e);
        }
    }
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
    for (0..result.len()) |row| rejected = rejected or !result.at(row).isZero();
    try std.testing.expect(rejected);
}
