//! DAA specialization of the shared execution-bound family component.

const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;
const daa = @import("daa.zig");
const execution = @import("execution.zig");
const family_component = @import("family_component.zig");
const runner = @import("../runner/mod.zig");

pub const N_CONSTRAINTS: usize = daa.N_BOUND_CONSTRAINTS + 1;
pub const Component = family_component.Component(daa);

test "DAA component rejects an execution-bound opcode mutation" {
    const component = Component{
        .log_size = 4,
        .is_active_main_column = execution.N_MAIN_COLUMNS + 1,
        .execution_offset = 0,
        .main_offset = execution.N_MAIN_COLUMNS + execution.N_FAMILY_SELECTORS +
            @import("alu8.zig").N_MAIN_COLUMNS,
    };
    try std.testing.expectEqual(N_CONSTRAINTS, component.nConstraints());
    _ = component.asVerifierComponent();
    _ = component.asProverComponent();

    var memory = try runner.Memory.init(std.testing.allocator);
    defer memory.deinit();
    memory.write(0, 0x27);
    var cpu = runner.Cpu{ .a = 0x9a };
    const step = try runner.step(&cpu, &memory);
    var values: [daa.N_MAIN_COLUMNS]QM31 = undefined;
    for (&values, daa.columns(try daa.ValidatedStep.init(step))) |*value, source| {
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
    machine_values[2 * execution.N_STATE_COLUMNS + 1] = QM31.fromBase(
        @import("stwo_core").fields.m31.M31.fromCanonical(0x2f),
    );
    try std.testing.expect(
        !(try component.evaluateRow(
            &values,
            try execution.Row(QM31).fromColumns(&machine_values),
            QM31.one(),
        )).allZero(),
    );
}
