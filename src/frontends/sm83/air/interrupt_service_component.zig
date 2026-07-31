//! Interrupt-service specialization of the shared execution-bound component.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const accumulation = @import("stwo_prover_engine").air.accumulation;
const prover_component = @import("stwo_prover_engine").air.component_prover;
const execution = @import("execution.zig");
const family_component = @import("family_component.zig");
const interrupt_service = @import("interrupt_service.zig");
const machine = @import("../runner/machine.zig");
const runner = @import("../runner/mod.zig");

pub const N_CONSTRAINTS: usize = interrupt_service.N_BOUND_CONSTRAINTS + 1;
pub const Component = family_component.Component(interrupt_service);

const test_component = Component{
    .log_size = 4,
    .is_active_main_column = execution.N_MAIN_COLUMNS,
    .execution_offset = 0,
    .main_offset = execution.N_MAIN_COLUMNS + 1,
};

fn interruptService() machine.CartridgeStepResult {
    const before_cpu = runner.Cpu{
        .a = 7,
        .sp = 0xc000,
        .pc = 0x1234,
        .ime = true,
    };
    var after_cpu = before_cpu;
    after_cpu.sp = 0xbffe;
    after_cpu.pc = 0x40;
    after_cpu.ime = false;
    var service = machine.CartridgeServiceTrace{};
    service.append(.dummy_read, serviceAccess(0x1234, .read, 0x5a));
    service.append(.oam_bug, null);
    service.append(.no_access, null);
    service.append(.stack_high, serviceAccess(0xbfff, .write, 0x12));
    service.ie_resample = .{ .after_cycle = 3, .value = 1 };
    service.append(.stack_low, serviceAccess(0xbffe, .write, 0x34));
    service.if_resample = .{ .after_cycle = 4, .value = 1 };
    service.acknowledgement = .{
        .during_cycle = 4,
        .index = 0,
        .before = 1,
        .after = 0,
    };
    return .{
        .before = serviceState(before_cpu, 1, 1, 3),
        .after = serviceState(after_cpu, 1, 0, 23),
        .event = .interrupt_service,
        .m_cycles = 5,
        .interrupt_index = 0,
        .service = service,
    };
}

fn serviceState(
    cpu: runner.Cpu,
    ie: u8,
    interrupt_flags: u8,
    div_counter: u16,
) machine.MachineState {
    return .{
        .cpu = cpu,
        .halt_bug = false,
        .div_counter = div_counter,
        .tima = 0x31,
        .tma = 0x42,
        .tac = 0x05,
        .timer_reload = .running,
        .interrupt_flags = interrupt_flags,
        .interrupt_enable = ie,
    };
}

fn serviceAccess(
    address: u16,
    action: runner.cartridge_memory.Action,
    value: u8,
) runner.cartridge_memory.Access {
    return .{
        .logical_address = address,
        .action = action,
        .region = .system,
        .physical_offset = null,
        .mapper_before = .{},
        .mapper_after = .{},
        .value = value,
    };
}

test "interrupt-service component binds the vector and stack writes" {
    try std.testing.expectEqual(N_CONSTRAINTS, test_component.nConstraints());
    _ = test_component.asVerifierComponent();
    _ = test_component.asProverComponent();

    const result = interruptService();
    const validated = try interrupt_service.ValidatedStep.init(result);
    const witness = interrupt_service.columns(validated);
    var values: [interrupt_service.N_MAIN_COLUMNS]QM31 = undefined;
    for (&values, witness) |*value, source|
        value.* = QM31.fromBase(source);
    const machine_witness =
        try interrupt_service.executionColumns(validated, 0);
    var machine_values: [execution.N_MAIN_COLUMNS]QM31 = undefined;
    for (&machine_values, machine_witness) |*value, source|
        value.* = QM31.fromBase(source);
    var execution_row = try execution.Row(QM31).fromColumns(&machine_values);
    try std.testing.expect(
        (try test_component.evaluateRow(
            &values,
            execution_row,
            QM31.one(),
        )).allZero(),
    );

    execution_row.after.values[@intFromEnum(execution.StateIndex.pc)] =
        execution_row.after.values[@intFromEnum(execution.StateIndex.pc)]
            .add(QM31.one());
    try std.testing.expect(
        !(try test_component.evaluateRow(
            &values,
            execution_row,
            QM31.one(),
        )).allZero(),
    );
}

test "interrupt-service component is inert on an ordinary execution row" {
    var memory = try runner.Memory.init(std.testing.allocator);
    defer memory.deinit();
    memory.write(0, 0x00);
    var cpu = runner.Cpu{};
    const ordinary = try runner.step(&cpu, &memory);
    const machine_witness = execution.columns(ordinary, 0);
    var machine_values: [execution.N_MAIN_COLUMNS]QM31 = undefined;
    for (&machine_values, machine_witness) |*value, source|
        value.* = QM31.fromBase(source);
    const witness = [_]QM31{QM31.zero()} ** interrupt_service.N_MAIN_COLUMNS;
    const evaluation = try test_component.evaluateRow(
        &witness,
        try execution.Row(QM31).fromColumns(&machine_values),
        QM31.zero(),
    );
    try std.testing.expect(
        evaluation.allZero(),
    );
}

test "interrupt-service component domain rejects a stack-byte mutation" {
    const allocator = std.testing.allocator;
    const log_size: u32 = 5;
    const size: usize = 1 << log_size;
    const result = interruptService();
    const validated = try interrupt_service.ValidatedStep.init(result);
    const witness = interrupt_service.columns(validated);
    const machine_witness =
        try interrupt_service.executionColumns(validated, 0);

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
    var main_values: [interrupt_service.N_MAIN_COLUMNS][size]M31 = undefined;
    var main_polynomials: [interrupt_service.N_MAIN_COLUMNS]prover_component.Poly =
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
    var combined: [
        execution.N_MAIN_COLUMNS + 1 + interrupt_service.N_MAIN_COLUMNS
    ]prover_component.Poly = undefined;
    @memcpy(combined[0..execution.N_MAIN_COLUMNS], &execution_polynomials);
    combined[execution.N_MAIN_COLUMNS] = active;
    @memcpy(
        combined[execution.N_MAIN_COLUMNS + 1 ..],
        &main_polynomials,
    );
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

    const stack_low_value =
        2 * execution.N_STATE_COLUMNS + 4 * execution.N_BUS_COLUMNS + 1;
    @memset(
        &execution_values[stack_low_value],
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
    var result_values = try mutated.finalize();
    defer result_values.deinit(allocator);
    var rejected = false;
    for (0..result_values.len()) |row|
        rejected = rejected or !result_values.at(row).isZero();
    try std.testing.expect(rejected);
}
