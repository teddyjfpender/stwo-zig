const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const subject = @import("apu_execution_lookup.zig");
const binding = @import("apu_binding.zig");
const apu = @import("../runner/apu_mmio.zig");
const runner = @import("../runner/mod.zig");
const memory = runner.cartridge_memory;

test "APU ordered lookup binds every execution access exactly once" {
    const steps = scenarioSteps();
    var trace = try subject.generateFromExecution(
        std.testing.allocator,
        11,
        .{},
        &steps,
    );
    defer trace.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 5), trace.semantic.rows.len);
    try std.testing.expectEqualSlices(
        u32,
        &.{ 11, 12, 15, 18, 23 },
        trace.mcycles,
    );
    try std.testing.expectEqual(@as(u32, 27), trace.final_execution_mcycle);

    var semantic = try binding.generateWitness(
        std.testing.allocator,
        trace.semantic,
    );
    defer semantic.deinit();
    var auxiliary = try subject.generateAuxiliaryWitness(
        std.testing.allocator,
        trace,
        &steps,
        11,
    );
    defer auxiliary.deinit();
    var interaction = try subject.generateInteraction(
        std.testing.allocator,
        trace,
        &steps,
        11,
        &auxiliary,
        subject.Relation.dummy(),
    );
    defer interaction.deinit();
    try std.testing.expectEqual(@as(usize, 5), semantic.event_count);
    try std.testing.expectEqual(@as(usize, 5), interaction.claims.execution_count);
    try std.testing.expectEqual(@as(usize, 5), interaction.claims.apu_count);
    try subject.verifyCancellation(
        interaction.claims,
        trace.semantic.initial_state,
        trace.semantic.final_state,
    );
}

test "APU ordered lookup rejects clock semantic ownership and claim mutations" {
    var steps = scenarioSteps();
    var trace = try subject.generateFromExecution(
        std.testing.allocator,
        31,
        .{},
        &steps,
    );
    defer trace.deinit(std.testing.allocator);

    trace.mcycles[2] += 1;
    try std.testing.expectError(
        error.ApuExecutionClockMismatch,
        subject.generateAuxiliaryWitness(
            std.testing.allocator,
            trace,
            &steps,
            31,
        ),
    );
    trace.mcycles[2] -= 1;

    const saved = trace.semantic.rows[2];
    trace.semantic.rows[2].after.registers[
        binding.registerIndex(0xff12)
    ] ^= 1;
    try std.testing.expectError(
        error.InvalidTransition,
        subject.validateAgainstExecution(trace, &steps, 31),
    );
    trace.semantic.rows[2] = saved;

    steps[7].accesses[0].?.region = .system;
    try std.testing.expectError(
        error.InvalidCartridgeAccess,
        subject.validateAgainstExecution(trace, &steps, 31),
    );
    steps[7] = scenarioSteps()[7];

    steps[7].accesses[0].?.value ^= 1;
    steps[7].instruction.cycles[0].value ^= 1;
    try std.testing.expectError(
        error.ApuReadResultMismatch,
        subject.validateAgainstExecution(trace, &steps, 31),
    );
    steps[7] = scenarioSteps()[7];

    var auxiliary = try subject.generateAuxiliaryWitness(
        std.testing.allocator,
        trace,
        &steps,
        31,
    );
    defer auxiliary.deinit();
    var interaction = try subject.generateInteraction(
        std.testing.allocator,
        trace,
        &steps,
        31,
        &auxiliary,
        subject.Relation.dummy(),
    );
    defer interaction.deinit();
    interaction.claims.apu = interaction.claims.apu.add(QM31.one());
    try std.testing.expectError(
        error.ApuExecutionLookupSumNonZero,
        subject.verifyCancellation(
            interaction.claims,
            trace.semantic.initial_state,
            trace.semantic.final_state,
        ),
    );
    interaction.claims.apu = interaction.claims.apu.sub(QM31.one());
    interaction.claims.apu_count -= 1;
    try std.testing.expectError(
        error.ApuExecutionCountMismatch,
        subject.verifyCancellation(
            interaction.claims,
            trace.semantic.initial_state,
            trace.semantic.final_state,
        ),
    );
}

test "APU lookup accepts empty ROM-agnostic segments and rejects vacuity" {
    const steps = [_]runner.CartridgeStepTrace{
        systemStep(0xff80, .read, 0),
    } ** 16;
    var trace = try subject.generateFromExecution(
        std.testing.allocator,
        0,
        .{},
        &steps,
    );
    defer trace.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 0), trace.semantic.rows.len);

    var semantic = try binding.generateWitness(
        std.testing.allocator,
        trace.semantic,
    );
    defer semantic.deinit();
    var auxiliary = try subject.generateAuxiliaryWitness(
        std.testing.allocator,
        trace,
        &steps,
        0,
    );
    defer auxiliary.deinit();
    var interaction = try subject.generateInteraction(
        std.testing.allocator,
        trace,
        &steps,
        0,
        &auxiliary,
        subject.Relation.dummy(),
    );
    defer interaction.deinit();
    try std.testing.expectEqual(@as(u32, 4), semantic.log_size);
    try std.testing.expectEqual(@as(usize, 0), interaction.claims.apu_count);
    try subject.verifyCancellation(
        interaction.claims,
        trace.semantic.initial_state,
        trace.semantic.final_state,
    );

    var changed = trace.semantic.final_state;
    changed.registers[0] = 1;
    try std.testing.expectError(
        error.InvalidEmptyApuAccessEndpoint,
        subject.verifyCancellation(
            interaction.claims,
            trace.semantic.initial_state,
            changed,
        ),
    );
    var forged = interaction.claims;
    forged.apu = QM31.one();
    try std.testing.expectError(
        error.ApuExecutionLookupSumNonZero,
        subject.verifyCancellation(
            forged,
            trace.semantic.initial_state,
            trace.semantic.final_state,
        ),
    );
}

test "APU lookup fails closed on unknown live state" {
    var steps = [_]runner.CartridgeStepTrace{
        systemStep(0xff80, .read, 0),
    } ** 16;
    steps[3] = apuStep(apu.NR52, .read, 0x70);
    try std.testing.expectError(
        error.UnknownChannelStatus,
        subject.generateFromExecution(
            std.testing.allocator,
            0,
            .{ .enabled = true, .channel_status = null },
            &steps,
        ),
    );
}

test "APU order and lookup recurrences are at most cubic" {
    const variables = [_]Degree{Degree.variable()} ** 6;
    const execution = subject.executionOrderConstraints(
        Degree,
        Degree.variable(),
        Degree.variable(),
        variables,
        Degree.variable(),
        Degree.variable(),
        Degree.variable(),
    );
    const apu_constraints = subject.apuOrderConstraints(
        Degree,
        Degree.variable(),
        Degree.variable(),
        Degree.variable(),
        Degree.variable(),
        Degree.variable(),
        Degree.variable(),
        Degree.variable(),
        Degree.variable(),
        Degree.variable(),
    );
    var maximum: u32 = 0;
    for (execution) |constraint| maximum = @max(maximum, constraint.degree);
    for (apu_constraints) |constraint|
        maximum = @max(maximum, constraint.degree);
    const lookup = subject.pairConstraint(
        Degree,
        Degree.variable(),
        Degree.variable(),
        Degree.variable(),
        Degree.variable(),
        Degree.variable(),
        Degree.variable(),
    );
    maximum = @max(maximum, lookup.degree);
    try std.testing.expectEqual(subject.MAX_CONSTRAINT_DEGREE, maximum);
}

fn scenarioSteps() [16]runner.CartridgeStepTrace {
    var result = [_]runner.CartridgeStepTrace{
        systemStep(0xff80, .read, 0),
    } ** 16;
    result[0] = apuStep(apu.NR11, .write, 0x3f);
    result[1] = apuStep(apu.NR52, .write, 0x80);
    result[4] = apuStep(0xff12, .write, 0x71);
    result[7] = apuStep(0xff12, .read, 0x71);
    result[12] = apuStep(apu.NR52, .write, 0);
    return result;
}

fn apuStep(
    address: u16,
    action: memory.Action,
    value: u8,
) runner.CartridgeStepTrace {
    return accessStep(address, action, value, .apu_mmio);
}

fn systemStep(
    address: u16,
    action: memory.Action,
    value: u8,
) runner.CartridgeStepTrace {
    return accessStep(address, action, value, .system);
}

fn accessStep(
    address: u16,
    action: memory.Action,
    value: u8,
    region: memory.Region,
) runner.CartridgeStepTrace {
    var result: runner.CartridgeStepTrace = undefined;
    result.instruction.cycle_count = 1;
    result.instruction.cycles[0] = .{
        .address = address,
        .value = value,
        .action = switch (action) {
            .read => .read,
            .write => .write,
        },
    };
    result.accesses = [_]?memory.Access{null} ** runner.MAX_BUS_CYCLES;
    result.accesses[0] = .{
        .logical_address = address,
        .action = action,
        .region = region,
        .physical_offset = null,
        .mapper_before = .{},
        .mapper_after = .{},
        .value = value,
    };
    return result;
}

const Degree = struct {
    degree: u32,

    fn variable() Degree {
        return .{ .degree = 1 };
    }
    pub fn zero() Degree {
        return .{ .degree = 0 };
    }
    pub fn one() Degree {
        return .{ .degree = 0 };
    }
    pub fn fromBase(_: M31) Degree {
        return .{ .degree = 0 };
    }
    pub fn add(a: Degree, b: Degree) Degree {
        return .{ .degree = @max(a.degree, b.degree) };
    }
    pub fn sub(a: Degree, b: Degree) Degree {
        return a.add(b);
    }
    pub fn mul(a: Degree, b: Degree) Degree {
        return .{ .degree = a.degree + b.degree };
    }
    pub fn neg(a: Degree) Degree {
        return a;
    }
    pub fn isZero(_: Degree) bool {
        return false;
    }
};
