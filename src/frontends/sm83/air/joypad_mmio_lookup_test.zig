const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const lookup = @import("joypad_mmio_lookup.zig");
const joypad_air = @import("joypad.zig");
const joypad_binding = @import("joypad_binding.zig");
const joypad_component = @import("joypad_component.zig");
const joypad = @import("../runner/joypad.zig");
const runner = @import("../runner/mod.zig");
const trace_builder = @import("../joypad_trace.zig");
const memory = runner.cartridge_memory;

test "interaction generation fails closed on empty execution" {
    try std.testing.expectError(
        error.InvalidExecutionTraceLength,
        lookup.generateInteraction(
            std.testing.allocator,
            &[_]runner.CartridgeStepTrace{},
            0,
            4,
            &.{},
            lookup.Relations.dummy(),
        ),
    );
}

test "generated plain write read plain execution cancels at exact clocks" {
    const mapper = @import("../cartridge/mbc3.zig").State{};
    const steps = [_]runner.CartridgeStepTrace{
        makeStep(mapper, .read, .system, 0xc000, 0),
        makeStep(mapper, .write, .joypad_mmio, joypad.P1_ADDRESS, 0x10),
        makeStep(mapper, .read, .joypad_mmio, joypad.P1_ADDRESS, 0xdf),
        makeStep(mapper, .read, .system, 0xc000, 0),
    };
    var events = try trace_builder.generate(
        std.testing.allocator,
        100,
        104,
        .{},
        &.{},
        &steps,
    );
    defer events.deinit(std.testing.allocator);
    const relations = lookup.Relations.dummy();
    var interaction = try lookup.generateInteraction(
        std.testing.allocator,
        &steps,
        100,
        4,
        events.rows,
        relations,
    );
    defer interaction.deinit();
    try lookup.verifyCancellation(interaction.claims);

    var mutated_rows = try std.testing.allocator.dupe(
        trace_builder.EventRow,
        events.rows,
    );
    defer std.testing.allocator.free(mutated_rows);
    mutated_rows[0].mcycle += 1;
    var wrong_clock = try lookup.generateInteraction(
        std.testing.allocator,
        &steps,
        100,
        4,
        mutated_rows,
        relations,
    );
    defer wrong_clock.deinit();
    try std.testing.expectError(
        error.JoypadMmioLookupSumNonZero,
        lookup.verifyCancellation(wrong_clock.claims),
    );

    var wrong_steps = steps;
    wrong_steps[2].instruction.cycles[0].value ^= 1;
    wrong_steps[2].accesses[0].?.value ^= 1;
    var wrong_value = try lookup.generateInteraction(
        std.testing.allocator,
        &wrong_steps,
        100,
        4,
        events.rows,
        relations,
    );
    defer wrong_value.deinit();
    try std.testing.expectError(
        error.JoypadMmioLookupSumNonZero,
        lookup.verifyCancellation(wrong_value.claims),
    );

    mutated_rows[0].mcycle -= 1;
    const write_index = for (mutated_rows, 0..) |row, index| {
        if (row.transition.event == .write_p1) break index;
    } else unreachable;
    mutated_rows[write_index].transition = try joypad.Transition.apply(
        mutated_rows[write_index].transition.before,
        .{ .write_p1 = 0x20 },
    );
    try std.testing.expectError(
        error.InvalidWriteProvenance,
        lookup.generateInteraction(
            std.testing.allocator,
            &steps,
            100,
            4,
            mutated_rows,
            relations,
        ),
    );

    var omitted = try lookup.generateInteraction(
        std.testing.allocator,
        &steps,
        100,
        4,
        events.rows[0 .. events.rows.len - 1],
        relations,
    );
    defer omitted.deinit();
    try std.testing.expectError(
        error.JoypadMmioLookupSumNonZero,
        lookup.verifyCancellation(omitted.claims),
    );
}

test "read relation uses externally visible pre-tick pending selector" {
    var initial = joypad.State{};
    _ = initial.setPressed(0x01);
    const write = try joypad.Transition.apply(initial, .{ .write_p1 = 0x10 });
    try std.testing.expect(write.after.switching_delay != 0);
    const tick = try joypad.Transition.apply(write.after, .tick_mcycle);
    var columns = [_]M31{M31.zero()} ** joypad_binding.N_MAIN_COLUMNS;
    const semantic = joypad_component.columns(
        try joypad_air.ValidatedStep.init(tick),
    );
    @memcpy(columns[0..joypad_component.N_MAIN_COLUMNS], &semantic);
    columns[joypad_binding.MCYCLE_OFFSET] = M31.fromCanonical(7);
    columns[joypad_binding.READ_ENABLED_OFFSET] = M31.one();

    var lifted: [joypad_binding.N_MAIN_COLUMNS]QM31 = undefined;
    for (&lifted, columns) |*target, source|
        target.* = QM31.fromBase(source);
    const row = try lookup.joypadRow(QM31, &lifted);
    try std.testing.expectEqual(
        QM31.fromBase(M31.fromCanonical(tick.before.readP1())),
        lookup.readBefore(QM31, row),
    );
    try std.testing.expect(
        !std.meta.eql(tick.before.readP1(), tick.after.readP1()) or
            tick.before.switching_delay > joypad.SAMEBOY_CYCLES_PER_M_CYCLE,
    );
}

test "read-enabled is boolean, tick-only, and inactive clocks are zero" {
    const initial = try joypad.State.init(0xcf, 0, 0, 0);
    const transition = try joypad.Transition.apply(initial, .tick_mcycle);
    var columns = [_]M31{M31.zero()} ** joypad_binding.N_MAIN_COLUMNS;
    const semantic = joypad_component.columns(
        try joypad_air.ValidatedStep.init(transition),
    );
    @memcpy(columns[0..joypad_component.N_MAIN_COLUMNS], &semantic);
    columns[joypad_binding.MCYCLE_OFFSET] = M31.fromCanonical(1);
    columns[joypad_binding.READ_ENABLED_OFFSET] = M31.one();
    var row = try lookup.joypadRow(M31, &columns);
    for (lookup.joypadBindingConstraints(M31, row)) |constraint|
        try std.testing.expect(constraint.isZero());

    row.read_enabled = M31.fromCanonical(2);
    try std.testing.expect(
        !lookup.joypadBindingConstraints(M31, row)[0].isZero(),
    );
    row.read_enabled = M31.one();
    row.semantic.events[2] = M31.zero();
    try std.testing.expect(
        !lookup.joypadBindingConstraints(M31, row)[1].isZero(),
    );
    row.active = M31.zero();
    try std.testing.expect(
        !lookup.joypadBindingConstraints(M31, row)[2].isZero(),
    );
}

test "claims cancel relation by relation and reject substitutions" {
    var claims = lookup.Claims{
        .execution = [_][lookup.N_EXECUTION_SUMS]QM31{
            [_]QM31{QM31.zero()} ** lookup.N_EXECUTION_SUMS,
        } ** lookup.N_RELATIONS,
        .joypad = [_]QM31{QM31.zero()} ** lookup.N_RELATIONS,
    };
    const value = QM31.fromU32Unchecked(1, 2, 3, 4);
    claims.execution[0][0] = value.neg();
    claims.joypad[0] = value;
    try lookup.verifyCancellation(claims);

    claims.joypad[0] = value.add(QM31.one());
    try std.testing.expectError(
        error.JoypadMmioLookupSumNonZero,
        lookup.verifyCancellation(claims),
    );
    claims.joypad[0] = value;
    claims.execution[1][0] = value.neg();
    claims.joypad[2] = value;
    try std.testing.expectError(
        error.JoypadMmioLookupSumNonZero,
        lookup.verifyCancellation(claims),
    );
}

test "all inactive binding row is non-vacuous only with zero extension" {
    const columns = joypad_binding.inactiveColumns();
    const row = try lookup.joypadRow(M31, &columns);
    for (lookup.joypadBindingConstraints(M31, row)) |constraint|
        try std.testing.expect(constraint.isZero());
    const pairs = lookup.joypadPairs(
        try liftJoypad(columns),
        lookup.Relations.dummy(),
    );
    for (pairs) |entry|
        try std.testing.expect(entry.numerator.isZero());

    var mutated = columns;
    mutated[joypad_binding.MCYCLE_OFFSET] = M31.one();
    const bad = try lookup.joypadRow(M31, &mutated);
    try std.testing.expect(
        !lookup.joypadBindingConstraints(M31, bad)[2].isZero(),
    );
}

fn liftJoypad(
    columns: [joypad_binding.N_MAIN_COLUMNS]M31,
) !lookup.JoypadRow(QM31) {
    var lifted: [joypad_binding.N_MAIN_COLUMNS]QM31 = undefined;
    for (&lifted, columns) |*target, source|
        target.* = QM31.fromBase(source);
    return lookup.joypadRow(QM31, &lifted);
}

fn makeStep(
    mapper: @import("../cartridge/mbc3.zig").State,
    action: memory.Action,
    region: memory.Region,
    address: u16,
    value: u8,
) runner.CartridgeStepTrace {
    var step: runner.CartridgeStepTrace = undefined;
    step.instruction.cycle_count = 1;
    step.instruction.cycles[0] = .{
        .address = address,
        .value = value,
        .action = switch (action) {
            .read => .read,
            .write => .write,
        },
    };
    step.accesses = [_]?memory.Access{null} ** 6;
    step.accesses[0] = .{
        .logical_address = address,
        .action = action,
        .region = region,
        .physical_offset = null,
        .mapper_before = mapper,
        .mapper_after = mapper,
        .value = value,
    };
    return step;
}
