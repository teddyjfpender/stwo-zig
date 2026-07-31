const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const lookup = @import("timer_mmio_lookup.zig");
const timer_binding = @import("timer_binding.zig");
const timer_air = @import("timer.zig");
const runner = @import("../runner/mod.zig");

const memory = runner.cartridge_memory;
const mapper = @import("../cartridge/mbc3.zig");

test "timer interaction generation fails closed on empty execution" {
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

test "timer tick write and read relations cancel at exact clocks" {
    const steps = scenarioSteps();
    var trace = try timer_binding.generateTrace(
        std.testing.allocator,
        100,
        116,
        .{},
        &steps,
    );
    defer trace.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 20), trace.rows.len);
    const relations = lookup.Relations.dummy();
    var interaction = try lookup.generateInteraction(
        std.testing.allocator,
        &steps,
        100,
        5,
        trace.rows,
        relations,
    );
    defer interaction.deinit();
    try lookup.verifyCancellation(interaction.claims);
    try std.testing.expectEqual(
        @as(usize, 72),
        interaction.execution_columns.len,
    );
    try std.testing.expectEqual(
        @as(usize, 12),
        interaction.timer_columns.len,
    );

    var mutated_rows = try std.testing.allocator.dupe(
        timer_binding.EventRow,
        trace.rows,
    );
    defer std.testing.allocator.free(mutated_rows);
    mutated_rows[0].mcycle += 1;
    var wrong_clock = try lookup.generateInteraction(
        std.testing.allocator,
        &steps,
        100,
        5,
        mutated_rows,
        relations,
    );
    defer wrong_clock.deinit();
    try std.testing.expectError(
        error.TimerMmioLookupSumNonZero,
        lookup.verifyCancellation(wrong_clock.claims),
    );
    mutated_rows[0].mcycle -= 1;

    var omitted = try lookup.generateInteraction(
        std.testing.allocator,
        &steps,
        100,
        5,
        trace.rows[0 .. trace.rows.len - 1],
        relations,
    );
    defer omitted.deinit();
    try std.testing.expectError(
        error.TimerMmioLookupSumNonZero,
        lookup.verifyCancellation(omitted.claims),
    );

    var duplicated_rows = try std.testing.allocator.alloc(
        timer_binding.EventRow,
        trace.rows.len + 1,
    );
    defer std.testing.allocator.free(duplicated_rows);
    @memcpy(duplicated_rows[0..trace.rows.len], trace.rows);
    duplicated_rows[trace.rows.len] = trace.rows[trace.rows.len - 1];
    var duplicated = try lookup.generateInteraction(
        std.testing.allocator,
        &steps,
        100,
        5,
        duplicated_rows,
        relations,
    );
    defer duplicated.deinit();
    try std.testing.expectError(
        error.TimerMmioLookupSumNonZero,
        lookup.verifyCancellation(duplicated.claims),
    );

    mutated_rows[0].transition = timer_air.Transition.apply(
        mutated_rows[0].transition.before,
        .{ .write_tima = 0xaa },
    );
    try std.testing.expectError(
        error.InvalidTimerWriteProvenance,
        lookup.generateInteraction(
            std.testing.allocator,
            &steps,
            100,
            5,
            mutated_rows,
            relations,
        ),
    );
}

test "timer lookup authenticates pre-tick address and read value" {
    const steps = scenarioSteps();
    var trace = try timer_binding.generateTrace(
        std.testing.allocator,
        0,
        16,
        .{},
        &steps,
    );
    defer trace.deinit(std.testing.allocator);
    const relations = lookup.Relations.dummy();
    const read_index = for (trace.rows, 0..) |row, index| {
        if (row.provenance == .execution_tick and
            row.provenance.execution_tick.execution_row == 5)
            break index;
    } else unreachable;
    const columns = try timer_binding.columns(
        trace.rows[read_index],
        &steps,
    );
    const pairs = lookup.timerPairs(
        try liftTimer(columns),
        relations,
    );
    const expected = relations.at(.read).combine(
        QM31.fromBase(M31.fromCanonical(5)),
        QM31.fromBase(M31.fromCanonical(0xff06)),
        QM31.fromBase(M31.fromCanonical(0x55)),
    );
    try std.testing.expectEqual(
        QM31.one(),
        pairs[@intFromEnum(lookup.RelationIndex.read)].numerator,
    );
    try std.testing.expectEqual(
        expected,
        pairs[@intFromEnum(lookup.RelationIndex.read)].denominator,
    );

    var wrong_steps = steps;
    wrong_steps[5].instruction.cycles[0].value ^= 1;
    wrong_steps[5].accesses[0].?.value ^= 1;
    try std.testing.expectError(
        error.InvalidTimerReadProvenance,
        lookup.generateInteraction(
            std.testing.allocator,
            &wrong_steps,
            0,
            5,
            trace.rows,
            relations,
        ),
    );
}

test "timer claims cancel independently and reject relation substitution" {
    var claims = lookup.Claims{
        .execution = [_][lookup.N_EXECUTION_SUMS]QM31{
            [_]QM31{QM31.zero()} ** lookup.N_EXECUTION_SUMS,
        } ** lookup.N_RELATIONS,
        .timer = [_]QM31{QM31.zero()} ** lookup.N_RELATIONS,
    };
    const value = QM31.fromU32Unchecked(1, 2, 3, 4);
    claims.execution[0][0] = value.neg();
    claims.timer[0] = value;
    try lookup.verifyCancellation(claims);

    claims.timer[0] = value.add(QM31.one());
    try std.testing.expectError(
        error.TimerMmioLookupSumNonZero,
        lookup.verifyCancellation(claims),
    );
    claims.timer[0] = value;
    claims.execution[1][0] = value.neg();
    claims.timer[2] = value;
    try std.testing.expectError(
        error.TimerMmioLookupSumNonZero,
        lookup.verifyCancellation(claims),
    );
}

test "all-inactive timer row contributes no lookup entries" {
    const columns = timer_binding.inactiveColumns();
    const row = try liftTimer(columns);
    const pairs = lookup.timerPairs(row, lookup.Relations.dummy());
    for (pairs) |entry| {
        try std.testing.expect(entry.numerator.isZero());
        try std.testing.expectEqual(QM31.one(), entry.denominator);
    }
}

fn liftTimer(
    columns: [timer_binding.N_MAIN_COLUMNS]M31,
) !lookup.TimerRow(QM31) {
    var lifted: [timer_binding.N_MAIN_COLUMNS]QM31 = undefined;
    for (&lifted, columns) |*target, source|
        target.* = QM31.fromBase(source);
    return lookup.timerRow(QM31, &lifted);
}

fn scenarioSteps() [16]runner.CartridgeStepTrace {
    const state = mapper.State{};
    var result = [_]runner.CartridgeStepTrace{
        systemStep(state),
    } ** 16;
    result[0] = accessStep(state, 0xff04, .write, .timer_mmio, 0xaa);
    result[1] = accessStep(state, 0xff04, .read, .timer_mmio, 0);
    result[2] = accessStep(state, 0xff05, .write, .timer_mmio, 0x44);
    result[3] = accessStep(state, 0xff05, .read, .timer_mmio, 0x44);
    result[4] = accessStep(state, 0xff06, .write, .timer_mmio, 0x55);
    result[5] = accessStep(state, 0xff06, .read, .timer_mmio, 0x55);
    result[6] = accessStep(state, 0xff07, .write, .timer_mmio, 0);
    result[7] = accessStep(state, 0xff07, .read, .timer_mmio, 0xf8);
    return result;
}

fn systemStep(state: mapper.State) runner.CartridgeStepTrace {
    return accessStep(state, 0xc000, .read, .system, 0x42);
}

fn accessStep(
    state: mapper.State,
    address: u16,
    action: memory.Action,
    region: memory.Region,
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
        .mapper_before = state,
        .mapper_after = state,
        .value = value,
    };
    return step;
}
