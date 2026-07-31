const std = @import("std");
const circle = @import("stwo_core").circle;
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const runner = @import("../runner/mod.zig");
const cartridge_access = @import("cartridge_access_component.zig");
const execution = @import("execution.zig");
const timer_binding = @import("timer_binding.zig");
const lookup = @import("timer_mmio_lookup.zig");
const subject = @import("timer_mmio_lookup_component.zig");

const LOG_SIZE: u32 = 4;
const FIRST_COLUMN: usize = 2;
const EXECUTION_OFFSET: usize = 3;
const ACCESS_OFFSET: usize =
    EXECUTION_OFFSET + execution.N_MAIN_COLUMNS + 2;
const EXECUTION_MAIN_COLUMNS: usize =
    ACCESS_OFFSET + cartridge_access.N_MAIN_COLUMNS;
const BINDING_OFFSET: usize = 5;
const TIMER_MAIN_COLUMNS: usize =
    BINDING_OFFSET + timer_binding.N_MAIN_COLUMNS;
const INTERACTION_OFFSET: usize = 7;
const EXECUTION_INTERACTION_COLUMNS: usize =
    INTERACTION_OFFSET + lookup.N_EXECUTION_INTERACTION_COLUMNS;
const TIMER_INTERACTION_COLUMNS: usize =
    INTERACTION_OFFSET + lookup.N_TIMER_INTERACTION_COLUMNS;

test "timer lookup owners expose offset-safe proof geometry" {
    const relations = lookup.Relations.dummy();
    const claims = zeroClaims();
    const execution_owner = executionComponent(&relations, claims);
    const timer_owner = timerComponent(&relations, claims);
    try std.testing.expectEqual(
        @as(usize, 18),
        execution_owner.nConstraints(),
    );
    try std.testing.expectEqual(
        @as(usize, 3),
        timer_owner.nConstraints(),
    );
    try std.testing.expectEqual(
        @as(u32, LOG_SIZE + 1),
        execution_owner.maxConstraintLogDegreeBound(),
    );
    _ = execution_owner.asVerifierComponent();
    _ = timer_owner.asProverComponent();

    var execution_bounds = try execution_owner.traceLogDegreeBounds(
        std.testing.allocator,
    );
    defer execution_bounds.deinitDeep(std.testing.allocator);
    try expectShape(
        execution_bounds.items,
        FIRST_COLUMN + 1,
        EXECUTION_MAIN_COLUMNS,
        EXECUTION_INTERACTION_COLUMNS,
    );
    var timer_bounds = try timer_owner.traceLogDegreeBounds(
        std.testing.allocator,
    );
    defer timer_bounds.deinitDeep(std.testing.allocator);
    try expectShape(
        timer_bounds.items,
        FIRST_COLUMN + 1,
        TIMER_MAIN_COLUMNS,
        TIMER_INTERACTION_COLUMNS,
    );
    var timer_mask = try timer_owner.maskPoints(
        std.testing.allocator,
        circle.SECURE_FIELD_CIRCLE_GEN,
        LOG_SIZE + 1,
    );
    defer timer_mask.deinitDeep(std.testing.allocator);
    try expectShape(
        timer_mask.items,
        FIRST_COLUMN + 1,
        TIMER_MAIN_COLUMNS,
        TIMER_INTERACTION_COLUMNS,
    );
    for (timer_mask.items[2]) |points|
        try std.testing.expectEqual(@as(usize, 2), points.len);
    const indices = try timer_owner.preprocessedColumnIndices(
        std.testing.allocator,
    );
    defer std.testing.allocator.free(indices);
    try std.testing.expectEqualSlices(
        usize,
        &.{FIRST_COLUMN},
        indices,
    );
}

test "sampled execution lookup rejects claim and MMIO provenance mutations" {
    const relations = lookup.Relations.dummy();
    const step = makeTimerRead();
    const machine = execution.columns(step.instruction, 100);
    const accesses = try cartridge_access.columns(step);
    const pairs = lookup.executionPairs(
        try liftExecution(machine),
        try liftAccess(accesses),
        relations,
    );
    var claims = zeroClaims();
    for (pairs, 0..) |relation_pairs, relation_index| {
        for (relation_pairs, 0..) |entry, sum_index|
            claims.execution[relation_index][sum_index] =
                try pairIncrement(entry);
    }

    var preprocessed_values =
        [_][1]QM31{.{QM31.zero()}} ** (FIRST_COLUMN + 1);
    preprocessed_values[FIRST_COLUMN][0] = QM31.one();
    var preprocessed: [FIRST_COLUMN + 1][]QM31 = undefined;
    pointSlices(&preprocessed, &preprocessed_values);
    var main_values =
        [_][1]QM31{.{QM31.zero()}} ** EXECUTION_MAIN_COLUMNS;
    fillPointConstants(
        main_values[EXECUTION_OFFSET..][0..execution.N_MAIN_COLUMNS],
        &machine,
    );
    fillPointConstants(
        main_values[ACCESS_OFFSET..][0..cartridge_access.N_MAIN_COLUMNS],
        &accesses,
    );
    var main: [EXECUTION_MAIN_COLUMNS][]QM31 = undefined;
    pointSlices(&main, &main_values);
    var interaction_values =
        [_][2]QM31{.{ QM31.zero(), QM31.zero() }} **
        EXECUTION_INTERACTION_COLUMNS;
    var interaction: [EXECUTION_INTERACTION_COLUMNS][]QM31 = undefined;
    pointSlices(&interaction, &interaction_values);

    var component = executionComponent(&relations, claims);
    var constraints: [subject.N_MAX_CONSTRAINTS]QM31 = undefined;
    const count = try component.evaluateSampled(
        &preprocessed,
        &main,
        &interaction,
        &constraints,
    );
    try std.testing.expect(allZero(constraints[0..count]));

    component.claims.execution[0][0] =
        component.claims.execution[0][0].add(QM31.one());
    _ = try component.evaluateSampled(
        &preprocessed,
        &main,
        &interaction,
        &constraints,
    );
    try std.testing.expect(!allZero(constraints[0..count]));
    component.claims = claims;

    const timer_region = ACCESS_OFFSET +
        @import("cartridge_access.zig").REGION_OFFSET +
        @intFromEnum(runner.cartridge_memory.Region.timer_mmio);
    main_values[timer_region][0] = QM31.zero();
    _ = try component.evaluateSampled(
        &preprocessed,
        &main,
        &interaction,
        &constraints,
    );
    try std.testing.expect(!allZero(constraints[0..count]));
}

test "sampled timer lookup rejects omitted read and accumulator mutation" {
    const relations = lookup.Relations.dummy();
    const step = makeTimerRead();
    var trace = try timer_binding.generateTrace(
        std.testing.allocator,
        100,
        101,
        .{},
        &.{step},
    );
    defer trace.deinit(std.testing.allocator);
    const timer_columns = try timer_binding.columns(
        trace.rows[0],
        &.{step},
    );
    const pairs = lookup.timerPairs(
        try liftTimer(timer_columns),
        relations,
    );
    var claims = zeroClaims();
    for (pairs, 0..) |entry, index|
        claims.timer[index] = try pairIncrement(entry);

    var preprocessed_values =
        [_][1]QM31{.{QM31.zero()}} ** (FIRST_COLUMN + 1);
    preprocessed_values[FIRST_COLUMN][0] = QM31.one();
    var preprocessed: [FIRST_COLUMN + 1][]QM31 = undefined;
    pointSlices(&preprocessed, &preprocessed_values);
    var main_values =
        [_][1]QM31{.{QM31.zero()}} ** TIMER_MAIN_COLUMNS;
    fillPointConstants(
        main_values[BINDING_OFFSET..][0..timer_binding.N_MAIN_COLUMNS],
        &timer_columns,
    );
    var main: [TIMER_MAIN_COLUMNS][]QM31 = undefined;
    pointSlices(&main, &main_values);
    var interaction_values =
        [_][2]QM31{.{ QM31.zero(), QM31.zero() }} **
        TIMER_INTERACTION_COLUMNS;
    var interaction: [TIMER_INTERACTION_COLUMNS][]QM31 = undefined;
    pointSlices(&interaction, &interaction_values);

    const component = timerComponent(&relations, claims);
    var constraints: [subject.N_MAX_CONSTRAINTS]QM31 = undefined;
    const count = try component.evaluateSampled(
        &preprocessed,
        &main,
        &interaction,
        &constraints,
    );
    try std.testing.expect(allZero(constraints[0..count]));

    main_values[
        BINDING_OFFSET + timer_binding.READ_MARKER_OFFSET +
            @intFromEnum(timer_binding.Register.tima)
    ][0] = QM31.zero();
    _ = try component.evaluateSampled(
        &preprocessed,
        &main,
        &interaction,
        &constraints,
    );
    try std.testing.expect(!allZero(constraints[0..count]));
    main_values[
        BINDING_OFFSET + timer_binding.READ_MARKER_OFFSET +
            @intFromEnum(timer_binding.Register.tima)
    ][0] = QM31.one();

    interaction_values[INTERACTION_OFFSET][0] = QM31.one();
    _ = try component.evaluateSampled(
        &preprocessed,
        &main,
        &interaction,
        &constraints,
    );
    try std.testing.expect(!allZero(constraints[0..count]));
}

fn executionComponent(
    relations: *const lookup.Relations,
    claims: lookup.Claims,
) subject.Component {
    return .{
        .kind = .execution,
        .log_size = LOG_SIZE,
        .is_first_column = FIRST_COLUMN,
        .execution_offset = EXECUTION_OFFSET,
        .access_offset = ACCESS_OFFSET,
        .interaction_offset = INTERACTION_OFFSET,
        .relations = relations,
        .claims = claims,
    };
}

fn timerComponent(
    relations: *const lookup.Relations,
    claims: lookup.Claims,
) subject.Component {
    return .{
        .kind = .timer,
        .log_size = LOG_SIZE,
        .is_first_column = FIRST_COLUMN,
        .binding_offset = BINDING_OFFSET,
        .interaction_offset = INTERACTION_OFFSET,
        .relations = relations,
        .claims = claims,
    };
}

fn zeroClaims() lookup.Claims {
    return .{
        .execution = [_][lookup.N_EXECUTION_SUMS]QM31{
            [_]QM31{QM31.zero()} ** lookup.N_EXECUTION_SUMS,
        } ** lookup.N_RELATIONS,
        .timer = [_]QM31{QM31.zero()} ** lookup.N_RELATIONS,
    };
}

fn liftExecution(
    values: [execution.N_MAIN_COLUMNS]M31,
) !execution.Row(QM31) {
    var lifted: [execution.N_MAIN_COLUMNS]QM31 = undefined;
    lift(&lifted, &values);
    return execution.Row(QM31).fromColumns(&lifted);
}

fn liftAccess(
    values: [cartridge_access.N_MAIN_COLUMNS]M31,
) !cartridge_access.PackedRow(QM31) {
    var lifted: [cartridge_access.N_MAIN_COLUMNS]QM31 = undefined;
    lift(&lifted, &values);
    return cartridge_access.PackedRow(QM31).fromColumns(&lifted);
}

fn liftTimer(
    values: [timer_binding.N_MAIN_COLUMNS]M31,
) !lookup.TimerRow(QM31) {
    var lifted: [timer_binding.N_MAIN_COLUMNS]QM31 = undefined;
    lift(&lifted, &values);
    return lookup.timerRow(QM31, &lifted);
}

fn lift(output: []QM31, values: []const M31) void {
    for (output, values) |*target, value|
        target.* = QM31.fromBase(value);
}

fn pairIncrement(entry: lookup.Pair) !QM31 {
    return entry.numerator.mul(try entry.denominator.inv());
}

fn pointSlices(output: anytype, values: anytype) void {
    for (output, values) |*column, *source| column.* = source;
}

fn fillPointConstants(destinations: anytype, values: []const M31) void {
    for (destinations, values) |*destination, value|
        destination[0] = QM31.fromBase(value);
}

fn expectShape(
    items: anytype,
    preprocessed: usize,
    main: usize,
    interaction: usize,
) !void {
    try std.testing.expectEqual(@as(usize, 3), items.len);
    try std.testing.expectEqual(preprocessed, items[0].len);
    try std.testing.expectEqual(main, items[1].len);
    try std.testing.expectEqual(interaction, items[2].len);
}

fn allZero(values: []const QM31) bool {
    for (values) |value|
        if (!value.isZero()) return false;
    return true;
}

fn makeTimerRead() runner.CartridgeStepTrace {
    const state = @import("../cartridge/mbc3.zig").State{};
    var step: runner.CartridgeStepTrace = undefined;
    step.instruction.cycle_count = 1;
    step.instruction.cycles[0] = .{
        .address = 0xff05,
        .value = 0,
        .action = .read,
    };
    step.accesses = [_]?runner.cartridge_memory.Access{null} ** 6;
    step.accesses[0] = .{
        .logical_address = 0xff05,
        .action = .read,
        .region = .timer_mmio,
        .physical_offset = null,
        .mapper_before = state,
        .mapper_after = state,
        .value = 0,
    };
    return step;
}
