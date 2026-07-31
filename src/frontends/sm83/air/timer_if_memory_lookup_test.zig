const std = @import("std");
const core_air_utils = @import("stwo_core").air.utils;
const M31_MODULUS = @import("stwo_core").fields.m31.Modulus;
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const runner = @import("../runner/mod.zig");
const timer_runner = @import("../runner/timer.zig");
const timer_air = @import("timer.zig");
const timer_binding = @import("timer_binding.zig");
const timer_component = @import("timer_component.zig");
const memory_lookup = @import("cartridge_memory_lookup.zig");
const subject = @import("timer_if_memory_lookup.zig");

test "timer IF row binds tick phase predecessor and bit-2 OR" {
    const event = requestingEvent(7);
    const predecessor = subject.Predecessor{
        .clock = 3,
        .value = 0x01,
    };
    const access = try subject.accessForEvent(event, predecessor);
    try std.testing.expectEqual(requestClock(), access.clock);
    try std.testing.expectEqual(@as(u8, 0x05), access.next_value);

    const timer_values = bindingColumns(event);
    const main_values = try subject.columnsForAccess(access);
    var timer = try liftTimer(timer_values);
    var row = try liftRow(main_values);
    try std.testing.expect(subject.evaluate(QM31, timer, row).allZero());

    row.previous_clock = row.previous_clock.add(QM31.one());
    try std.testing.expect(
        !subject.evaluate(QM31, timer, row).allZero(),
    );
    row = try liftRow(main_values);
    row.previous_value[0] =
        row.previous_value[0].add(QM31.one());
    try std.testing.expect(
        !subject.evaluate(QM31, timer, row).allZero(),
    );
    row = try liftRow(main_values);
    row.difference_bits[0] =
        row.difference_bits[0].sub(QM31.one());
    try std.testing.expect(
        !subject.evaluate(QM31, timer, row).allZero(),
    );

    row = try liftRow(main_values);
    timer.semantic.interrupt_requested = QM31.zero();
    try std.testing.expect(
        !subject.evaluate(QM31, timer, row).allZero(),
    );
}

test "timer IF witness rejects forged request metadata and clock collisions" {
    const first = requestingEvent(7);
    const second = requestingEvent(7);
    try std.testing.expectError(
        error.TimerIfClockCollision,
        subject.generateWitness(
            std.testing.allocator,
            4,
            &.{ first, second },
            &.{
                .{ .clock = 3, .value = 0 },
                .{ .clock = 4, .value = timer_runner.TIMER_INTERRUPT },
            },
        ),
    );

    var forged = first;
    forged.transition.interrupt_requested = false;
    try std.testing.expectError(
        error.InvalidTimerTransition,
        subject.accessForEvent(forged, .{}),
    );
    const quiet = quietEvent(8);
    try std.testing.expectError(
        error.InvalidInactivePredecessor,
        subject.accessForEvent(
            quiet,
            .{ .clock = 1, .value = 2 },
        ),
    );
    var late = first;
    late.mcycle = M31_MODULUS - 1;
    try std.testing.expectError(
        error.NonCanonicalTimerIfClock,
        subject.accessForEvent(late, .{}),
    );
    try std.testing.expectError(
        error.InvalidTimerIfPredecessorClock,
        subject.accessForEvent(
            first,
            .{ .clock = requestClock(), .value = 0 },
        ),
    );
}

test "timer IF interaction cancels only the authenticated FF0F transition" {
    const relation = memory_lookup.Relation.dummy();
    const event = requestingEvent(7);
    const access = try subject.accessForEvent(
        event,
        .{ .clock = 3, .value = 0x01 },
    );
    var accesses = [_]subject.Access{.{}} ** 16;
    accesses[0] = access;
    var interaction = try subject.generateInteraction(
        std.testing.allocator,
        &accesses,
        4,
        relation,
    );
    defer interaction.deinit();

    var total = interaction.claim;
    total = try subject.accumulate(
        total,
        boundaryPair(
            relation,
            3,
            0x01,
            requestClock(),
            0x05,
        ),
    );
    try std.testing.expect(total.isZero());
    try std.testing.expect(!interaction.claim.isZero());

    const mutations = [_]subject.Access{
        .{
            .enabled = true,
            .previous_clock = 2,
            .previous_value = 0x01,
            .clock = requestClock(),
            .next_value = 0x05,
        },
        .{
            .enabled = true,
            .previous_clock = 3,
            .previous_value = 0x00,
            .clock = requestClock(),
            .next_value = 0x04,
        },
        .{
            .enabled = true,
            .previous_clock = 3,
            .previous_value = 0x01,
            .clock = requestClock() + 1,
            .next_value = 0x05,
        },
    };
    for (mutations) |mutation| {
        var forged_total = try subject.accumulate(
            QM31.zero(),
            try subject.pair(mutation, relation),
        );
        forged_total = try subject.accumulate(
            forged_total,
            boundaryPair(
                relation,
                3,
                0x01,
                requestClock(),
                0x05,
            ),
        );
        try std.testing.expect(!forged_total.isZero());
    }

    const wrong_address = memory_lookup.RowPair{
        .n1 = QM31.one().neg(),
        .d1 = relation.combine(q(0xff0e), q(3), q(0x01)),
        .n2 = QM31.one(),
        .d2 = relation.combine(
            q(0xff0e),
            q(requestClock()),
            q(0x05),
        ),
    };
    var wrong_total = try subject.accumulate(
        QM31.zero(),
        wrong_address,
    );
    wrong_total = try subject.accumulate(
        wrong_total,
        boundaryPair(
            relation,
            3,
            0x01,
            requestClock(),
            0x05,
        ),
    );
    try std.testing.expect(!wrong_total.isZero());

    const omitted = try subject.accumulate(
        QM31.zero(),
        boundaryPair(
            relation,
            3,
            0x01,
            requestClock(),
            0x05,
        ),
    );
    try std.testing.expect(!omitted.isZero());
}

test "timer IF witness is bit reversed and padding is neutral" {
    const event = requestingEvent(7);
    var witness = try subject.generateWitness(
        std.testing.allocator,
        4,
        &.{event},
        &.{.{ .clock = 3, .value = 0x04 }},
    );
    defer witness.deinit();
    try std.testing.expectEqual(@as(usize, 16), witness.accesses.len);
    const storage = try core_air_utils.circleBitReversedIndex(4, 0);
    try std.testing.expectEqual(
        M31.fromCanonical(3),
        witness.main[subject.PREVIOUS_CLOCK_OFFSET][storage],
    );
    for (witness.accesses[1..]) |access|
        try std.testing.expectEqual(subject.Access{}, access);

    const inactive_timer = timer_binding.inactiveColumns();
    const inactive_main = subject.inactiveColumns();
    const timer = try liftTimer(inactive_timer);
    const row = try liftRow(inactive_main);
    try std.testing.expect(
        subject.evaluate(QM31, timer, row).allZero(),
    );
    const neutral = try subject.pair(
        .{},
        memory_lookup.Relation.dummy(),
    );
    try std.testing.expect(neutral.n1.isZero());
    try std.testing.expect(neutral.n2.isZero());

    const endpoint = timer_runner.Timer{};
    const vacuous = try timer_component.evaluateRows(
        QM31,
        &([_]QM31{QM31.zero()} ** timer_air.N_MAIN_COLUMNS),
        &([_]QM31{QM31.zero()} ** timer_air.N_MAIN_COLUMNS),
        QM31.zero(),
        QM31.zero(),
        QM31.one(),
        QM31.one(),
        endpoint,
        endpoint,
    );
    try std.testing.expect(!vacuous.allZero());
}

test "timer IF access validation rejects value drift and inactive garbage" {
    try std.testing.expectError(
        error.InvalidTimerIfValueTransition,
        subject.columnsForAccess(.{
            .enabled = true,
            .previous_clock = 3,
            .previous_value = 0x01,
            .clock = 8,
            .next_value = 0x01,
        }),
    );
    try std.testing.expectError(
        error.InvalidInactiveAccess,
        subject.columnsForAccess(.{ .previous_value = 1 }),
    );
    try std.testing.expectError(
        error.InvalidLogSize,
        subject.generateWitness(
            std.testing.allocator,
            3,
            &.{requestingEvent(0)},
            &.{.{}},
        ),
    );
}

fn requestingEvent(mcycle: u32) timer_binding.EventRow {
    const transition = timer_air.Transition.apply(
        .{
            .tima = 0x42,
            .tma = 0x42,
            .reload_state = .reloading,
        },
        .tick_mcycle,
    );
    std.debug.assert(transition.interrupt_requested);
    return .{
        .mcycle = mcycle,
        .transition = transition,
        .provenance = .{ .execution_tick = .{
            .execution_row = 0,
            .cycle = 0,
        } },
    };
}

fn requestClock() u32 {
    return memory_lookup.memory_clock.phaseClock(
        7,
        memory_lookup.memory_clock.TIMER_PHASE,
    ) catch unreachable;
}

fn quietEvent(mcycle: u32) timer_binding.EventRow {
    const transition = timer_air.Transition.apply(
        .{},
        .tick_mcycle,
    );
    std.debug.assert(!transition.interrupt_requested);
    return .{
        .mcycle = mcycle,
        .transition = transition,
        .provenance = .{ .execution_tick = .{
            .execution_row = 0,
            .cycle = 0,
        } },
    };
}

fn bindingColumns(
    event: timer_binding.EventRow,
) [timer_binding.N_MAIN_COLUMNS]M31 {
    var values = timer_binding.inactiveColumns();
    const semantic = timer_component.columns(
        timer_air.ValidatedStep.init(event.transition) catch unreachable,
    );
    @memcpy(values[0..semantic.len], &semantic);
    values[timer_binding.MCYCLE_OFFSET] =
        M31.fromCanonical(event.mcycle);
    return values;
}

fn liftTimer(
    values: [timer_binding.N_MAIN_COLUMNS]M31,
) !subject.TimerRow(QM31) {
    var lifted: [timer_binding.N_MAIN_COLUMNS]QM31 = undefined;
    for (&lifted, values) |*target, source|
        target.* = QM31.fromBase(source);
    return subject.TimerRow(QM31).fromColumns(&lifted);
}

fn liftRow(
    values: [subject.N_MAIN_COLUMNS]M31,
) !subject.Row(QM31) {
    var lifted: [subject.N_MAIN_COLUMNS]QM31 = undefined;
    for (&lifted, values) |*target, source|
        target.* = QM31.fromBase(source);
    return subject.Row(QM31).fromColumns(&lifted);
}

fn boundaryPair(
    relation: memory_lookup.Relation,
    initial_clock: u32,
    initial_value: u8,
    final_clock: u32,
    final_value: u8,
) memory_lookup.RowPair {
    return .{
        .n1 = QM31.one(),
        .d1 = relation.combine(
            q(runner.cartridge_memory.INTERRUPT_FLAGS),
            q(initial_clock),
            q(initial_value),
        ),
        .n2 = QM31.one().neg(),
        .d2 = relation.combine(
            q(runner.cartridge_memory.INTERRUPT_FLAGS),
            q(final_clock),
            q(final_value),
        ),
    };
}

fn q(value: anytype) QM31 {
    return QM31.fromBase(M31.fromU64(@intCast(value)));
}
