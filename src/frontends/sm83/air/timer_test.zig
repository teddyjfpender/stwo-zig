const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const subject = @import("timer.zig");
const timer = @import("../runner/timer.zig");

test "timer AIR has exact cubic degree and geometry" {
    try std.testing.expectEqual(@as(usize, 123), subject.N_MAIN_COLUMNS);
    try std.testing.expectEqual(@as(usize, 330), subject.N_CONSTRAINTS);
    try std.testing.expectEqual(@as(usize, 38), subject.N_CHAIN_CONSTRAINTS);

    const variables =
        [_]Degree{Degree.variable()} ** subject.N_MAIN_COLUMNS;
    const evaluation = subject.Semantics(Degree).evaluate(
        try subject.Semantics(Degree).Row.fromColumns(&variables),
        Degree.variable(),
    );
    var maximum: u32 = 0;
    for (evaluation.values) |constraint|
        maximum = @max(maximum, constraint.degree);
    try std.testing.expectEqual(@as(u32, 3), maximum);
    const chain = subject.Semantics(Degree).evaluateChain(
        try subject.Semantics(Degree).Row.fromColumns(&variables),
        try subject.Semantics(Degree).Row.fromColumns(&variables),
    );
    maximum = 0;
    for (chain.values) |constraint|
        maximum = @max(maximum, constraint.degree);
    try std.testing.expectEqual(@as(u32, 1), maximum);
}

test "timer AIR accepts every divider checkpoint and TAC frequency tick" {
    var accepted: usize = 0;
    for (0..1 << 16) |div_value| {
        const low: u16 = @intCast(div_value & 0x3ff);
        const at_falling_edge =
            low >= 12 and low <= 15 or
            low >= 28 and low <= 31 or
            low >= 124 and low <= 127 or
            low >= 508 and low <= 511;
        for (0..8) |tac_value| {
            const before = timer.Timer{
                .div_counter = @intCast(div_value),
                .tima = if (at_falling_edge)
                    0xff
                else
                    @truncate(div_value),
                .tma = @truncate(div_value >> 8),
                .tac = @intCast(tac_value),
                .reload_state = @enumFromInt(
                    @as(u2, @intCast((div_value + tac_value) % 3)),
                ),
            };
            try expectHonest(subject.Transition.apply(
                before,
                .tick_mcycle,
            ));
            accepted += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 524_288), accepted);
}

test "timer AIR accepts exhaustive write values signals and reload conflicts" {
    var accepted: usize = 0;
    for (0..256) |raw_value| {
        const value: u8 = @intCast(raw_value);
        for (0..3) |reload_value| {
            const before = timer.Timer{
                .div_counter = @as(u16, value) * 257,
                .tima = value ^ 0xa5,
                .tma = value ^ 0x5a,
                .tac = @truncate(value),
                .reload_state = @enumFromInt(
                    @as(u2, @intCast(reload_value)),
                ),
            };
            inline for ([_]subject.Event{
                .{ .write_div = value },
                .{ .write_tima = value },
                .{ .write_tma = value },
                .{ .write_tac = value },
            }) |event_value| {
                try expectHonest(subject.Transition.apply(
                    before,
                    event_value,
                ));
                accepted += 1;
            }
        }
    }

    for (0..1024) |div_value| {
        for (0..8) |old_tac| {
            const before = timer.Timer{
                .div_counter = @intCast(div_value),
                .tima = 0xff,
                .tma = @truncate(div_value),
                .tac = @intCast(old_tac),
                .reload_state = @enumFromInt(
                    @as(u2, @intCast(div_value % 3)),
                ),
            };
            try expectHonest(subject.Transition.apply(
                before,
                .{ .write_div = @truncate(div_value) },
            ));
            accepted += 1;
            for (0..8) |new_tac| {
                try expectHonest(subject.Transition.apply(
                    before,
                    .{ .write_tac = @intCast(new_tac) },
                ));
                accepted += 1;
            }
        }
    }
    try std.testing.expectEqual(@as(usize, 76_800), accepted);
}

test "timer AIR rejects every output auxiliary chain and vacuity mutation" {
    const before = timer.Timer{
        .div_counter = 12,
        .tima = 0xff,
        .tma = 0x42,
        .tac = 0x05,
        .reload_state = .reloading,
    };
    const transition = subject.Transition.apply(before, .tick_mcycle);
    const validated = try subject.ValidatedStep.init(transition);
    const honest = subject.columns(validated);
    try std.testing.expect(try satisfied(honest, true));

    for (
        subject.AFTER_STATE_OFFSET..subject.AFTER_STATE_OFFSET + subject.N_STATE_COLUMNS + 1,
    ) |column| {
        var forged = honest;
        forged[column] = flip(forged[column]);
        try std.testing.expect(!try satisfied(forged, true));
    }
    for (subject.BASE_N_MAIN_COLUMNS..subject.N_MAIN_COLUMNS) |column| {
        var forged = honest;
        forged[column] = flip(forged[column]);
        try std.testing.expect(!try satisfied(forged, true));
    }
    for (0..5) |column| {
        var forged = honest;
        forged[column] = flip(forged[column]);
        try std.testing.expect(!try satisfied(forged, true));
    }
    for (
        subject.ACTION_COLUMN_OFFSET..subject.ACTION_COLUMN_OFFSET + 8,
    ) |column| {
        var forged = honest;
        forged[column] = M31.one();
        try std.testing.expect(!try satisfied(forged, true));
    }

    const second_transition = subject.Transition.apply(
        transition.after,
        .{ .write_tma = 0x99 },
    );
    const second = subject.columns(
        try subject.ValidatedStep.init(second_transition),
    );
    const honest_chain = try subject.evaluateChain(honest, second);
    try std.testing.expect(honest_chain.allZero());
    for (
        subject.BEFORE_STATE_OFFSET..subject.BEFORE_STATE_OFFSET + subject.N_STATE_COLUMNS,
    ) |column| {
        var forged = second;
        forged[column] = flip(forged[column]);
        const chain = try subject.evaluateChain(honest, forged);
        try std.testing.expect(!chain.allZero());
    }

    const inactive = subject.inactiveColumns();
    try std.testing.expect(try satisfied(inactive, false));
    for (0..subject.N_MAIN_COLUMNS) |column| {
        var forged = inactive;
        forged[column] = M31.one();
        try std.testing.expect(!try satisfied(forged, false));
    }
}

test "timer AIR validation rejects forged transition metadata" {
    const transition = subject.Transition.apply(
        .{
            .div_counter = 12,
            .tima = 0xff,
            .tma = 0x42,
            .tac = 0x05,
            .reload_state = .reloading,
        },
        .tick_mcycle,
    );
    _ = try subject.ValidatedStep.init(transition);

    var forged = transition;
    forged.after.tima ^= 1;
    try std.testing.expectError(
        error.InvalidTimerTransition,
        subject.ValidatedStep.init(forged),
    );
    forged = transition;
    forged.after.reload_state = .running;
    try std.testing.expectError(
        error.InvalidTimerTransition,
        subject.ValidatedStep.init(forged),
    );
    forged = transition;
    forged.interrupt_requested = !forged.interrupt_requested;
    try std.testing.expectError(
        error.InvalidTimerTransition,
        subject.ValidatedStep.init(forged),
    );
    forged = transition;
    forged.event = .{ .write_div = 0 };
    try std.testing.expectError(
        error.InvalidTimerTransition,
        subject.ValidatedStep.init(forged),
    );
}

fn expectHonest(transition: subject.Transition) !void {
    const columns = subject.columns(
        try subject.ValidatedStep.init(transition),
    );
    const row = try subject.Semantics(M31).Row.fromColumns(&columns);
    const evaluation = subject.Semantics(M31).evaluate(row, M31.one());
    try std.testing.expect(evaluation.allZero());
}

fn satisfied(
    columns: [subject.N_MAIN_COLUMNS]M31,
    active: bool,
) !bool {
    const row = try subject.Semantics(M31).Row.fromColumns(&columns);
    return subject.Semantics(M31).evaluate(
        row,
        if (active) M31.one() else M31.zero(),
    ).allZero();
}

fn flip(value: M31) M31 {
    return if (value.isZero()) M31.one() else M31.zero();
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
    pub fn add(left: Degree, right: Degree) Degree {
        return .{ .degree = @max(left.degree, right.degree) };
    }
    pub fn sub(left: Degree, right: Degree) Degree {
        return left.add(right);
    }
    pub fn mul(left: Degree, right: Degree) Degree {
        return .{ .degree = left.degree + right.degree };
    }
    pub fn isZero(_: Degree) bool {
        return false;
    }
};
