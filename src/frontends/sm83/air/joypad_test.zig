const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const air = @import("joypad.zig");
const joypad = @import("../runner/joypad.zig");

const EVENT_OFFSET: usize = 0;
const BEFORE_P1_OFFSET: usize = 3;
const BEFORE_PRESSED_OFFSET: usize = 11;
const ACTION_OFFSET: usize = 27;
const AFTER_P1_OFFSET: usize = 35;
const AFTER_PRESSED_OFFSET: usize = 43;
const AFTER_PENDING_OFFSET: usize = 51;
const AFTER_DELAY_OFFSET: usize = 53;
const READ_OFFSET: usize = 59;
const EDGE_OFFSET: usize = 67;
const DELAY_HOT_OFFSET: usize = 68;
const AUXILIARY_OFFSET: usize = 117;

test "joypad AIR constraints are at most cubic" {
    const DegreeSemantics = air.Semantics(Degree);
    const variables = [_]Degree{Degree.variable()} ** air.N_MAIN_COLUMNS;
    const row = try DegreeSemantics.Row.fromColumns(&variables);
    const evaluation = DegreeSemantics.evaluate(row, Degree.variable());
    var maximum: u32 = 0;
    for (evaluation.values) |constraint|
        maximum = @max(maximum, constraint.degree);
    try std.testing.expectEqual(@as(u32, 3), maximum);

    const chain = DegreeSemantics.evaluateChain(row, row);
    for (chain.values) |constraint|
        try std.testing.expect(constraint.degree <= 1);
}

test "joypad AIR accepts exhaustive key replacement and selector writes" {
    comptime {
        std.debug.assert(air.N_MAIN_COLUMNS == 143);
        std.debug.assert(air.N_CONSTRAINTS == 336);
    }
    for (0..4) |selection| {
        const before = try stableState(@intCast(selection), 0);
        for (0..256) |pressed| {
            try expectHonest(try joypad.Transition.apply(
                before,
                .{ .set_pressed = @intCast(pressed) },
            ));
        }
        for (0..4) |requested| {
            try expectHonest(try joypad.Transition.apply(
                before,
                .{ .write_p1 = @as(u8, @intCast(requested)) << 4 },
            ));
        }
    }
}

test "joypad AIR accepts delayed ticks and mid-transition selector writes" {
    for (0..4) |previous| {
        const before = try stableState(@intCast(previous), 0x95);
        for (0..4) |requested| {
            const first = try joypad.Transition.apply(
                before,
                .{ .write_p1 = @as(u8, @intCast(requested)) << 4 },
            );
            try expectHonest(first);
            var current = first.after;
            while (current.switching_delay != 0) {
                const tick = try joypad.Transition.apply(
                    current,
                    .tick_mcycle,
                );
                try expectHonest(tick);
                current = tick.after;
            }
            for (0..4) |second| {
                try expectHonest(try joypad.Transition.apply(
                    first.after,
                    .{ .write_p1 = @as(u8, @intCast(second)) << 4 },
                ));
            }
        }
    }
}

test "joypad AIR matches arbitrary canonical pending-delay checkpoints" {
    const delays = [_]u8{ 1, 7, 8, 9, 24, 25, 47, 48 };
    const key_masks = [_]u8{ 0, 0x55, 0xaa, 0xff };
    for (0..4) |internal| {
        for (0..4) |pending| {
            for (delays) |delay| {
                for (key_masks) |pressed| {
                    const stable = try stableState(@intCast(internal), pressed);
                    const before = try joypad.State.init(
                        stable.p1,
                        pressed,
                        @intCast(pending),
                        delay,
                    );
                    try expectHonest(try joypad.Transition.apply(
                        before,
                        .tick_mcycle,
                    ));
                    try expectHonest(try joypad.Transition.apply(
                        before,
                        .{ .set_pressed = ~pressed },
                    ));
                    for (0..4) |requested| {
                        try expectHonest(try joypad.Transition.apply(
                            before,
                            .{
                                .write_p1 = @as(u8, @intCast(requested)) << 4,
                            },
                        ));
                    }
                }
            }
        }
    }
}

test "joypad AIR binds every auxiliary chain and inactive witness" {
    const first_transition = try joypad.Transition.apply(
        try stableState(2, 0),
        .{ .set_pressed = joypad.Key.right.mask() },
    );
    const first = air.columns(try air.ValidatedStep.init(first_transition));
    try std.testing.expect((try air.evaluate(first, true)).allZero());

    const second_transition = try joypad.Transition.apply(
        first_transition.after,
        .{ .write_p1 = 0x10 },
    );
    const second = air.columns(try air.ValidatedStep.init(second_transition));
    try std.testing.expect((try air.evaluate(second, true)).allZero());
    try std.testing.expect((try air.evaluateChain(first, second)).allZero());

    const semantic_mutations = [_]usize{
        ACTION_OFFSET,
        AFTER_P1_OFFSET,
        AFTER_PRESSED_OFFSET,
        AFTER_PENDING_OFFSET,
        AFTER_DELAY_OFFSET,
        READ_OFFSET,
        EDGE_OFFSET,
    };
    for (semantic_mutations) |column| {
        var forged = first;
        forged[column] = M31.one().sub(forged[column]);
        try std.testing.expect(!(try air.evaluate(forged, true)).allZero());
    }

    var forged_event = first;
    forged_event[EVENT_OFFSET] = M31.zero();
    forged_event[EVENT_OFFSET + 1] = M31.one();
    try std.testing.expect(!(try air.evaluate(forged_event, true)).allZero());

    var forged_delay = first;
    forged_delay[DELAY_HOT_OFFSET] = M31.zero();
    forged_delay[DELAY_HOT_OFFSET + 1] = M31.one();
    try std.testing.expect(!(try air.evaluate(forged_delay, true)).allZero());

    for (AUXILIARY_OFFSET..air.N_MAIN_COLUMNS) |column| {
        var forged = first;
        forged[column] = if (forged[column].isZero())
            M31.one()
        else
            M31.zero();
        try std.testing.expect(!(try air.evaluate(forged, true)).allZero());
    }

    var broken_chain = second;
    broken_chain[BEFORE_PRESSED_OFFSET] =
        M31.one().sub(broken_chain[BEFORE_PRESSED_OFFSET]);
    try std.testing.expect(
        !(try air.evaluateChain(first, broken_chain)).allZero(),
    );

    const inactive = air.inactiveColumns();
    try std.testing.expect((try air.evaluate(inactive, false)).allZero());
    for (0..air.N_MAIN_COLUMNS) |column| {
        var non_vacuous = inactive;
        non_vacuous[column] = M31.one();
        try std.testing.expect(
            !(try air.evaluate(non_vacuous, false)).allZero(),
        );
    }
}

test "joypad AIR validation rejects forged transition metadata" {
    var transition = try joypad.Transition.apply(
        try stableState(1, 0x10),
        .{ .set_pressed = 0 },
    );
    transition.p1_read ^= 1;
    try std.testing.expectError(
        error.InvalidJoypadTransition,
        air.ValidatedStep.init(transition),
    );
    transition = try joypad.Transition.apply(
        try stableState(1, 0x10),
        .{ .set_pressed = 0 },
    );
    transition.interrupt_requested = !transition.interrupt_requested;
    try std.testing.expectError(
        error.InvalidJoypadTransition,
        air.ValidatedStep.init(transition),
    );
}

fn stableState(selection: u2, pressed: u8) !joypad.State {
    var state = joypad.State{};
    _ = state.setPressed(pressed);
    _ = state.writeP1(@as(u8, selection) << 4);
    _ = state.tickSameBoyCycles(48);
    try state.validate();
    return state;
}

fn expectHonest(transition: joypad.Transition) !void {
    const witness = air.columns(try air.ValidatedStep.init(transition));
    try std.testing.expect((try air.evaluate(witness, true)).allZero());
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
        return .{ .degree = @max(left.degree, right.degree) };
    }

    pub fn mul(left: Degree, right: Degree) Degree {
        return .{ .degree = left.degree + right.degree };
    }

    pub fn isZero(_: Degree) bool {
        return false;
    }
};
