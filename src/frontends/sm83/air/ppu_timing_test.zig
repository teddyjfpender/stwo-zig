const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const air = @import("ppu_timing.zig");
const layout = @import("ppu_timing_witness.zig");
const ppu = @import("../runner/ppu_timing.zig");

const EVENT_OFFSET: usize = 0;
const BEFORE_OFFSET: usize = 4;
const ACTION_OFFSET: usize = 42;
const AFTER_OFFSET: usize = 50;
const INTERRUPT_OFFSET: usize = 88;
const LY_READ_OFFSET: usize = 90;
const STAT_READ_OFFSET: usize = 98;

const StateOffset = struct {
    const lcd: usize = 0;
    const line: usize = 1;
    const dot: usize = 9;
    const startup: usize = 18;
    const lyc: usize = 19;
    const stat_enable: usize = 27;
    const coincidence: usize = 31;
    const lyc_line: usize = 32;
    const stat_line: usize = 33;
    const mode: usize = 34;
};

test "PPU AIR has exact cubic degree and geometry" {
    try std.testing.expectEqual(@as(usize, 209), air.N_MAIN_COLUMNS);
    try std.testing.expectEqual(@as(usize, 574), air.N_CONSTRAINTS);
    try std.testing.expectEqual(@as(usize, 38), air.N_CHAIN_CONSTRAINTS);

    const DegreeSemantics = air.Semantics(Degree);
    const variables = [_]Degree{Degree.variable()} ** air.N_MAIN_COLUMNS;
    const row = try DegreeSemantics.Row.fromColumns(&variables);
    const evaluation = DegreeSemantics.evaluate(row, Degree.variable());
    var maximum: u32 = 0;
    for (evaluation.values) |constraint|
        maximum = @max(maximum, constraint.degree);
    try std.testing.expectEqual(@as(u32, 3), maximum);
    for (DegreeSemantics.evaluateChain(row, row).values) |constraint|
        try std.testing.expect(constraint.degree <= 1);
}

test "PPU AIR accepts one exhaustive fixed frame and pinned boundaries" {
    var state = canonicalState(0, 0, 0xff, 0);
    const expected_count: usize =
        @as(usize, ppu.LINES_PER_FRAME) * ppu.DOTS_PER_LINE;
    for (0..expected_count) |_| {
        const transition = try ppu.Transition.apply(state, .tick_dot);
        try expectHonest(transition);
        state = transition.after;
    }
    try std.testing.expectEqual(@as(u8, 0), state.line);
    try std.testing.expectEqual(@as(u16, 0), state.dot);

    for (ppu.REFERENCE_VECTOR) |point| {
        const boundary =
            canonicalState(point.line, point.dot, 0xff, 0);
        try std.testing.expectEqual(point.mode, boundary.mode());
        try std.testing.expectEqual(point.ly, boundary.readLy());
        try expectHonest(try ppu.Transition.apply(boundary, .tick_dot));
    }
}

test "PPU AIR rejects a vblank selector while LCD is disabled" {
    const transition = try ppu.Transition.apply(ppu.State{}, .tick_dot);
    const honest = air.columns(try air.ValidatedStep.init(transition));
    try std.testing.expect((try air.evaluate(honest, true)).allZero());

    var forged = honest;
    forged[layout.BEFORE_LINE_SEGMENT_OFFSET + 6] = M31.one();
    try std.testing.expect(!(try air.evaluate(forged, true)).allZero());
}

test "PPU AIR classifies every byte write and chained IF edges" {
    const disabled = ppu.State{};
    const enabled = canonicalState(42, 79, 0xff, 0);
    for (0..256) |raw| {
        const value: u8 = @intCast(raw);
        try expectHonest(try ppu.Transition.apply(
            disabled,
            .{ .write_lcdc = value },
        ));
        try expectHonest(try ppu.Transition.apply(
            enabled,
            .{ .write_lcdc = value },
        ));
        const stat_write = try ppu.Transition.apply(
            enabled,
            .{ .write_stat = value },
        );
        const stat_row = air.columns(try air.ValidatedStep.init(stat_write));
        try std.testing.expectEqual(
            value & 0x08 == 0,
            (try air.evaluate(stat_row, true)).allZero(),
        );
        try expectHonest(try ppu.Transition.apply(
            enabled,
            .{ .write_lyc = value },
        ));
    }

    const enable = try ppu.Transition.apply(
        disabled,
        .{ .write_lcdc = 0x80 },
    );
    const first = air.columns(try air.ValidatedStep.init(enable));
    const lyc = try ppu.Transition.apply(
        enable.after,
        .{ .write_lyc = 0 },
    );
    const second = air.columns(try air.ValidatedStep.init(lyc));
    try std.testing.expect((try air.evaluateChain(first, second)).allZero());
    const tick = try ppu.Transition.apply(lyc.after, .tick_dot);
    const third = air.columns(try air.ValidatedStep.init(tick));
    try std.testing.expect((try air.evaluateChain(second, third)).allZero());

    const vblank = canonicalState(143, 455, 0xff, 0x4);
    const boundary = try ppu.Transition.apply(vblank, .tick_dot);
    try std.testing.expect(!boundary.interrupts.vblank);
    try std.testing.expect(!boundary.interrupts.stat);
    try expectHonest(boundary);
    const edge = try ppu.Transition.apply(boundary.after, .tick_dot);
    try std.testing.expect(edge.interrupts.vblank);
    try std.testing.expect(edge.interrupts.stat);
    try expectHonest(edge);
    try expectHonest(try ppu.Transition.apply(edge.after, .tick_dot));
}

test "PPU AIR binds every auxiliary inverse branch chain and vacuity" {
    const before = canonicalState(144, 0, 0xff, 0x4);
    const first_transition = try ppu.Transition.apply(before, .tick_dot);
    const honest = air.columns(try air.ValidatedStep.init(first_transition));
    try std.testing.expect((try air.evaluate(honest, true)).allZero());

    const semantic_mutations = [_]usize{
        BEFORE_OFFSET + StateOffset.line,
        BEFORE_OFFSET + StateOffset.dot,
        BEFORE_OFFSET + StateOffset.mode,
        BEFORE_OFFSET + StateOffset.stat_enable,
        AFTER_OFFSET + StateOffset.lcd,
        AFTER_OFFSET + StateOffset.line,
        AFTER_OFFSET + StateOffset.dot,
        AFTER_OFFSET + StateOffset.startup,
        AFTER_OFFSET + StateOffset.lyc,
        AFTER_OFFSET + StateOffset.stat_enable,
        AFTER_OFFSET + StateOffset.coincidence,
        AFTER_OFFSET + StateOffset.lyc_line,
        AFTER_OFFSET + StateOffset.stat_line,
        AFTER_OFFSET + StateOffset.mode + 1,
        INTERRUPT_OFFSET,
        INTERRUPT_OFFSET + 1,
        LY_READ_OFFSET,
        STAT_READ_OFFSET,
    };
    for (semantic_mutations) |column|
        try expectMutation(honest, column);

    var forged_event = honest;
    forged_event[EVENT_OFFSET] = M31.zero();
    forged_event[EVENT_OFFSET + 1] = M31.one();
    forged_event[ACTION_OFFSET + 7] = M31.one();
    try std.testing.expect(
        !(try air.evaluate(forged_event, true)).allZero(),
    );
    for (layout.BASE_N_MAIN_COLUMNS..air.N_MAIN_COLUMNS) |column|
        try expectMutation(honest, column);

    const nonzero = air.columns(try air.ValidatedStep.init(
        try ppu.Transition.apply(
            canonicalState(10, 100, 77, 0),
            .tick_dot,
        ),
    ));
    for (0..layout.N_EQUALITIES) |equality| {
        try expectMutation(
            nonzero,
            layout.BEFORE_EQUALITY_OFFSET + equality,
        );
        try expectMutation(
            nonzero,
            layout.AFTER_EQUALITY_OFFSET + equality,
        );
        try expectMutation(
            nonzero,
            layout.BEFORE_INVERSE_OFFSET + equality,
        );
        try expectMutation(
            nonzero,
            layout.AFTER_INVERSE_OFFSET + equality,
        );
    }
    const zero_states = [_]ppu.State{
        canonicalState(10, 100, 10, 0),
        canonicalState(10, 100, 153, 0),
        canonicalState(10, 100, 0, 0),
    };
    for (zero_states, 0..) |zero_state, equality| {
        const zero = air.columns(try air.ValidatedStep.init(
            try ppu.Transition.apply(zero_state, .tick_dot),
        ));
        try expectMutation(
            zero,
            layout.BEFORE_EQUALITY_OFFSET + equality,
        );
        try expectMutation(
            zero,
            layout.AFTER_EQUALITY_OFFSET + equality,
        );
        try expectMutation(
            zero,
            layout.BEFORE_INVERSE_OFFSET + equality,
        );
        try expectMutation(
            zero,
            layout.AFTER_INVERSE_OFFSET + equality,
        );
    }

    const next_transition = try ppu.Transition.apply(
        first_transition.after,
        .tick_dot,
    );
    var broken_chain =
        air.columns(try air.ValidatedStep.init(next_transition));
    broken_chain[BEFORE_OFFSET + StateOffset.line] =
        M31.one().sub(broken_chain[BEFORE_OFFSET + StateOffset.line]);
    try std.testing.expect(
        !(try air.evaluateChain(honest, broken_chain)).allZero(),
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

test "PPU AIR validation rejects forged transition metadata" {
    var transition = try ppu.Transition.apply(
        canonicalState(10, 79, 0xff, 0),
        .tick_dot,
    );
    transition.stat_read ^= 1;
    try std.testing.expectError(
        error.InvalidPpuTimingTransition,
        air.ValidatedStep.init(transition),
    );
}

fn canonicalState(
    line: u8,
    dot: u16,
    lyc: u8,
    stat_enable: u4,
) ppu.State {
    var state = ppu.State{
        .lcd_enabled = true,
        .line = line,
        .dot = dot,
        .lyc = lyc,
        .stat_enable = stat_enable,
    };
    if (line != 153) {
        state.coincidence = line == lyc;
        state.lyc_interrupt_line = state.coincidence;
    } else if (dot >= 6 and dot < 8) {
        state.coincidence = lyc == 153;
        state.lyc_interrupt_line = state.coincidence;
    } else if (dot >= 12) {
        state.coincidence = lyc == 0;
        state.lyc_interrupt_line = state.coincidence;
    }
    const mode_enabled = switch (state.mode()) {
        .hblank => stat_enable & 0x1 != 0,
        .vblank => stat_enable & 0x2 != 0,
        .oam => stat_enable & 0x4 != 0,
        .transfer => false,
    };
    state.stat_interrupt_line =
        mode_enabled or (stat_enable & 0x8 != 0 and
            state.lyc_interrupt_line);
    std.debug.assert((ppu.State.restore(state) catch null) != null);
    return state;
}

fn expectHonest(transition: ppu.Transition) !void {
    const row = air.columns(try air.ValidatedStep.init(transition));
    try std.testing.expect((try air.evaluate(row, true)).allZero());
}

fn expectMutation(
    honest: [air.N_MAIN_COLUMNS]M31,
    column: usize,
) !void {
    var forged = honest;
    forged[column] = if (forged[column].isZero())
        M31.one()
    else
        M31.zero();
    try std.testing.expect(!(try air.evaluate(forged, true)).allZero());
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
