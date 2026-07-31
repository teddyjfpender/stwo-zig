const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const subject = @import("timer_binding_component.zig");
const binding = @import("timer_binding.zig");
const timer_component = @import("timer_component.zig");
const timer_air = @import("timer.zig");
const timer = @import("../runner/timer.zig");

test "timer binding component is exactly cubic with offset-safe geometry" {
    const variables =
        [_]Degree{Degree.variable()} ** binding.N_MAIN_COLUMNS;
    const evaluation = try subject.evaluateRows(
        Degree,
        &variables,
        &variables,
        Degree.variable(),
        Degree.variable(),
        7,
        9,
    );
    var maximum: u32 = 0;
    for (evaluation.values) |constraint|
        maximum = @max(maximum, constraint.degree);
    try std.testing.expectEqual(subject.MAX_CONSTRAINT_DEGREE, maximum);
    try std.testing.expectEqual(@as(usize, 40), subject.N_CONSTRAINTS);

    const component = subject.Component{
        .log_size = 4,
        .is_first_column = 2,
        .is_last_column = 4,
        .main_offset = 7,
        .initial_mcycle = 7,
        .final_mcycle = 9,
    };
    try std.testing.expectEqual(
        subject.N_CONSTRAINTS,
        component.nConstraints(),
    );
    try std.testing.expectEqual(
        @as(u32, 5),
        component.maxConstraintLogDegreeBound(),
    );
    _ = component.asVerifierComponent();
    _ = component.asProverComponent();
    const indices = try component.preprocessedColumnIndices(
        std.testing.allocator,
    );
    defer std.testing.allocator.free(indices);
    try std.testing.expectEqualSlices(usize, &.{ 2, 4 }, indices);

    var bounds = try component.traceLogDegreeBounds(
        std.testing.allocator,
    );
    defer bounds.deinitDeep(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 5), bounds.items[0].len);
    try std.testing.expectEqual(
        7 + binding.N_MAIN_COLUMNS,
        bounds.items[1].len,
    );
    var mask = try component.maskPoints(
        std.testing.allocator,
        core.circle.SECURE_FIELD_CIRCLE_GEN,
        component.maxConstraintLogDegreeBound(),
    );
    defer mask.deinitDeep(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 5), mask.items[0].len);
    try std.testing.expectEqual(
        7 + binding.N_MAIN_COLUMNS,
        mask.items[1].len,
    );
    for (mask.items[0]) |column|
        try std.testing.expectEqual(@as(usize, 1), column.len);
    for (mask.items[1]) |column|
        try std.testing.expectEqual(@as(usize, 2), column.len);
}

test "timer binding component binds write tick read clock and endpoints" {
    const initial = timer.Timer{
        .div_counter = 0x1200,
        .tima = 0x22,
        .tma = 0x33,
        .tac = 0x05,
    };
    const write_transition = timer_air.Transition.apply(
        initial,
        .{ .write_tima = 0x44 },
    );
    const tick_transition = timer_air.Transition.apply(
        write_transition.after,
        .tick_mcycle,
    );
    var write = row(write_transition, 7, null);
    var tick = row(tick_transition, 7, .tima);
    const inactive =
        [_]QM31{QM31.zero()} ** binding.N_MAIN_COLUMNS;
    const component = subject.Component{
        .log_size = 4,
        .is_first_column = 0,
        .is_last_column = 1,
        .main_offset = 0,
        .initial_mcycle = 7,
        .final_mcycle = 8,
    };
    try expect(&component, &write, &tick, true, false, true);
    try expect(&component, &tick, &inactive, false, false, true);
    try expect(&component, &tick, &write, false, true, true);

    tick[binding.MCYCLE_OFFSET] =
        QM31.fromBase(M31.fromCanonical(8));
    try expect(&component, &write, &tick, true, false, false);
    tick[binding.MCYCLE_OFFSET] =
        QM31.fromBase(M31.fromCanonical(7));

    for (binding.READ_VALUE_OFFSET..binding.N_MAIN_COLUMNS) |column| {
        tick[column] = QM31.one().sub(tick[column]);
        try expect(&component, &tick, &inactive, false, false, false);
        tick[column] = QM31.one().sub(tick[column]);
    }
    const read_tick = tick;
    tick[binding.READ_MARKER_OFFSET + @intFromEnum(binding.Register.tima)] =
        QM31.zero();
    for (tick[binding.READ_VALUE_OFFSET..]) |*value|
        value.* = QM31.zero();
    // Removing the read is a locally valid timer tick. The read LogUp owner
    // rejects it against the execution-side MMIO read.
    try expect(&component, &tick, &inactive, false, false, true);
    tick = read_tick;

    const repeated_write = write;
    try expect(
        &component,
        &write,
        &repeated_write,
        true,
        false,
        false,
    );
    var forged = component;
    forged.final_mcycle = 9;
    try expect(&forged, &tick, &inactive, false, false, false);
    forged = component;
    forged.initial_mcycle = 6;
    try expect(&forged, &write, &tick, true, false, false);
}

test "timer binding component rejects nonbinary and inactive binding data" {
    const tick_transition = timer_air.Transition.apply(
        .{ .tma = 0xa5 },
        .tick_mcycle,
    );
    const tick = row(tick_transition, 0, .tma);
    const inactive =
        [_]QM31{QM31.zero()} ** binding.N_MAIN_COLUMNS;

    var nonbinary_marker = tick;
    nonbinary_marker[binding.READ_MARKER_OFFSET + 2] =
        QM31.fromBase(M31.fromCanonical(2));
    try expectRows(
        &nonbinary_marker,
        &inactive,
        false,
        false,
        0,
        1,
        false,
    );
    var multiple_markers = tick;
    multiple_markers[binding.READ_MARKER_OFFSET] = QM31.one();
    try expectRows(
        &multiple_markers,
        &inactive,
        false,
        false,
        0,
        1,
        false,
    );
    var nonbinary_bit = tick;
    nonbinary_bit[binding.READ_VALUE_OFFSET] =
        QM31.fromBase(M31.fromCanonical(2));
    try expectRows(
        &nonbinary_bit,
        &inactive,
        false,
        false,
        0,
        1,
        false,
    );

    for (binding.MCYCLE_OFFSET..binding.N_MAIN_COLUMNS) |column| {
        var forged_inactive = inactive;
        forged_inactive[column] = QM31.one();
        try expectRows(
            &forged_inactive,
            &inactive,
            false,
            true,
            0,
            1,
            false,
        );
    }

    var non_tick_read = row(
        timer_air.Transition.apply(
            tick_transition.after,
            .{ .write_tma = 0x11 },
        ),
        1,
        null,
    );
    non_tick_read[binding.READ_MARKER_OFFSET + 2] = QM31.one();
    for (
        non_tick_read[binding.READ_VALUE_OFFSET..binding.N_MAIN_COLUMNS],
        0..,
    ) |*value, bit_index| {
        value.* = qBool((@as(u8, 0xa5) >> @intCast(bit_index) & 1) == 1);
    }
    try expectRows(
        &non_tick_read,
        &tick,
        false,
        false,
        0,
        2,
        false,
    );
}

fn row(
    transition: timer_air.Transition,
    mcycle: u32,
    read_register: ?binding.Register,
) [binding.N_MAIN_COLUMNS]QM31 {
    var result =
        [_]QM31{QM31.zero()} ** binding.N_MAIN_COLUMNS;
    const semantic = timer_component.columns(
        timer_air.ValidatedStep.init(transition) catch unreachable,
    );
    for (result[0..semantic.len], semantic) |*destination, value|
        destination.* = QM31.fromBase(value);
    result[binding.MCYCLE_OFFSET] =
        QM31.fromBase(M31.fromCanonical(mcycle));
    if (read_register) |register| {
        result[
            binding.READ_MARKER_OFFSET + @intFromEnum(register)
        ] = QM31.one();
        const value = binding.readTimerRegister(
            transition.before,
            register,
        );
        for (
            result[binding.READ_VALUE_OFFSET..binding.N_MAIN_COLUMNS],
            0..,
        ) |*destination, bit_index|
            destination.* = qBool(
                (value >> @intCast(bit_index) & 1) == 1,
            );
    }
    return result;
}

fn expect(
    component: *const subject.Component,
    current: []const QM31,
    next: []const QM31,
    is_first: bool,
    is_last: bool,
    expected: bool,
) !void {
    const evaluation = try component.evaluateRow(
        current,
        next,
        qBool(is_first),
        qBool(is_last),
    );
    try std.testing.expectEqual(expected, evaluation.allZero());
}

fn expectRows(
    current: []const QM31,
    next: []const QM31,
    is_first: bool,
    is_last: bool,
    initial_mcycle: u32,
    final_mcycle: u32,
    expected: bool,
) !void {
    const evaluation = try subject.evaluateRows(
        QM31,
        current,
        next,
        qBool(is_first),
        qBool(is_last),
        initial_mcycle,
        final_mcycle,
    );
    try std.testing.expectEqual(expected, evaluation.allZero());
}

fn qBool(value: bool) QM31 {
    return if (value) QM31.one() else QM31.zero();
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
