const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const apu = @import("../runner/apu_mmio.zig");
const binding = @import("apu_binding.zig");
const subject = @import("apu_binding_component.zig");
const layout = binding.layout;

test "APU binding component is exactly cubic and backend generic" {
    const variables =
        [_]Degree{Degree.variable()} ** layout.N_MAIN_COLUMNS;
    const evaluation = try subject.evaluateRows(
        Degree,
        &variables,
        &variables,
        Degree.variable(),
        Degree.variable(),
        .{},
        .{},
        1,
    );
    var maximum: u32 = 0;
    for (evaluation.values) |constraint|
        maximum = @max(maximum, constraint.degree);
    try std.testing.expectEqual(subject.MAX_CONSTRAINT_DEGREE, maximum);
    try std.testing.expectEqual(@as(usize, 663), layout.N_MAIN_COLUMNS);
    try std.testing.expectEqual(@as(usize, 1045), subject.N_CONSTRAINTS);

    const component = subject.Component{
        .log_size = 4,
        .is_first_column = 2,
        .is_last_column = 4,
        .main_offset = 7,
        .initial_state = .{},
        .final_state = .{},
        .event_count = 1,
    };
    try std.testing.expectEqual(@as(u32, 5), component.maxConstraintLogDegreeBound());
    try std.testing.expectEqual(subject.N_CONSTRAINTS, component.nConstraints());
    _ = component.asVerifierComponent();
    _ = component.asProverComponent();
    var bounds = try component.traceLogDegreeBounds(std.testing.allocator);
    defer bounds.deinitDeep(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 5), bounds.items[0].len);
    try std.testing.expectEqual(
        7 + layout.N_MAIN_COLUMNS,
        bounds.items[1].len,
    );
}

test "APU AIR accepts every runner read and write transition" {
    var enabled = apu.State{ .enabled = true, .channel_status = 0xa };
    for (&enabled.registers, 0..) |*register, index|
        register.* = @truncate(index * 37 + 11);
    enabled.registers[binding.registerIndex(apu.NR52)] = 0;

    for (apu.FIRST_ADDRESS..apu.LAST_ADDRESS + 1) |raw_address| {
        const address: u16 = @intCast(raw_address);
        const read = try apu.Transition.apply(enabled, .{ .read = address });
        try expectHonest(read);
        if (isUnused(address)) continue;
        for (0..256) |raw_value| {
            const value: u8 = @intCast(raw_value);
            const write = try apu.Transition.apply(enabled, .{ .write = .{
                .address = address,
                .value = value,
            } });
            try expectHonest(write);
        }
    }

    var disabled = apu.State{};
    @memset(&disabled.registers, 0x5a);
    disabled.registers[binding.registerIndex(apu.NR52)] = 0;
    disabled.channel_status = 0;
    disabled.wave_access = .inactive;
    for (apu.FIRST_ADDRESS..apu.WAVE_START) |raw_address| {
        const address: u16 = @intCast(raw_address);
        if (isUnused(address)) continue;
        for (0..256) |raw_value| {
            const write = try apu.Transition.apply(disabled, .{ .write = .{
                .address = address,
                .value = @intCast(raw_value),
            } });
            try expectHonest(write);
        }
    }
}

test "APU AIR proves blocked and current-byte wave aliasing" {
    var state = apu.State{
        .enabled = true,
        .channel_status = 4,
        .wave_access = .blocked,
    };
    state.registers[binding.registerIndex(0xff37)] = 0x61;
    try expectHonest(try apu.Transition.apply(
        state,
        .{ .read = apu.WAVE_START },
    ));
    try expectHonest(try apu.Transition.apply(state, .{ .write = .{
        .address = apu.WAVE_END,
        .value = 0xa5,
    } }));

    state.wave_access = .{ .current_byte = 7 };
    try expectHonest(try apu.Transition.apply(
        state,
        .{ .read = apu.WAVE_END },
    ));
    try expectHonest(try apu.Transition.apply(state, .{ .write = .{
        .address = apu.WAVE_START,
        .value = 0xa5,
    } }));
}

test "APU AIR rejects semantic endpoint chain and vacuity mutations" {
    var initial = apu.State{ .enabled = true, .channel_status = 3 };
    initial.registers[binding.registerIndex(0xff12)] = 0x71;
    const first = try apu.Transition.apply(
        initial,
        .{ .read = 0xff12 },
    );
    const second = try apu.Transition.apply(first.after, .{ .write = .{
        .address = apu.NR52,
        .value = 0,
    } });
    var first_row = try secureColumns(first);
    var second_row = try secureColumns(second);
    const inactive = secureInactive();
    try expectRows(first_row, second_row, true, false, initial, second.after, true);
    try expectRows(second_row, inactive, false, false, initial, second.after, true);

    const mutations = [_]usize{
        layout.READ_VALUE_BITS_OFFSET,
        layout.READ_ADDRESS_OFFSET + binding.registerIndex(0xff12),
        layout.BEFORE_STATE_OFFSET + binding.registerIndex(0xff12),
        layout.beforeRegisterBit(binding.registerIndex(0xff12), 0),
        layout.AFTER_STATE_OFFSET + binding.registerIndex(0xff12),
    };
    for (mutations) |column| {
        const saved = first_row[column];
        first_row[column] = flip(saved);
        try expectRows(first_row, second_row, true, false, initial, second.after, false);
        first_row[column] = saved;
    }
    second_row[layout.POWER_OFF_OFFSET] = QM31.zero();
    try expectRows(second_row, inactive, false, false, initial, second.after, false);
    second_row = try secureColumns(second);

    var forged_final = second.after;
    forged_final.registers[binding.registerIndex(apu.WAVE_START)] ^= 1;
    try expectRows(second_row, inactive, false, false, initial, forged_final, false);
    var forged_initial = initial;
    forged_initial.registers[binding.registerIndex(0xff12)] ^= 1;
    try expectRows(first_row, second_row, true, false, forged_initial, second.after, false);

    var broken_chain = second_row;
    broken_chain[layout.BEFORE_STATE_OFFSET + binding.registerIndex(0xff12)] =
        QM31.fromBase(M31.fromCanonical(0x70));
    try expectRows(first_row, broken_chain, true, false, initial, second.after, false);

    try expectRows(inactive, inactive, true, false, .{}, .{}, false);
    var noncanonical_padding = inactive;
    noncanonical_padding[layout.BEFORE_STATE_OFFSET] = QM31.one();
    try expectRows(noncanonical_padding, inactive, false, false, .{}, .{}, false);
}

test "APU AIR rejects unknown status and wave phase when accessed" {
    var status_state = apu.State{
        .enabled = true,
        .channel_status = 1,
    };
    const status_read = try apu.Transition.apply(
        status_state,
        .{ .read = apu.NR52 },
    );
    var status_row = try secureColumns(status_read);
    status_row[layout.stateStatusKnown(layout.BEFORE_STATE_OFFSET)] = QM31.zero();
    status_row[layout.stateStatusBit(layout.BEFORE_STATE_OFFSET, 0)] = QM31.zero();
    try expectRows(
        status_row,
        secureInactive(),
        true,
        false,
        status_state,
        status_read.after,
        false,
    );

    status_state.channel_status = 0;
    status_state.wave_access = .blocked;
    const wave_read = try apu.Transition.apply(
        status_state,
        .{ .read = apu.WAVE_START },
    );
    var wave_row = try secureColumns(wave_read);
    wave_row[
        layout.stateWaveMode(
            layout.BEFORE_STATE_OFFSET,
            layout.WAVE_BLOCKED,
        )
    ] = QM31.zero();
    wave_row[
        layout.stateWaveMode(
            layout.BEFORE_STATE_OFFSET,
            layout.WAVE_UNKNOWN,
        )
    ] = QM31.one();
    try expectRows(
        wave_row,
        secureInactive(),
        true,
        false,
        status_state,
        wave_read.after,
        false,
    );
}

test "APU AIR accepts empty unchanged endpoints and rejects empty mutations" {
    var endpoint = apu.State{};
    endpoint.registers[binding.registerIndex(apu.WAVE_START)] = 0x42;
    const inactive = secureInactive();
    const honest = try subject.evaluateRows(
        QM31,
        &inactive,
        &inactive,
        QM31.one(),
        QM31.zero(),
        endpoint,
        endpoint,
        0,
    );
    try std.testing.expect(honest.allZero());

    const forged_activity = try subject.evaluateRows(
        QM31,
        &inactive,
        &inactive,
        QM31.one(),
        QM31.zero(),
        endpoint,
        endpoint,
        1,
    );
    try std.testing.expect(!forged_activity.allZero());
    var changed = endpoint;
    changed.registers[binding.registerIndex(apu.WAVE_START)] ^= 1;
    try std.testing.expectError(
        error.InvalidEmptyApuAccessEndpoint,
        subject.evaluateRows(
            QM31,
            &inactive,
            &inactive,
            QM31.one(),
            QM31.zero(),
            endpoint,
            changed,
            0,
        ),
    );
}

fn expectHonest(transition: apu.Transition) !void {
    try expectRows(
        try secureColumns(transition),
        secureInactive(),
        true,
        false,
        transition.before,
        transition.after,
        true,
    );
}

fn expectRows(
    current: [layout.N_MAIN_COLUMNS]QM31,
    next: [layout.N_MAIN_COLUMNS]QM31,
    is_first: bool,
    is_last: bool,
    initial: apu.State,
    final: apu.State,
    expected: bool,
) !void {
    const evaluation = try subject.evaluateRows(
        QM31,
        &current,
        &next,
        if (is_first) QM31.one() else QM31.zero(),
        if (is_last) QM31.one() else QM31.zero(),
        initial,
        final,
        1,
    );
    try std.testing.expectEqual(expected, evaluation.allZero());
}

fn secureColumns(transition: apu.Transition) ![layout.N_MAIN_COLUMNS]QM31 {
    const base = try binding.columns(transition);
    var result: [layout.N_MAIN_COLUMNS]QM31 = undefined;
    for (&result, base) |*destination, source|
        destination.* = QM31.fromBase(source);
    return result;
}

fn secureInactive() [layout.N_MAIN_COLUMNS]QM31 {
    return [_]QM31{QM31.zero()} ** layout.N_MAIN_COLUMNS;
}

fn flip(value: QM31) QM31 {
    return if (value.isZero()) QM31.one() else QM31.zero();
}

fn isUnused(address: u16) bool {
    return address == 0xff15 or address == 0xff1f or
        (address >= 0xff27 and address <= 0xff2f);
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
