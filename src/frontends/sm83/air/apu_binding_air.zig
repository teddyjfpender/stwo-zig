//! Cubic AIR for exact CPU-visible APU register accesses.
//!
//! This proves register latches, read masks, NR52 power semantics, status
//! invalidation, and DMG wave-RAM aliasing. It does not clock oscillators,
//! generate samples, or advance the frame sequencer.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const apu = @import("../runner/apu_mmio.zig");
const binding = @import("apu_binding.zig");
const layout = binding.layout;

pub const N_CONSTRAINTS: usize = 1045;
pub const MAX_CONSTRAINT_DEGREE: u32 = 3;

pub fn Evaluation(comptime S: type) type {
    return struct {
        values: [N_CONSTRAINTS]S,

        pub fn allZero(self: @This()) bool {
            for (self.values) |value|
                if (!value.isZero()) return false;
            return true;
        }
    };
}

pub fn evaluateRows(
    comptime S: type,
    current: []const S,
    next: []const S,
    is_first: S,
    is_last: S,
    initial_state: apu.State,
    final_state: apu.State,
    event_count: usize,
) !Evaluation(S) {
    if (current.len != layout.N_MAIN_COLUMNS or
        next.len != layout.N_MAIN_COLUMNS)
        return error.InvalidMainTraceShape;
    try initial_state.validate();
    try final_state.validate();
    if (event_count == 0 and !std.meta.eql(initial_state, final_state))
        return error.InvalidEmptyApuAccessEndpoint;
    const one = S.one();
    const has_events = if (event_count == 0) S.zero() else one;
    const active = current[layout.ACTIVE_OFFSET];
    const next_active = next[layout.ACTIVE_OFFSET];
    const read_total = sum(
        S,
        current[layout.READ_ADDRESS_OFFSET..layout.WRITE_ADDRESS_OFFSET],
    );
    const write_total = sum(
        S,
        current[layout.WRITE_ADDRESS_OFFSET..layout.WRITE_VALUE_BITS_OFFSET],
    );
    const enabled = stateEnabled(current, layout.BEFORE_STATE_OFFSET);
    const status_known = stateStatusKnown(
        current,
        layout.BEFORE_STATE_OFFSET,
    );
    const wave_current = stateWaveMode(
        current,
        layout.BEFORE_STATE_OFFSET,
        layout.WAVE_CURRENT,
    );
    const wave_unknown = stateWaveMode(
        current,
        layout.BEFORE_STATE_OFFSET,
        layout.WAVE_UNKNOWN,
    );
    const power_off = current[layout.POWER_OFF_OFFSET];
    const power_on = current[layout.POWER_ON_OFFSET];
    const trigger = current[layout.TRIGGER_OFFSET];
    const wave_trigger = current[layout.WAVE_TRIGGER_OFFSET];
    const high_nonzero = current[layout.HIGH_NONZERO_OFFSET];
    const value_bit_7 = current[layout.WRITE_VALUE_BITS_OFFSET + 7];
    var out: [N_CONSTRAINTS]S = undefined;
    var at: usize = 0;

    append(S, &out, &at, active.mul(active.sub(one)));
    for (current[layout.READ_ADDRESS_OFFSET..layout.WRITE_VALUE_BITS_OFFSET]) |
        selector,
    | append(S, &out, &at, selector.mul(selector.sub(one)));
    append(S, &out, &at, read_total.add(write_total).sub(active));

    for (current[layout.WRITE_VALUE_BITS_OFFSET..layout.READ_VALUE_BITS_OFFSET]) |
        bit,
    | {
        append(S, &out, &at, bit.mul(bit.sub(one)));
        append(S, &out, &at, bit.mul(one.sub(write_total)));
    }
    for (current[layout.READ_VALUE_BITS_OFFSET..layout.WAVE_READ_TARGET_OFFSET]) |
        bit,
    | {
        append(S, &out, &at, bit.mul(bit.sub(one)));
        append(S, &out, &at, bit.mul(one.sub(read_total)));
    }

    const wave_read = sum(
        S,
        current[layout.READ_ADDRESS_OFFSET + 32 .. layout.READ_ADDRESS_OFFSET + 48],
    );
    const wave_write = sum(
        S,
        current[layout.WRITE_ADDRESS_OFFSET + 32 .. layout.WRITE_ADDRESS_OFFSET + 48],
    );
    append(
        S,
        &out,
        &at,
        sum(S, current[layout.WAVE_READ_TARGET_OFFSET..layout.WAVE_WRITE_TARGET_OFFSET])
            .sub(wave_current.mul(wave_read)),
    );
    append(
        S,
        &out,
        &at,
        sum(S, current[layout.WAVE_WRITE_TARGET_OFFSET..layout.POWER_OFF_OFFSET])
            .sub(wave_current.mul(wave_write)),
    );
    for (0..layout.WAVE_BYTES) |target| {
        const read_target = current[layout.WAVE_READ_TARGET_OFFSET + target];
        const write_target = current[layout.WAVE_WRITE_TARGET_OFFSET + target];
        for (0..4) |bit| {
            const expected = constant(S, target >> @intCast(bit) & 1);
            const actual = stateWaveCurrentBit(
                current,
                layout.BEFORE_STATE_OFFSET,
                bit,
            );
            append(S, &out, &at, read_target.mul(actual.sub(expected)));
            append(S, &out, &at, write_target.mul(actual.sub(expected)));
        }
    }

    const write_power = writeSelector(current, binding.registerIndex(apu.NR52));
    append(
        S,
        &out,
        &at,
        power_off.sub(
            write_power.mul(enabled).mul(one.sub(value_bit_7)),
        ),
    );
    append(
        S,
        &out,
        &at,
        power_on.sub(
            write_power.mul(one.sub(enabled)).mul(value_bit_7),
        ),
    );
    var trigger_writes = S.zero();
    inline for (.{ 0xff14, 0xff19, apu.NR34, 0xff23 }) |address|
        trigger_writes = trigger_writes.add(
            writeSelector(current, binding.registerIndex(address)),
        );
    append(
        S,
        &out,
        &at,
        trigger.sub(trigger_writes.mul(enabled).mul(value_bit_7)),
    );
    append(
        S,
        &out,
        &at,
        wave_trigger.sub(
            writeSelector(current, binding.registerIndex(apu.NR34))
                .mul(enabled).mul(value_bit_7),
        ),
    );
    appendDacConstraints(S, current, enabled, high_nonzero, &out, &at);

    const high_sum = sum(
        S,
        current[layout.WRITE_VALUE_BITS_OFFSET + 3 .. layout.WRITE_VALUE_BITS_OFFSET + 8],
    );
    const high_inverse = current[layout.HIGH_INVERSE_OFFSET];
    append(S, &out, &at, high_nonzero.mul(high_nonzero.sub(one)));
    append(
        S,
        &out,
        &at,
        high_sum.mul(high_inverse).sub(high_nonzero),
    );
    append(S, &out, &at, high_sum.mul(one.sub(high_nonzero)));
    append(S, &out, &at, high_inverse.mul(one.sub(high_nonzero)));

    appendStateValidity(S, current, active, &out, &at);
    append(S, &out, &at, wave_read.add(wave_write).mul(wave_unknown));
    append(
        S,
        &out,
        &at,
        readSelector(current, binding.registerIndex(apu.NR52))
            .mul(one.sub(status_known)),
    );
    var unsupported_writes = S.zero();
    for (0..layout.REGISTER_COUNT) |register| {
        if (binding.isUnused(register)) {
            unsupported_writes = unsupported_writes.add(
                writeSelector(current, register),
            );
        }
    }
    append(S, &out, &at, unsupported_writes);

    appendReadConstraints(S, current, &out, &at);
    appendRegisterTransitions(S, current, &out, &at);
    appendMetadataTransitions(S, current, &out, &at);

    append(S, &out, &at, is_first.mul(active.sub(has_events)));
    for (0..layout.N_STATE_COLUMNS) |column|
        append(
            S,
            &out,
            &at,
            is_first.mul(has_events).mul(
                current[layout.BEFORE_STATE_OFFSET + column].sub(
                    publicStateValue(S, initial_state, column),
                ),
            ),
        );
    const not_last = one.sub(is_last);
    append(
        S,
        &out,
        &at,
        not_last.mul(next_active).mul(one.sub(active)),
    );
    const chain = not_last.mul(next_active);
    for (0..layout.N_STATE_COLUMNS) |column|
        append(
            S,
            &out,
            &at,
            chain.mul(
                current[layout.AFTER_STATE_OFFSET + column].sub(
                    next[layout.BEFORE_STATE_OFFSET + column],
                ),
            ),
        );
    const ends = is_last.mul(active).add(
        not_last.mul(active.sub(next_active)),
    );
    for (0..layout.N_STATE_COLUMNS) |column|
        append(
            S,
            &out,
            &at,
            ends.mul(
                current[layout.AFTER_STATE_OFFSET + column].sub(
                    publicStateValue(S, final_state, column),
                ),
            ),
        );

    std.debug.assert(at == out.len);
    return .{ .values = out };
}

fn appendStateValidity(
    comptime S: type,
    row: []const S,
    active: S,
    out: *[N_CONSTRAINTS]S,
    at: *usize,
) void {
    const one = S.one();
    for (0..layout.REGISTER_COUNT) |register| {
        const value = stateRegister(row, layout.BEFORE_STATE_OFFSET, register);
        var reconstructed = S.zero();
        for (0..8) |bit| {
            const item = beforeRegisterBit(row, register, bit);
            reconstructed = reconstructed.add(item.mul(constant(S, @as(u32, 1) << @intCast(bit))));
        }
        append(S, out, at, value.sub(reconstructed));
        append(S, out, at, value.mul(one.sub(active)));
    }
    for (0..layout.REGISTER_COUNT) |register|
        for (0..8) |bit| {
            const item = beforeRegisterBit(row, register, bit);
            append(S, out, at, item.mul(item.sub(one)));
        };

    const enabled = stateEnabled(row, layout.BEFORE_STATE_OFFSET);
    const known = stateStatusKnown(row, layout.BEFORE_STATE_OFFSET);
    append(S, out, at, enabled.mul(enabled.sub(one)));
    append(S, out, at, enabled.mul(one.sub(active)));
    append(S, out, at, known.mul(known.sub(one)));
    append(S, out, at, known.mul(one.sub(active)));
    for (0..4) |bit| {
        const status = stateStatusBit(row, layout.BEFORE_STATE_OFFSET, bit);
        append(S, out, at, status.mul(status.sub(one)));
        append(S, out, at, status.mul(one.sub(known)));
    }
    var mode_sum = S.zero();
    for (0..4) |mode| {
        const item = stateWaveMode(row, layout.BEFORE_STATE_OFFSET, mode);
        append(S, out, at, item.mul(item.sub(one)));
        mode_sum = mode_sum.add(item);
    }
    append(S, out, at, mode_sum.sub(active));
    const current_mode = stateWaveMode(
        row,
        layout.BEFORE_STATE_OFFSET,
        layout.WAVE_CURRENT,
    );
    for (0..4) |bit| {
        const item = stateWaveCurrentBit(
            row,
            layout.BEFORE_STATE_OFFSET,
            bit,
        );
        append(S, out, at, item.mul(item.sub(one)));
        append(S, out, at, item.mul(one.sub(current_mode)));
    }
    const disabled = active.sub(enabled);
    append(S, out, at, disabled.mul(one.sub(known)));
    for (0..4) |bit|
        append(
            S,
            out,
            at,
            disabled.mul(stateStatusBit(row, layout.BEFORE_STATE_OFFSET, bit)),
        );
    append(
        S,
        out,
        at,
        disabled.mul(
            one.sub(stateWaveMode(
                row,
                layout.BEFORE_STATE_OFFSET,
                layout.WAVE_INACTIVE,
            )),
        ),
    );
    append(
        S,
        out,
        at,
        stateRegister(
            row,
            layout.BEFORE_STATE_OFFSET,
            binding.registerIndex(apu.NR52),
        ),
    );
}

fn appendDacConstraints(
    comptime S: type,
    row: []const S,
    enabled: S,
    high_nonzero: S,
    out: *[N_CONSTRAINTS]S,
    at: *usize,
) void {
    const one = S.one();
    const value_bit_7 = row[layout.WRITE_VALUE_BITS_OFFSET + 7];
    const addresses = [_]u16{ 0xff12, 0xff17, 0xff1a, 0xff21 };
    for (addresses, 0..) |address, channel| {
        const zero_test = if (channel == 2)
            one.sub(value_bit_7)
        else
            one.sub(high_nonzero);
        append(
            S,
            out,
            at,
            row[layout.DAC_DISABLE_OFFSET + channel].sub(
                writeSelector(row, binding.registerIndex(address))
                    .mul(enabled).mul(zero_test),
            ),
        );
    }
}

fn appendReadConstraints(
    comptime S: type,
    row: []const S,
    out: *[N_CONSTRAINTS]S,
    at: *usize,
) void {
    const enabled = stateEnabled(row, layout.BEFORE_STATE_OFFSET);
    for (0..8) |bit| {
        var expected = S.zero();
        for (0..32) |register| {
            const selector = readSelector(row, register);
            if (binding.isUnused(register)) {
                expected = expected.add(selector);
            } else if (register == binding.registerIndex(apu.NR52)) {
                const value = if (bit < 4)
                    stateStatusBit(row, layout.BEFORE_STATE_OFFSET, bit)
                else if (bit < 7)
                    S.one()
                else
                    enabled;
                expected = expected.add(selector.mul(value));
            } else if (binding.READ_MASKS[register] >> @intCast(bit) & 1 != 0) {
                expected = expected.add(selector);
            } else {
                expected = expected.add(
                    selector.mul(beforeRegisterBit(row, register, bit)),
                );
            }
        }
        const wave_inactive = stateWaveMode(
            row,
            layout.BEFORE_STATE_OFFSET,
            layout.WAVE_INACTIVE,
        );
        const wave_blocked = stateWaveMode(
            row,
            layout.BEFORE_STATE_OFFSET,
            layout.WAVE_BLOCKED,
        );
        for (0..layout.WAVE_BYTES) |wave| {
            const register = 32 + wave;
            expected = expected.add(
                readSelector(row, register).mul(wave_inactive).mul(
                    beforeRegisterBit(row, register, bit),
                ),
            );
            expected = expected.add(readSelector(row, register).mul(wave_blocked));
            expected = expected.add(
                row[layout.WAVE_READ_TARGET_OFFSET + wave].mul(
                    beforeRegisterBit(row, register, bit),
                ),
            );
        }
        append(
            S,
            out,
            at,
            row[layout.READ_VALUE_BITS_OFFSET + bit].sub(expected),
        );
    }
}

fn appendRegisterTransitions(
    comptime S: type,
    row: []const S,
    out: *[N_CONSTRAINTS]S,
    at: *usize,
) void {
    const one = S.one();
    const enabled = stateEnabled(row, layout.BEFORE_STATE_OFFSET);
    const wave_inactive = stateWaveMode(
        row,
        layout.BEFORE_STATE_OFFSET,
        layout.WAVE_INACTIVE,
    );
    const power_off = row[layout.POWER_OFF_OFFSET];
    const write_value = bitsValue(
        S,
        row[layout.WRITE_VALUE_BITS_OFFSET..layout.READ_VALUE_BITS_OFFSET],
    );
    for (0..layout.REGISTER_COUNT) |register| {
        const before = stateRegister(row, layout.BEFORE_STATE_OFFSET, register);
        const after = stateRegister(row, layout.AFTER_STATE_OFFSET, register);
        var delta = S.zero();
        if (register < 32) {
            delta = delta.add(power_off.mul(before.neg()));
            if (!binding.isUnused(register) and
                register != binding.registerIndex(apu.NR52))
            {
                const selected = writeSelector(row, register);
                delta = delta.add(
                    selected.mul(enabled).mul(write_value.sub(before)),
                );
                if (binding.isWritableWhileOff(register)) {
                    const off_value = if ((register == binding.registerIndex(apu.NR11) or
                        register == binding.registerIndex(apu.NR21)))
                        bitsValue(
                            S,
                            row[layout.WRITE_VALUE_BITS_OFFSET .. layout.WRITE_VALUE_BITS_OFFSET + 6],
                        )
                    else
                        write_value;
                    delta = delta.add(
                        selected.mul(one.sub(enabled)).mul(off_value.sub(before)),
                    );
                }
            }
        } else {
            delta = delta.add(
                writeSelector(row, register).mul(wave_inactive).mul(
                    write_value.sub(before),
                ),
            );
            delta = delta.add(
                row[layout.WAVE_WRITE_TARGET_OFFSET + register - 32]
                    .mul(write_value.sub(before)),
            );
        }
        append(S, out, at, after.sub(before).sub(delta));
    }
}

fn appendMetadataTransitions(
    comptime S: type,
    row: []const S,
    out: *[N_CONSTRAINTS]S,
    at: *usize,
) void {
    const one = S.one();
    const before_offset = layout.BEFORE_STATE_OFFSET;
    const after_offset = layout.AFTER_STATE_OFFSET;
    const enabled = stateEnabled(row, before_offset);
    const write_power = writeSelector(row, binding.registerIndex(apu.NR52));
    const value_bit_7 = row[layout.WRITE_VALUE_BITS_OFFSET + 7];
    append(
        S,
        out,
        at,
        stateEnabled(row, after_offset).sub(enabled).sub(
            write_power.mul(value_bit_7.sub(enabled)),
        ),
    );
    const reset = row[layout.POWER_OFF_OFFSET].add(row[layout.POWER_ON_OFFSET]);
    const trigger = row[layout.TRIGGER_OFFSET];
    const before_known = stateStatusKnown(row, before_offset);
    append(
        S,
        out,
        at,
        stateStatusKnown(row, after_offset).sub(before_known)
            .sub(reset.mul(one.sub(before_known)))
            .add(trigger.mul(before_known)),
    );
    for (0..4) |bit| {
        const before = stateStatusBit(row, before_offset, bit);
        const after = stateStatusBit(row, after_offset, bit);
        const clears = reset.add(trigger).add(row[layout.DAC_DISABLE_OFFSET + bit]);
        append(S, out, at, after.sub(before).add(clears.mul(before)));
    }
    const reset_inactive = reset.add(row[layout.DAC_DISABLE_OFFSET + 2]);
    const wave_trigger = row[layout.WAVE_TRIGGER_OFFSET];
    for (0..4) |mode| {
        const before = stateWaveMode(row, before_offset, mode);
        const after = stateWaveMode(row, after_offset, mode);
        const inactive_target = constant(S, @intFromBool(mode == layout.WAVE_INACTIVE));
        const unknown_target = constant(S, @intFromBool(mode == layout.WAVE_UNKNOWN));
        append(
            S,
            out,
            at,
            after.sub(before)
                .sub(reset_inactive.mul(inactive_target.sub(before)))
                .sub(wave_trigger.mul(unknown_target.sub(before))),
        );
    }
    const wave_reset = reset_inactive.add(wave_trigger);
    for (0..4) |bit| {
        const before = stateWaveCurrentBit(row, before_offset, bit);
        const after = stateWaveCurrentBit(row, after_offset, bit);
        append(S, out, at, after.sub(before).add(wave_reset.mul(before)));
    }
}

fn stateRegister(row: anytype, offset: usize, register: usize) @TypeOf(row[0]) {
    return row[layout.stateRegister(offset, register)];
}

fn stateEnabled(row: anytype, offset: usize) @TypeOf(row[0]) {
    return row[layout.stateEnabled(offset)];
}

fn stateStatusKnown(row: anytype, offset: usize) @TypeOf(row[0]) {
    return row[layout.stateStatusKnown(offset)];
}

fn stateStatusBit(row: anytype, offset: usize, bit: usize) @TypeOf(row[0]) {
    return row[layout.stateStatusBit(offset, bit)];
}

fn stateWaveMode(row: anytype, offset: usize, mode: usize) @TypeOf(row[0]) {
    return row[layout.stateWaveMode(offset, mode)];
}

fn stateWaveCurrentBit(row: anytype, offset: usize, bit: usize) @TypeOf(row[0]) {
    return row[layout.stateWaveCurrentBit(offset, bit)];
}

fn beforeRegisterBit(row: anytype, register: usize, bit: usize) @TypeOf(row[0]) {
    return row[layout.beforeRegisterBit(register, bit)];
}

fn readSelector(row: anytype, register: usize) @TypeOf(row[0]) {
    return row[layout.READ_ADDRESS_OFFSET + register];
}

fn writeSelector(row: anytype, register: usize) @TypeOf(row[0]) {
    return row[layout.WRITE_ADDRESS_OFFSET + register];
}

fn sum(comptime S: type, values: []const S) S {
    var result = S.zero();
    for (values) |value| result = result.add(value);
    return result;
}

fn bitsValue(comptime S: type, bits: []const S) S {
    var result = S.zero();
    for (bits, 0..) |bit, index|
        result = result.add(bit.mul(constant(S, @as(u32, 1) << @intCast(index))));
    return result;
}

fn publicStateValue(comptime S: type, state: apu.State, column: usize) S {
    if (column < layout.REGISTER_COUNT)
        return constant(S, state.registers[column]);
    if (column == layout.STATE_ENABLED_OFFSET)
        return constant(S, @intFromBool(state.enabled));
    if (column == layout.STATE_STATUS_KNOWN_OFFSET)
        return constant(S, @intFromBool(state.channel_status != null));
    if (column < layout.STATE_WAVE_MODE_OFFSET) {
        const bit = column - layout.STATE_STATUS_BITS_OFFSET;
        const status = state.channel_status orelse 0;
        return constant(S, status >> @intCast(bit) & 1);
    }
    if (column < layout.STATE_WAVE_CURRENT_BITS_OFFSET) {
        const mode = column - layout.STATE_WAVE_MODE_OFFSET;
        const expected: usize = switch (state.wave_access) {
            .inactive => layout.WAVE_INACTIVE,
            .blocked => layout.WAVE_BLOCKED,
            .current_byte => layout.WAVE_CURRENT,
            .unknown => layout.WAVE_UNKNOWN,
        };
        return constant(S, @intFromBool(mode == expected));
    }
    const bit = column - layout.STATE_WAVE_CURRENT_BITS_OFFSET;
    const current = switch (state.wave_access) {
        .current_byte => |value| value,
        else => 0,
    };
    return constant(S, current >> @intCast(bit) & 1);
}

fn append(
    comptime S: type,
    out: *[N_CONSTRAINTS]S,
    at: *usize,
    value: S,
) void {
    out[at.*] = value;
    at.* += 1;
}

fn constant(comptime S: type, value: anytype) S {
    return S.fromBase(M31.fromCanonical(@intCast(value)));
}
