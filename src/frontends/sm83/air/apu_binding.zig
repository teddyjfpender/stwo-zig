//! Detached CPU-visible DMG-B APU access trace and witness.
//!
//! There is exactly one active row per supplied FF10-FF3F CPU access. An empty
//! segment has a 16-row inactive witness and an unchanged public endpoint. The
//! execution lookup proves that the supplied list is complete.
//! This leaf deliberately models no sample generation, oscillator ticks, or
//! frame-sequencer ticks; runner states that need an uncommitted live phase
//! already fail closed.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const air_utils = @import("stwo_core").air.utils;
const apu = @import("../runner/apu_mmio.zig");
pub const layout = @import("apu_binding_layout.zig");

pub const READ_MASKS = [_]u8{
    0x80, 0x3f, 0x00, 0xff, 0xbf, 0xff, 0x3f, 0x00,
    0xff, 0xbf, 0x7f, 0xff, 0x9f, 0xff, 0xbf, 0xff,
    0xff, 0x00, 0x00, 0xbf, 0x00, 0x00, 0x70, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,
};

pub const Trace = struct {
    rows: []apu.Transition,
    initial_state: apu.State,
    final_state: apu.State,

    pub fn deinit(self: *Trace, allocator: std.mem.Allocator) void {
        allocator.free(self.rows);
        self.* = undefined;
    }
};

pub const Witness = struct {
    log_size: u32,
    event_count: usize,
    main: [layout.N_MAIN_COLUMNS][]M31,
    allocator: std.mem.Allocator,
    owned: bool = true,

    pub fn disown(self: *Witness) void {
        self.owned = false;
    }

    pub fn deinit(self: *Witness) void {
        if (self.owned)
            for (self.main) |column| self.allocator.free(column);
        self.* = undefined;
    }
};

pub fn generateTrace(
    allocator: std.mem.Allocator,
    initial_state: apu.State,
    events: []const apu.Event,
) !Trace {
    try initial_state.validate();
    const rows = try allocator.alloc(apu.Transition, events.len);
    errdefer allocator.free(rows);
    var state = initial_state;
    for (events, rows) |event, *row| {
        row.* = try apu.Transition.apply(state, event);
        state = row.after;
    }
    return .{
        .rows = rows,
        .initial_state = initial_state,
        .final_state = state,
    };
}

pub fn generateWitness(
    allocator: std.mem.Allocator,
    trace: Trace,
) !Witness {
    try validateTrace(trace);
    const padded = std.math.ceilPowerOfTwo(
        usize,
        @max(trace.rows.len, 16),
    ) catch return error.ApuAccessTraceTooLong;
    const log_size: u32 = @intCast(std.math.log2_int(usize, padded));
    var result = Witness{
        .log_size = log_size,
        .event_count = trace.rows.len,
        .main = undefined,
        .allocator = allocator,
    };
    var initialized: usize = 0;
    errdefer for (result.main[0..initialized]) |column|
        allocator.free(column);
    for (&result.main) |*column| {
        column.* = try allocator.alloc(M31, padded);
        @memset(column.*, M31.zero());
        initialized += 1;
    }
    for (trace.rows, 0..) |transition, row| {
        const values = try columns(transition);
        const storage = try air_utils.circleBitReversedIndex(log_size, row);
        for (&result.main, values) |column, value|
            column[storage] = value;
    }
    return result;
}

pub fn validateTrace(trace: Trace) !void {
    try trace.initial_state.validate();
    try trace.final_state.validate();
    if (trace.rows.len == 0) {
        if (!std.meta.eql(trace.initial_state, trace.final_state))
            return error.InvalidEmptyApuAccessEndpoint;
        return;
    }
    if (!std.meta.eql(trace.rows[0].before, trace.initial_state) or
        !std.meta.eql(trace.rows[trace.rows.len - 1].after, trace.final_state))
        return error.InvalidApuAccessEndpoint;
    for (trace.rows, 0..) |transition, row| {
        try transition.validate();
        if (row != 0 and !std.meta.eql(
            trace.rows[row - 1].after,
            transition.before,
        )) return error.DisconnectedApuAccessTrace;
    }
}

pub fn columns(transition: apu.Transition) ![layout.N_MAIN_COLUMNS]M31 {
    try transition.validate();
    var out = inactiveColumns();
    out[layout.ACTIVE_OFFSET] = M31.one();
    const address = switch (transition.event) {
        .read => |value| value,
        .write => |access| access.address,
    };
    if (!apu.isAddress(address)) return error.UnsupportedApuAddress;
    const register = registerIndex(address);
    switch (transition.event) {
        .read => {
            out[layout.READ_ADDRESS_OFFSET + register] = M31.one();
            writeBits(
                out[layout.READ_VALUE_BITS_OFFSET..][0..8],
                transition.read_value orelse return error.MissingApuReadValue,
            );
        },
        .write => |access| {
            if (transition.read_value != null)
                return error.UnexpectedApuReadValue;
            out[layout.WRITE_ADDRESS_OFFSET + register] = M31.one();
            writeBits(
                out[layout.WRITE_VALUE_BITS_OFFSET..][0..8],
                access.value,
            );
            const high_count: u32 = @popCount(access.value >> 3);
            if (high_count != 0) {
                out[layout.HIGH_NONZERO_OFFSET] = M31.one();
                out[layout.HIGH_INVERSE_OFFSET] =
                    try M31.fromCanonical(high_count).inv();
            }
            encodeFlags(&out, transition.before, register, access.value);
        },
    }
    encodeWaveTarget(&out, transition.before, register, transition.event);
    encodeState(&out, layout.BEFORE_STATE_OFFSET, transition.before);
    encodeRegisterBits(&out, transition.before);
    encodeState(&out, layout.AFTER_STATE_OFFSET, transition.after);
    return out;
}

pub fn inactiveColumns() [layout.N_MAIN_COLUMNS]M31 {
    return [_]M31{M31.zero()} ** layout.N_MAIN_COLUMNS;
}

fn encodeFlags(
    out: *[layout.N_MAIN_COLUMNS]M31,
    before: apu.State,
    register: usize,
    value: u8,
) void {
    const bit7 = value & 0x80 != 0;
    if (register == registerIndex(apu.NR52)) {
        if (before.enabled and !bit7)
            out[layout.POWER_OFF_OFFSET] = M31.one();
        if (!before.enabled and bit7)
            out[layout.POWER_ON_OFFSET] = M31.one();
    }
    if (before.enabled and bit7 and isTrigger(register)) {
        out[layout.TRIGGER_OFFSET] = M31.one();
        if (register == registerIndex(apu.NR34))
            out[layout.WAVE_TRIGGER_OFFSET] = M31.one();
    }
    if (!before.enabled) return;
    if (register == registerIndex(0xff12) and value & 0xf8 == 0)
        out[layout.DAC_DISABLE_OFFSET] = M31.one();
    if (register == registerIndex(0xff17) and value & 0xf8 == 0)
        out[layout.DAC_DISABLE_OFFSET + 1] = M31.one();
    if (register == registerIndex(0xff1a) and !bit7)
        out[layout.DAC_DISABLE_OFFSET + 2] = M31.one();
    if (register == registerIndex(0xff21) and value & 0xf8 == 0)
        out[layout.DAC_DISABLE_OFFSET + 3] = M31.one();
}

fn encodeWaveTarget(
    out: *[layout.N_MAIN_COLUMNS]M31,
    before: apu.State,
    register: usize,
    event: apu.Event,
) void {
    if (register < registerIndex(apu.WAVE_START)) return;
    const byte = switch (before.wave_access) {
        .current_byte => |value| value,
        else => return,
    };
    switch (event) {
        .read => out[layout.WAVE_READ_TARGET_OFFSET + byte] = M31.one(),
        .write => out[layout.WAVE_WRITE_TARGET_OFFSET + byte] = M31.one(),
    }
}

fn encodeState(
    out: *[layout.N_MAIN_COLUMNS]M31,
    offset: usize,
    state: apu.State,
) void {
    for (state.registers, 0..) |value, register|
        out[layout.stateRegister(offset, register)] = M31.fromCanonical(value);
    out[layout.stateEnabled(offset)] = boolField(state.enabled);
    if (state.channel_status) |status| {
        out[layout.stateStatusKnown(offset)] = M31.one();
        writeBits(out[layout.stateStatusBit(offset, 0)..][0..4], status);
    }
    const mode: usize = switch (state.wave_access) {
        .inactive => layout.WAVE_INACTIVE,
        .blocked => layout.WAVE_BLOCKED,
        .current_byte => layout.WAVE_CURRENT,
        .unknown => layout.WAVE_UNKNOWN,
    };
    out[layout.stateWaveMode(offset, mode)] = M31.one();
    if (state.wave_access == .current_byte)
        writeBits(
            out[layout.stateWaveCurrentBit(offset, 0)..][0..4],
            state.wave_access.current_byte,
        );
}

fn encodeRegisterBits(
    out: *[layout.N_MAIN_COLUMNS]M31,
    state: apu.State,
) void {
    for (state.registers, 0..) |value, register|
        writeBits(
            out[layout.beforeRegisterBit(register, 0)..][0..8],
            value,
        );
}

fn writeBits(out: []M31, value: anytype) void {
    for (out, 0..) |*destination, bit|
        destination.* = boolField(value >> @intCast(bit) & 1 != 0);
}

fn boolField(value: bool) M31 {
    return if (value) M31.one() else M31.zero();
}

pub fn registerIndex(address: u16) usize {
    std.debug.assert(apu.isAddress(address));
    return address - apu.FIRST_ADDRESS;
}

pub fn isWave(register: usize) bool {
    return register >= registerIndex(apu.WAVE_START);
}

pub fn isUnused(register: usize) bool {
    return register == registerIndex(0xff15) or
        register == registerIndex(0xff1f) or
        (register >= registerIndex(0xff27) and
            register <= registerIndex(0xff2f));
}

pub fn isWritableWhileOff(register: usize) bool {
    return register == registerIndex(apu.NR11) or
        register == registerIndex(apu.NR21) or
        register == registerIndex(apu.NR31) or
        register == registerIndex(apu.NR41);
}

pub fn isTrigger(register: usize) bool {
    return register == registerIndex(0xff14) or
        register == registerIndex(0xff19) or
        register == registerIndex(apu.NR34) or
        register == registerIndex(0xff23);
}
