//! Exact CPU-visible DMG-B APU register overlay, without sample generation.
//!
//! Oracle: pinned SameBoy `213a12ce93d66b105a113debd9396306066a7cfc`,
//! `Core/apu.c:1100-1140,1682-1740` and `Core/memory.c:741-744,1768-1772`.
//! The overlay owns only latch/read-mask/power behavior. It deliberately does
//! not invent oscillator or frame-sequencer state: NR52 and wave RAM accesses
//! that need an unprovided live channel phase fail closed.

const std = @import("std");

pub const FIRST_ADDRESS: u16 = 0xff10;
pub const LAST_ADDRESS: u16 = 0xff3f;
pub const NR10: u16 = 0xff10;
pub const NR11: u16 = 0xff11;
pub const NR21: u16 = 0xff16;
pub const NR31: u16 = 0xff1b;
pub const NR41: u16 = 0xff20;
pub const NR52: u16 = 0xff26;
pub const NR34: u16 = 0xff1e;
pub const WAVE_START: u16 = 0xff30;
pub const WAVE_END: u16 = 0xff3f;
pub const REGISTER_COUNT: usize = LAST_ADDRESS - FIRST_ADDRESS + 1;
pub const SAMEBOY_NATIVE_SIZE: usize = 104;

const READ_MASKS = [_]u8{
    0x80, 0x3f, 0x00, 0xff, 0xbf, 0xff, 0x3f, 0x00,
    0xff, 0xbf, 0x7f, 0xff, 0x9f, 0xff, 0xbf, 0xff,
    0xff, 0x00, 0x00, 0xbf, 0x00, 0x00, 0x70, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,
};

pub const WaveAccess = union(enum) {
    /// Channel 3 is inactive, so FF30-FF3F access its addressed byte.
    inactive,
    /// Active DMG channel outside its narrow readable window: reads return
    /// FF and writes are ignored.
    blocked,
    /// Active channel at a known sample byte; all wave accesses alias it.
    current_byte: u4,
    /// The native checkpoint did not project the phase. Do not guess.
    unknown,
};

pub const Access = struct {
    address: u16,
    value: u8,
};

pub const Event = union(enum) {
    read: u16,
    write: Access,
};

pub const Error = error{
    UnsupportedAddress,
    UnsupportedWrite,
    UnknownChannelStatus,
    UnknownWavePhase,
    InvalidState,
    InvalidTransition,
};

/// Checkpoint state for the CPU-visible portion of SameBoy's DMG APU.
///
/// `channel_status` is the live low nibble of NR52, if a complete APU clock
/// supplied it. `null` is intentional: a register-only model cannot keep it
/// exact after a trigger, so a later NR52 read is rejected rather than stale.
pub const State = struct {
    registers: [REGISTER_COUNT]u8 = [_]u8{0} ** REGISTER_COUNT,
    enabled: bool = false,
    channel_status: ?u4 = 0,
    wave_access: WaveAccess = .inactive,

    pub fn restore(checkpoint: State) Error!State {
        try checkpoint.validate();
        return checkpoint;
    }

    pub fn validate(self: State) Error!void {
        if (self.registers[index(NR52)] != 0)
            return error.InvalidState;
        if (!self.enabled and (self.channel_status == null or
            self.channel_status.? != 0 or
            !std.meta.eql(self.wave_access, WaveAccess.inactive)))
            return error.InvalidState;
    }

    /// Projects raw SameBoy IO latches. The native APU section must provide
    /// `enabled`, status, and `wave_access`: IO alone cannot do so.
    pub fn fromIo(
        io: []const u8,
        enabled: bool,
        channel_status: ?u4,
        wave_access: WaveAccess,
    ) Error!State {
        if (io.len < 0x40) return error.InvalidState;
        var result = State{
            .enabled = enabled,
            .channel_status = channel_status,
            .wave_access = wave_access,
        };
        @memcpy(&result.registers, io[0x10..0x40]);
        result.registers[index(NR52)] = 0;
        try result.validate();
        return result;
    }

    /// Projects the CPU-visible fields from SameBoy native-state v15's APU
    /// section. The section is eight-byte padded (104 bytes); its live APU
    /// object ends at byte 102. Boolean fields are checked instead of treated
    /// as arbitrary truthy bytes.
    pub fn fromSameBoyNative(
        io: []const u8,
        native: []const u8,
    ) Error!State {
        if (native.len != SAMEBOY_NATIVE_SIZE) return error.InvalidState;
        const enabled = try nativeBool(native, 0);
        var status: u4 = 0;
        for (0..4) |channel| {
            if (try nativeBool(native, 8 + channel))
                status |= @as(u4, 1) << @intCast(channel);
        }
        const wave_active = try nativeBool(native, 10);
        const wave_just_read = try nativeBool(native, 70);
        const wave_access: WaveAccess = if (!wave_active)
            .inactive
        else if (!wave_just_read)
            .blocked
        else
            .{ .current_byte = @truncate(native[68] >> 1) };
        return fromIo(io, enabled, status, wave_access);
    }

    pub fn read(self: State, address: u16) Error!u8 {
        if (!isAddress(address)) return error.UnsupportedAddress;
        if (address == NR52) {
            const status = self.channel_status orelse
                return error.UnknownChannelStatus;
            return 0x70 | (@as(u8, @intFromBool(self.enabled)) << 7) |
                @as(u8, status);
        }
        if (isUnused(address)) return 0xff;
        if (isWave(address)) return self.readWave(address);
        if (!isReadableLatch(address)) return error.UnsupportedAddress;
        return self.registers[index(address)] | READ_MASKS[index(address)];
    }

    pub fn write(self: *State, address: u16, value: u8) Error!void {
        if (!isAddress(address)) return error.UnsupportedAddress;
        if (address == NR52) return self.writePower(value);
        if (isUnused(address)) return error.UnsupportedWrite;
        if (isWave(address)) return self.writeWave(address, value);
        if (!self.enabled) {
            if (!isWritableWhileOff(address)) return;
            self.registers[index(address)] = if (address == NR11 or
                address == NR21) value & 0x3f else value;
            return;
        }
        self.registers[index(address)] = value;
        if (isTrigger(address, value)) {
            self.channel_status = null;
            if (address == NR34) self.wave_access = .unknown;
        }
        if (isDacDisable(address, value)) self.clearKnownChannel(address);
    }

    /// The full APU timing owner may refresh these only from a committed
    /// native/trace state. This method cannot make an uncertain state precise.
    pub fn setLiveChannelState(
        self: *State,
        status: u4,
        wave_access: WaveAccess,
    ) void {
        self.channel_status = status;
        self.wave_access = wave_access;
    }

    fn writePower(self: *State, value: u8) void {
        const next_enabled = value & 0x80 != 0;
        if (self.enabled and !next_enabled) {
            @memset(self.registers[index(NR10)..index(WAVE_START)], 0);
            self.channel_status = 0;
            self.wave_access = .inactive;
        } else if (!self.enabled and next_enabled) {
            self.channel_status = 0;
            self.wave_access = .inactive;
        }
        self.enabled = next_enabled;
    }

    fn readWave(self: State, address: u16) Error!u8 {
        const target = switch (self.wave_access) {
            .inactive => address,
            .blocked => return 0xff,
            .current_byte => |byte| WAVE_START + byte,
            .unknown => return error.UnknownWavePhase,
        };
        return self.registers[index(target)];
    }

    fn writeWave(self: *State, address: u16, value: u8) Error!void {
        const target = switch (self.wave_access) {
            .inactive => address,
            .blocked => return,
            .current_byte => |byte| WAVE_START + byte,
            .unknown => return error.UnknownWavePhase,
        };
        self.registers[index(target)] = value;
    }

    fn clearKnownChannel(self: *State, address: u16) void {
        const bit: u2 = switch (address) {
            0xff12 => 0,
            0xff17 => 1,
            0xff1a => 2,
            0xff21 => 3,
            else => return,
        };
        if (self.channel_status) |status|
            self.channel_status = status & ~(@as(u4, 1) << bit);
        if (address == 0xff1a) self.wave_access = .inactive;
    }
};

pub const Transition = struct {
    before: State,
    after: State,
    event: Event,
    read_value: ?u8,

    pub fn apply(before: State, event: Event) Error!Transition {
        try before.validate();
        var after = before;
        const read_value = switch (event) {
            .read => |address| try after.read(address),
            .write => |access| write: {
                try after.write(access.address, access.value);
                break :write null;
            },
        };
        try after.validate();
        return .{
            .before = before,
            .after = after,
            .event = event,
            .read_value = read_value,
        };
    }

    pub fn validate(self: Transition) Error!void {
        const expected = Transition.apply(self.before, self.event) catch
            return error.InvalidTransition;
        if (!std.meta.eql(expected, self)) return error.InvalidTransition;
    }
};

pub fn isAddress(address: u16) bool {
    return address >= FIRST_ADDRESS and address <= LAST_ADDRESS;
}

fn index(address: u16) usize {
    std.debug.assert(isAddress(address));
    return address - FIRST_ADDRESS;
}

fn isWave(address: u16) bool {
    return address >= WAVE_START and address <= WAVE_END;
}

fn isUnused(address: u16) bool {
    return address == 0xff15 or address == 0xff1f or
        (address >= 0xff27 and address <= 0xff2f);
}

fn isReadableLatch(address: u16) bool {
    return address != NR52 and !isUnused(address) and !isWave(address);
}

fn isWritableWhileOff(address: u16) bool {
    return address == NR11 or address == NR21 or address == NR31 or
        address == NR41;
}

fn isTrigger(address: u16, value: u8) bool {
    return value & 0x80 != 0 and switch (address) {
        0xff14, 0xff19, NR34, 0xff23 => true,
        else => false,
    };
}

fn isDacDisable(address: u16, value: u8) bool {
    return switch (address) {
        0xff12, 0xff17, 0xff21 => value & 0xf8 == 0,
        0xff1a => value & 0x80 == 0,
        else => false,
    };
}

fn nativeBool(native: []const u8, offset: usize) Error!bool {
    return switch (native[offset]) {
        0 => false,
        1 => true,
        else => error.InvalidState,
    };
}

test "DMG APU latch masks cover every readable non-status register" {
    var state = State{ .enabled = true };
    for (FIRST_ADDRESS..LAST_ADDRESS + 1) |raw_address| {
        const address: u16 = @intCast(raw_address);
        if (!isReadableLatch(address)) continue;
        for (0..256) |raw_value| {
            const value: u8 = @intCast(raw_value);
            state.registers[index(address)] = value;
            try std.testing.expectEqual(
                value | READ_MASKS[index(address)],
                try state.read(address),
            );
        }
    }
}

test "DMG APU power gate preserves only documented off-state latches" {
    for (FIRST_ADDRESS..WAVE_START) |raw_address| {
        const address: u16 = @intCast(raw_address);
        if (isUnused(address) or address == NR52) continue;
        for (0..256) |raw_value| {
            const value: u8 = @intCast(raw_value);
            var state = State{};
            state.registers[index(address)] = 0xa5;
            try state.write(address, value);
            const expected = if (isWritableWhileOff(address))
                if (address == NR11 or address == NR21) value & 0x3f else value
            else
                @as(u8, 0xa5);
            try std.testing.expectEqual(expected, state.registers[index(address)]);
        }
    }

    var powered = State{ .enabled = true };
    @memset(powered.registers[0..index(WAVE_START)], 0xa5);
    powered.registers[index(WAVE_START)] = 0x6b;
    try powered.write(NR52, 0);
    try std.testing.expect(!powered.enabled);
    try std.testing.expectEqual(@as(?u4, 0), powered.channel_status);
    for (powered.registers[0..index(WAVE_START)]) |value|
        try std.testing.expectEqual(@as(u8, 0), value);
    try std.testing.expectEqual(@as(u8, 0x6b), powered.registers[index(WAVE_START)]);
    try std.testing.expectEqual(@as(u8, 0x70), try powered.read(NR52));
    try powered.write(NR52, 0x80);
    try std.testing.expectEqual(@as(u8, 0xf0), try powered.read(NR52));
}

test "SameBoy IO projection takes power from native APU state" {
    var io = [_]u8{0} ** 0x40;
    io[0x25] = 0x37;
    io[0x26] = 0;
    const state = try State.fromIo(&io, true, 0, .inactive);
    try std.testing.expect(state.enabled);
    try std.testing.expectEqual(@as(u8, 0xf0), try state.read(NR52));
    try std.testing.expectEqual(@as(u8, 0x37), try state.read(0xff25));
    try std.testing.expectEqual(@as(u8, 0), state.registers[index(NR52)]);
}

test "SameBoy native APU projection commits status and wave phase" {
    var io = [_]u8{0} ** 0x40;
    io[0x25] = 0x37;
    var native = [_]u8{0} ** SAMEBOY_NATIVE_SIZE;
    native[0] = 1;
    native[8] = 1;
    native[10] = 1;
    native[68] = 0x0f;
    native[70] = 1;
    var state = try State.fromSameBoyNative(&io, &native);
    try std.testing.expectEqual(@as(u8, 0xf5), try state.read(NR52));
    try state.write(WAVE_START, 0x9a);
    try std.testing.expectEqual(@as(u8, 0x9a), try state.read(WAVE_END));

    native[70] = 2;
    try std.testing.expectError(
        error.InvalidState,
        State.fromSameBoyNative(&io, &native),
    );
}

test "DMG wave RAM is exact only for a committed phase" {
    var state = State{ .enabled = true };
    for (WAVE_START..WAVE_END + 1) |raw_address| {
        const address: u16 = @intCast(raw_address);
        const value: u8 = @truncate(raw_address);
        try state.write(address, value);
        try std.testing.expectEqual(value, try state.read(address));
    }

    state.wave_access = .blocked;
    try state.write(WAVE_START, 0x42);
    try std.testing.expectEqual(@as(u8, 0xff), try state.read(WAVE_START));
    try std.testing.expectEqual(@as(u8, 0x30), state.registers[index(WAVE_START)]);

    state.wave_access = .{ .current_byte = 7 };
    try state.write(WAVE_START, 0x91);
    try std.testing.expectEqual(@as(u8, 0x91), try state.read(WAVE_END));
    try std.testing.expectEqual(@as(u8, 0x91), state.registers[index(0xff37)]);

    state.wave_access = .unknown;
    try std.testing.expectError(error.UnknownWavePhase, state.read(WAVE_START));
    try std.testing.expectError(error.UnknownWavePhase, state.write(WAVE_START, 1));
}

test "DMG APU transitions reject stale latches and opaque status" {
    var state = State{ .enabled = true };
    const honest = try Transition.apply(state, .{ .write = .{
        .address = 0xff25,
        .value = 0x55,
    } });
    try honest.validate();

    var forged = honest;
    forged.after.registers[index(0xff25)] ^= 1;
    try std.testing.expectError(error.InvalidTransition, forged.validate());
    forged = honest;
    forged.read_value = 0;
    try std.testing.expectError(error.InvalidTransition, forged.validate());

    try state.write(NR34, 0x80);
    try std.testing.expectError(error.UnknownChannelStatus, state.read(NR52));
    try std.testing.expectError(error.UnknownWavePhase, state.write(WAVE_START, 0));
    try std.testing.expectError(error.UnsupportedWrite, state.write(0xff15, 0));
    try std.testing.expectError(error.UnsupportedAddress, state.read(0xff40));
}
