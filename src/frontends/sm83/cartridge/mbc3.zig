//! Pure RTC-free MBC3 state transitions and cartridge address resolution.

const std = @import("std");
const header = @import("header.zig");

pub const ROM_FIXED_END: u16 = 0x3fff;
pub const ROM_SWITCHED_START: u16 = 0x4000;
pub const ROM_SWITCHED_END: u16 = 0x7fff;
pub const RAM_START: u16 = 0xa000;
pub const RAM_END: u16 = 0xbfff;

pub const RomOffset = u20;
pub const RamOffset = u15;

pub const State = struct {
    /// The physical MBC3 register is seven bits wide. Zero is retained here
    /// and remapped only when resolving the switched ROM window.
    rom_bank_register: u7 = 0,
    /// RTC-free MBC3 cartridges expose four RAM banks. The selector write is
    /// eight bits wide, but SameBoy retains only its low three bits and the
    /// effective SRAM bank is decoded from the low two bits. The RTC-mapped
    /// bit has no observable effect for cartridge type 0x13.
    ram_bank_register: u3 = 0,
    ram_enabled: bool = false,

    pub fn selectedRomBank(self: State) u6 {
        const nonzero: u7 = if (self.rom_bank_register == 0)
            1
        else
            self.rom_bank_register;
        return @truncate(nonzero);
    }

    pub fn selectedRamBank(self: State) u2 {
        return @truncate(self.ram_bank_register);
    }
};

pub const ReadTarget = union(enum) {
    rom: RomOffset,
    ram: RamOffset,
    open_bus,
};

pub const WriteTarget = union(enum) {
    control,
    ram: RamOffset,
    ignored,
};

pub const ResolveError = error{NotCartridgeAddress};

pub const TransitionError = error{NotControlAddress};

pub fn resolveRead(state: State, address: u16) ResolveError!ReadTarget {
    if (address <= ROM_FIXED_END)
        return .{ .rom = @intCast(address) };
    if (address <= ROM_SWITCHED_END) {
        const bank_base =
            @as(RomOffset, state.selectedRomBank()) *
            @as(RomOffset, header.ROM_BANK_SIZE);
        return .{
            .rom = bank_base + @as(
                RomOffset,
                @intCast(address & ROM_FIXED_END),
            ),
        };
    }
    if (address >= RAM_START and address <= RAM_END) {
        if (!state.ram_enabled) return .open_bus;
        return .{ .ram = ramOffset(state, address) };
    }
    return error.NotCartridgeAddress;
}

pub fn resolveWrite(state: State, address: u16) ResolveError!WriteTarget {
    if (address <= ROM_SWITCHED_END) return .control;
    if (address >= RAM_START and address <= RAM_END) {
        if (!state.ram_enabled) return .ignored;
        return .{ .ram = ramOffset(state, address) };
    }
    return error.NotCartridgeAddress;
}

/// Applies one write to the MBC3 control range and returns the next state.
/// Errors are transactional because the input state is passed by value.
pub fn transition(
    state: State,
    address: u16,
    value: u8,
) TransitionError!State {
    var next = state;
    switch (address) {
        0x0000...0x1fff => next.ram_enabled = value & 0x0f == 0x0a,
        0x2000...0x3fff => next.rom_bank_register = @truncate(value),
        0x4000...0x5fff => next.ram_bank_register = @truncate(value),
        // This cartridge type has no RTC to latch. The range is decoded, but
        // its writes have no machine-visible effect.
        0x6000...0x7fff => {},
        else => return error.NotControlAddress,
    }
    return next;
}

fn ramOffset(state: State, address: u16) RamOffset {
    std.debug.assert(address >= RAM_START and address <= RAM_END);
    const bank_base =
        @as(RamOffset, state.selectedRamBank()) *
        @as(RamOffset, header.RAM_BANK_SIZE);
    return bank_base + @as(RamOffset, @intCast(address & 0x1fff));
}

test "ROM resolution covers fixed zero-remapped and aliased bank boundaries" {
    const reset = State{};
    try std.testing.expectEqual(
        ReadTarget{ .rom = 0 },
        try resolveRead(reset, 0x0000),
    );
    try std.testing.expectEqual(
        ReadTarget{ .rom = 0x3fff },
        try resolveRead(reset, 0x3fff),
    );
    try std.testing.expectEqual(
        ReadTarget{ .rom = 0x4000 },
        try resolveRead(reset, 0x4000),
    );
    try std.testing.expectEqual(
        ReadTarget{ .rom = 0x7fff },
        try resolveRead(reset, 0x7fff),
    );

    const bank_63 = try transition(reset, 0x2000, 0x3f);
    try std.testing.expectEqual(@as(u6, 63), bank_63.selectedRomBank());
    try std.testing.expectEqual(
        ReadTarget{ .rom = header.ROM_SIZE - 1 },
        try resolveRead(bank_63, 0x7fff),
    );

    const bank_64 = try transition(reset, 0x3fff, 0x40);
    try std.testing.expectEqual(@as(u6, 0), bank_64.selectedRomBank());
    try std.testing.expectEqual(
        ReadTarget{ .rom = 0 },
        try resolveRead(bank_64, 0x4000),
    );

    const truncated_zero = try transition(reset, 0x2000, 0x80);
    try std.testing.expectEqual(@as(u7, 0), truncated_zero.rom_bank_register);
    try std.testing.expectEqual(@as(u6, 1), truncated_zero.selectedRomBank());

    const bank_127 = try transition(reset, 0x2000, 0xff);
    try std.testing.expectEqual(@as(u7, 0x7f), bank_127.rom_bank_register);
    try std.testing.expectEqual(@as(u6, 63), bank_127.selectedRomBank());
}

test "RAM enable uses the low nibble and disabled access is explicit" {
    const reset = State{};
    try std.testing.expectEqual(ReadTarget.open_bus, try resolveRead(reset, RAM_START));
    try std.testing.expectEqual(WriteTarget.ignored, try resolveWrite(reset, RAM_START));

    const enabled = try transition(reset, 0x1fff, 0xfa);
    try std.testing.expect(enabled.ram_enabled);
    try std.testing.expectEqual(
        ReadTarget{ .ram = 0 },
        try resolveRead(enabled, RAM_START),
    );
    try std.testing.expectEqual(
        WriteTarget{ .ram = 0x1fff },
        try resolveWrite(enabled, RAM_END),
    );

    const disabled = try transition(enabled, 0x0000, 0x0b);
    try std.testing.expect(!disabled.ram_enabled);
}

test "all RAM selector bytes match SameBoy type 0x13 aliases" {
    const enabled = try transition(State{}, 0, 0x0a);
    for (0..256) |raw_selector| {
        const state = try transition(
            enabled,
            0x4000,
            @intCast(raw_selector),
        );
        try std.testing.expectEqual(
            @as(u3, @truncate(raw_selector)),
            state.ram_bank_register,
        );
        try std.testing.expectEqual(
            @as(u2, @truncate(raw_selector)),
            state.selectedRamBank(),
        );
        const expected: RamOffset =
            @as(RamOffset, @as(u2, @truncate(raw_selector))) *
            @as(RamOffset, header.RAM_BANK_SIZE);
        try std.testing.expectEqual(
            ReadTarget{ .ram = expected },
            try resolveRead(state, RAM_START),
        );
        try std.testing.expectEqual(
            WriteTarget{ .ram = expected +
                @as(RamOffset, header.RAM_BANK_SIZE - 1) },
            try resolveWrite(state, RAM_END),
        );
    }
    const bank_3 = try transition(enabled, 0x5fff, 7);
    try std.testing.expectEqual(
        ReadTarget{ .ram = header.RAM_SIZE - 1 },
        try resolveRead(bank_3, RAM_END),
    );
}

test "RTC-free latch writes are inert" {
    const initial = try transition(State{}, 0, 0x0a);
    try std.testing.expectEqualDeep(
        initial,
        try transition(initial, 0x6000, 0),
    );
    try std.testing.expectEqualDeep(
        initial,
        try transition(initial, 0x7fff, 1),
    );
}

test "non-cartridge addresses and non-control transitions fail closed" {
    try std.testing.expectError(
        error.NotCartridgeAddress,
        resolveRead(State{}, 0x8000),
    );
    try std.testing.expectError(
        error.NotCartridgeAddress,
        resolveWrite(State{}, 0xffff),
    );
    try std.testing.expectEqual(
        WriteTarget.control,
        try resolveWrite(State{}, ROM_SWITCHED_END),
    );
    try std.testing.expectError(
        error.NotControlAddress,
        transition(State{}, 0xa000, 0),
    );
}
