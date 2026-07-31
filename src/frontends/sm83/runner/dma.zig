//! Deterministic DMG-B OAM DMA progression in SM83 M-cycle units.
//!
//! This mirrors pinned SameBoy `Core/memory.c`:
//! - an FF46 write installs one warm-up M-cycle;
//! - 160 following M-cycles copy one byte each to FE00...FE9F;
//! - one final M-cycle changes the internal A0 destination into inactive A1;
//! - DMA advances before the CPU memory access at the end of an M-cycle.
//!
//! Source bytes remain explicit inputs. A proof integration must authenticate
//! them against ordered cartridge/system-memory lookups. PPU conflicts, OAM
//! corruption, CGB variants, and DMA progression while HALT/STOP is entered
//! remain outside this DMG-B leaf.

const std = @import("std");

pub const DMA_ADDRESS: u16 = 0xff46;
pub const OAM_START: u16 = 0xfe00;
pub const OAM_LENGTH: u8 = 160;
pub const STARTUP_MCYCLES: u8 = 1;
pub const TRANSFER_MCYCLES: u8 = OAM_LENGTH;
pub const COMPLETION_MCYCLES: u8 = 1;
pub const MAX_CLOCK: u32 = (1 << 30) - 1;

pub const Phase = enum(u2) {
    idle,
    startup,
    transfer,
    finishing,
};

/// Access classification only. A memory-bus integration must bind the value
/// observed by a blocked CPU read to the DMA bus value.
pub const CpuAccess = enum {
    allowed,
    blocked_source_bus,
    blocked_oam,
};

pub const StateError = error{
    InvalidClock,
    InvalidCopiedCount,
    InvalidRestartState,
};

pub const TransitionError = StateError || error{
    ClockExhausted,
    InvalidEvent,
};

/// Complete deterministic state at an M-cycle boundary.
///
/// `copied` is the number of committed OAM bytes. The transfer phase admits
/// 0...159; finishing is the explicit SameBoy destination-A0 state at 160.
pub const State = struct {
    clock: u32 = 0,
    page: u8 = 0xff,
    copied: u8 = 0,
    phase: Phase = .idle,
    restarting: bool = false,

    pub fn validate(self: State) StateError!void {
        if (self.clock > MAX_CLOCK) return error.InvalidClock;
        switch (self.phase) {
            .idle, .startup => {
                if (self.copied != 0) return error.InvalidCopiedCount;
            },
            .transfer => {
                if (self.copied >= OAM_LENGTH)
                    return error.InvalidCopiedCount;
            },
            .finishing => {
                if (self.copied != OAM_LENGTH)
                    return error.InvalidCopiedCount;
            },
        }
        if (self.restarting and
            self.phase != .startup and
            !(self.phase == .transfer and self.copied == 0))
        {
            return error.InvalidRestartState;
        }
    }

    pub fn isActive(self: State) bool {
        return self.phase != .idle;
    }

    /// OAM is unavailable after FF46 is written, except for the observable
    /// fresh-DMA destination-zero warm-up boundary.
    pub fn oamBlocked(self: State) bool {
        return switch (self.phase) {
            .idle => false,
            .startup, .finishing => true,
            .transfer => self.copied != 0 or self.restarting,
        };
    }

    /// DMG has one cartridge/WRAM bus and one VRAM bus. IO and HRAM remain
    /// accessible, which is the policy used by Pokémon's HRAM DMA routine.
    pub fn cpuAccess(self: State, address: u16) CpuAccess {
        if (address >= 0xfe00 and address < 0xff00 and self.oamBlocked())
            return .blocked_oam;
        if (!self.sourceBusBlocked() or address >= 0xfe00)
            return .allowed;
        return if (busForAddress(address) == self.sourceBus())
            .blocked_source_bus
        else
            .allowed;
    }

    /// SameBoy allows one destination-zero OAM read during warm-up, but drops
    /// every OAM write while DMA remains active.
    pub fn cpuWriteAccess(self: State, address: u16) CpuAccess {
        if (address >= 0xfe00 and address < 0xff00 and self.isActive())
            return .blocked_oam;
        return self.cpuAccess(address);
    }

    fn sourceBusBlocked(self: State) bool {
        return self.phase == .finishing or
            (self.phase == .transfer and self.copied != 0);
    }

    fn sourceBus(self: State) Bus {
        return if (self.page >= 0x80 and self.page < 0xa0)
            .vram
        else
            .main;
    }
};

/// One CPU M-cycle. SameBoy advances an existing transfer before applying the
/// optional FF46 write, hence the explicit combined event.
pub const Event = union(enum) {
    tick,
    write_ff46: u8,
    transfer: u8,
    transfer_and_write: struct {
        source_byte: u8,
        page: u8,
    },
};

pub const Transfer = struct {
    source_address: u16,
    destination_address: u16,
    value: u8,
};

pub const Transition = struct {
    before: State,
    after: State,
    event: Event,
    transfer: ?Transfer,
    completed: bool,

    pub fn apply(before: State, event: Event) TransitionError!Transition {
        try before.validate();
        if (before.clock == MAX_CLOCK) return error.ClockExhausted;

        const expects_transfer = before.phase == .transfer;
        const has_transfer = switch (event) {
            .transfer, .transfer_and_write => true,
            .tick, .write_ff46 => false,
        };
        if (expects_transfer != has_transfer) return error.InvalidEvent;

        var after = before;
        after.clock += 1;
        const transfer = try progress(&after, event);
        const completed = before.phase == .finishing;

        switch (event) {
            .write_ff46 => |page| start(&after, page),
            .transfer_and_write => |write| start(&after, write.page),
            .tick, .transfer => {},
        }

        try after.validate();
        return .{
            .before = before,
            .after = after,
            .event = event,
            .transfer = transfer,
            .completed = completed,
        };
    }

    pub fn validate(self: Transition) error{InvalidTransition}!void {
        const expected = Transition.apply(self.before, self.event) catch
            return error.InvalidTransition;
        if (!std.meta.eql(expected, self))
            return error.InvalidTransition;
    }
};

pub fn effectiveSourceAddress(page: u8, offset: u8) u16 {
    const raw = (@as(u16, page) << 8) | offset;
    return if (raw >= 0xe000) raw - 0x2000 else raw;
}

fn progress(after: *State, event: Event) TransitionError!?Transfer {
    switch (after.phase) {
        .idle => return null,
        .startup => {
            after.phase = .transfer;
            return null;
        },
        .finishing => {
            after.phase = .idle;
            after.copied = 0;
            after.restarting = false;
            return null;
        },
        .transfer => {},
    }

    const source_byte = switch (event) {
        .transfer => |value| value,
        .transfer_and_write => |write| write.source_byte,
        else => return error.InvalidEvent,
    };
    const copied = after.copied;
    const transfer = Transfer{
        .source_address = effectiveSourceAddress(after.page, copied),
        .destination_address = OAM_START + @as(u16, copied),
        .value = source_byte,
    };
    after.copied += 1;
    after.restarting = false;
    if (after.copied == OAM_LENGTH)
        after.phase = .finishing;
    return transfer;
}

fn start(after: *State, page: u8) void {
    const restarting =
        after.phase == .transfer and after.copied != 0;
    after.page = page;
    after.copied = 0;
    after.phase = .startup;
    after.restarting = restarting;
}

const Bus = enum {
    main,
    vram,
    none,
};

fn busForAddress(address: u16) Bus {
    if (address >= 0xfe00) return .none;
    return if (address >= 0x8000 and address < 0xa000)
        .vram
    else
        .main;
}

test "DMG-B DMA has exact warm-up transfer and completion M-cycles" {
    var state = State{};
    var transition = try Transition.apply(
        state,
        .{ .write_ff46 = 0xc0 },
    );
    state = transition.after;
    try std.testing.expectEqual(Phase.startup, state.phase);
    try std.testing.expect(state.oamBlocked());

    transition = try Transition.apply(state, .tick);
    state = transition.after;
    try std.testing.expectEqual(Phase.transfer, state.phase);
    try std.testing.expectEqual(@as(u8, 0), state.copied);
    try std.testing.expect(!state.oamBlocked());

    for (0..OAM_LENGTH) |index| {
        transition = try Transition.apply(
            state,
            .{ .transfer = @intCast(index) },
        );
        const copy = transition.transfer.?;
        try std.testing.expectEqual(
            @as(u16, 0xc000) + @as(u16, @intCast(index)),
            copy.source_address,
        );
        try std.testing.expectEqual(
            OAM_START + @as(u16, @intCast(index)),
            copy.destination_address,
        );
        try std.testing.expectEqual(@as(u8, @intCast(index)), copy.value);
        state = transition.after;
    }
    try std.testing.expectEqual(Phase.finishing, state.phase);
    try std.testing.expectEqual(OAM_LENGTH, state.copied);
    try std.testing.expect(state.oamBlocked());

    transition = try Transition.apply(state, .tick);
    try std.testing.expect(transition.completed);
    try std.testing.expectEqual(Phase.idle, transition.after.phase);
    try std.testing.expectEqual(@as(u32, 163), transition.after.clock);
}

test "DMG source aliases and CPU bus blocking match SameBoy" {
    try std.testing.expectEqual(
        @as(u16, 0xc000),
        effectiveSourceAddress(0xe0, 0),
    );
    try std.testing.expectEqual(
        @as(u16, 0xde9f),
        effectiveSourceAddress(0xfe, 0x9f),
    );
    try std.testing.expectEqual(
        @as(u16, 0xdf9f),
        effectiveSourceAddress(0xff, 0x9f),
    );

    var state = (try Transition.apply(
        State{},
        .{ .write_ff46 = 0xc0 },
    )).after;
    state = (try Transition.apply(state, .tick)).after;
    try std.testing.expectEqual(CpuAccess.allowed, state.cpuAccess(0xc000));
    try std.testing.expectEqual(CpuAccess.allowed, state.cpuAccess(0xfe00));
    try std.testing.expectEqual(
        CpuAccess.blocked_oam,
        state.cpuWriteAccess(0xfe00),
    );
    state = (try Transition.apply(state, .{ .transfer = 0x42 })).after;
    try std.testing.expectEqual(
        CpuAccess.blocked_source_bus,
        state.cpuAccess(0x1234),
    );
    try std.testing.expectEqual(CpuAccess.allowed, state.cpuAccess(0x8000));
    try std.testing.expectEqual(CpuAccess.allowed, state.cpuAccess(0xff46));
    try std.testing.expectEqual(CpuAccess.allowed, state.cpuAccess(0xff80));
    try std.testing.expectEqual(
        CpuAccess.blocked_oam,
        state.cpuAccess(0xfe00),
    );

    state.page = 0x80;
    try std.testing.expectEqual(CpuAccess.allowed, state.cpuAccess(0xc000));
    try std.testing.expectEqual(
        CpuAccess.blocked_source_bus,
        state.cpuAccess(0x8000),
    );
}

test "restart copies the old byte before installing the new page" {
    var state = (try Transition.apply(
        State{},
        .{ .write_ff46 = 0xc0 },
    )).after;
    state = (try Transition.apply(state, .tick)).after;
    state = (try Transition.apply(state, .{ .transfer = 1 })).after;

    const restart = try Transition.apply(state, .{
        .transfer_and_write = .{
            .source_byte = 2,
            .page = 0x80,
        },
    });
    try std.testing.expectEqual(@as(u16, 0xc001), restart.transfer.?.source_address);
    try std.testing.expectEqual(@as(u16, 0xfe01), restart.transfer.?.destination_address);
    try std.testing.expectEqual(Phase.startup, restart.after.phase);
    try std.testing.expect(restart.after.restarting);

    state = (try Transition.apply(restart.after, .tick)).after;
    try std.testing.expect(state.oamBlocked());
    try std.testing.expectEqual(CpuAccess.allowed, state.cpuAccess(0x8000));
    state = (try Transition.apply(state, .{ .transfer = 3 })).after;
    try std.testing.expect(!state.restarting);
}

test "transition validation fails closed" {
    try std.testing.expectError(
        error.InvalidEvent,
        Transition.apply(State{}, .{ .transfer = 0 }),
    );
    const exhausted = State{ .clock = MAX_CLOCK };
    try std.testing.expectError(
        error.ClockExhausted,
        Transition.apply(exhausted, .tick),
    );

    var forged = try Transition.apply(State{}, .{ .write_ff46 = 0x80 });
    forged.after.page ^= 1;
    try std.testing.expectError(
        error.InvalidTransition,
        forged.validate(),
    );
}
