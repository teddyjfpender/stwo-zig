//! Owned flat SM83 memory with optional timer, PPU, DMA, and ROM-only overlays.
//!
//! The 64 KiB byte image remains the single owner. A ROM-only installation
//! copies its immutable public bytes into that image; attached devices are
//! borrowed only until their explicit detach operation.

const std = @import("std");
const hardware_dma = @import("dma.zig");
const hardware_ppu = @import("ppu_mmio.zig");
const live_dma = @import("live_dma.zig");
const rom_only_memory = @import("rom_only_memory.zig");
const hardware_timer = @import("timer.zig");

const DIV: u16 = 0xff04;
const TIMA: u16 = 0xff05;
const TMA: u16 = 0xff06;
const TAC: u16 = 0xff07;
const IF: u16 = 0xff0f;
const IF_WRITABLE_MASK: u8 = 0x1f;
const IF_READ_MASK: u8 = 0xe0;

pub const Memory = struct {
    bytes: *[65536]u8,
    allocator: std.mem.Allocator,
    timer: ?*hardware_timer.Timer = null,
    ppu: ?*hardware_ppu.State = null,
    dma: ?*live_dma.Controller = null,
    rom_only: ?rom_only_memory.Mapping = null,

    pub fn init(allocator: std.mem.Allocator) !Memory {
        const bytes = try allocator.create([65536]u8);
        @memset(bytes, 0);
        return .{ .bytes = bytes, .allocator = allocator };
    }

    pub fn deinit(self: *Memory) void {
        self.allocator.destroy(self.bytes);
        self.* = undefined;
    }

    pub fn read(self: *Memory, address: u16) u8 {
        self.prepareDmaCycle(null);
        if (self.dma) |controller| switch (controller.state.cpuAccess(address)) {
            .allowed => {},
            .blocked_source_bus => return self.readResolved(
                controller.last_transfer.?.source_address,
            ),
            .blocked_oam => return 0xff,
        };
        return self.readResolved(address);
    }

    fn readResolved(self: *Memory, address: u16) u8 {
        if (self.ppu) |ppu| if (ppu.read(address)) |value| return value;
        if (address == IF and self.hardwareAttached())
            return self.bytes[address] & IF_WRITABLE_MASK | IF_READ_MASK;
        if (self.timer) |device_timer| return switch (address) {
            DIV => device_timer.readDiv(),
            TIMA => device_timer.readTima(),
            TMA => device_timer.readTma(),
            TAC => device_timer.readTac(),
            else => if (self.rom_only) |mapping|
                mapping.read(self.bytes, address) orelse self.bytes[address]
            else
                self.bytes[address],
        };
        if (self.rom_only) |mapping|
            return mapping.read(self.bytes, address) orelse self.bytes[address];
        return self.bytes[address];
    }

    pub fn write(self: *Memory, address: u16, value: u8) void {
        self.prepareDmaCycle(
            if (address == hardware_dma.DMA_ADDRESS) value else null,
        );
        if (self.dma) |controller| switch (controller.state.cpuWriteAccess(address)) {
            .allowed => {},
            .blocked_oam => return,
            .blocked_source_bus => {
                const transfer = controller.last_transfer.?;
                if (transfer.source_address < 0xa000) {
                    self.writeResolved(transfer.source_address, value);
                } else {
                    self.bytes[transfer.destination_address] &= value;
                }
                return;
            },
        };
        self.writeResolved(address, value);
    }

    fn writeResolved(self: *Memory, address: u16, value: u8) void {
        if (self.ppu) |ppu| if (ppu.read(address) != null) {
            _ = ppu.write(address, value) catch unreachable;
            self.syncPpu();
            return;
        };
        if (self.timer) |device_timer| switch (address) {
            DIV => device_timer.writeDiv(),
            TIMA => device_timer.writeTima(value),
            TMA => device_timer.writeTma(value),
            TAC => device_timer.writeTac(value),
            else => {
                self.writeSystem(address, value);
                return;
            },
        } else {
            self.writeSystem(address, value);
            return;
        }
        self.syncTimer();
    }

    pub fn attachTimer(
        self: *Memory,
        device_timer: *hardware_timer.Timer,
    ) void {
        std.debug.assert(self.timer == null);
        self.timer = device_timer;
        self.syncTimer();
    }

    pub fn detachTimer(self: *Memory) void {
        self.syncTimer();
        self.timer = null;
    }

    pub fn installRomOnly(self: *Memory, rom: []const u8) !void {
        if (self.rom_only != null) return error.RomAlreadyInstalled;
        self.rom_only = try rom_only_memory.Mapping.install(self.bytes, rom);
    }

    pub fn attachPpu(
        self: *Memory,
        ppu: *hardware_ppu.State,
    ) hardware_ppu.ValidationError!void {
        std.debug.assert(self.ppu == null);
        try ppu.validate();
        ppu.interrupt_flags = self.bytes[IF] & IF_WRITABLE_MASK;
        self.ppu = ppu;
        self.syncPpu();
    }

    pub fn detachPpu(self: *Memory) void {
        self.syncPpu();
        self.ppu = null;
    }

    pub fn attachDma(
        self: *Memory,
        controller: *live_dma.Controller,
    ) live_dma.ValidationError!void {
        std.debug.assert(self.dma == null);
        try controller.validate();
        self.dma = controller;
        self.bytes[hardware_dma.DMA_ADDRESS] = controller.state.page;
    }

    pub fn detachDma(self: *Memory) void {
        const controller = self.dma orelse return;
        std.debug.assert(!controller.prepared);
        self.bytes[hardware_dma.DMA_ADDRESS] = controller.state.page;
        self.dma = null;
    }

    /// Advances every attached device by exactly one SM83 M-cycle.
    pub fn tickMcycle(self: *Memory) void {
        self.prepareDmaCycle(null);
        if (self.timer) |device_timer| {
            if (device_timer.tickMcycle())
                self.requestInterrupt(hardware_timer.TIMER_INTERRUPT);
            self.syncTimer();
        }
        if (self.ppu) |ppu| {
            _ = ppu.tickMcycle();
            self.syncPpu();
        }
        if (self.dma) |controller| controller.finishCycle();
    }

    fn syncTimer(self: *Memory) void {
        const device_timer = self.timer orelse return;
        self.bytes[DIV] = device_timer.readDiv();
        self.bytes[TIMA] = device_timer.readTima();
        self.bytes[TMA] = device_timer.readTma();
        // The committed backing image stores only writable TAC bits; CPU reads
        // synthesize the hardware's high-one mask while the timer is attached.
        self.bytes[TAC] = device_timer.tac;
    }

    fn syncPpu(self: *Memory) void {
        const ppu = self.ppu orelse return;
        inline for (.{
            hardware_ppu.LCDC_ADDRESS,
            hardware_ppu.STAT_ADDRESS,
            hardware_ppu.LY_ADDRESS,
            hardware_ppu.LYC_ADDRESS,
        }) |address| self.bytes[address] = ppu.read(address).?;
        self.bytes[IF] = ppu.interrupt_flags & IF_WRITABLE_MASK;
    }

    fn writeSystem(self: *Memory, address: u16, value: u8) void {
        if (self.rom_only) |mapping|
            if (mapping.write(self.bytes, address, value)) return;
        self.bytes[address] = if (address == IF and self.hardwareAttached())
            value & IF_WRITABLE_MASK
        else
            value;
        if (address == IF and self.hardwareAttached()) {
            if (self.ppu) |ppu|
                ppu.interrupt_flags = value & IF_WRITABLE_MASK;
        }
    }

    fn requestInterrupt(self: *Memory, interrupt: u8) void {
        self.bytes[IF] =
            (self.bytes[IF] | interrupt) & IF_WRITABLE_MASK;
        if (self.ppu) |ppu| ppu.interrupt_flags = self.bytes[IF];
    }

    fn hardwareAttached(self: *const Memory) bool {
        return self.timer != null or self.ppu != null or
            self.dma != null or self.rom_only != null;
    }

    fn prepareDmaCycle(self: *Memory, ff46_page: ?u8) void {
        const controller = self.dma orelse return;
        if (controller.prepared) {
            std.debug.assert(ff46_page == null);
            return;
        }
        const source_byte = if (controller.nextSourceAddress()) |address|
            self.readResolved(address)
        else
            null;
        const transition = controller.advance(
            source_byte,
            ff46_page,
        ) catch unreachable;
        if (transition.transfer) |transfer|
            self.bytes[transfer.destination_address] = transfer.value;
        self.bytes[hardware_dma.DMA_ADDRESS] = controller.state.page;
    }
};

test "IF CPU reads synthesize high bits while writes store only low five" {
    var memory = try Memory.init(std.testing.allocator);
    defer memory.deinit();

    // Device-free memory remains a literal byte array for SingleStepTests.
    memory.write(IF, 0x40);
    try std.testing.expectEqual(@as(u8, 0x40), memory.read(IF));

    var device_timer = hardware_timer.Timer{};
    memory.attachTimer(&device_timer);
    defer memory.detachTimer();

    memory.write(IF, 0);
    try std.testing.expectEqual(@as(u8, 0), memory.bytes[IF]);
    try std.testing.expectEqual(@as(u8, 0xe0), memory.read(IF));

    memory.write(IF, 0xff);
    try std.testing.expectEqual(@as(u8, 0x1f), memory.bytes[IF]);
    try std.testing.expectEqual(@as(u8, 0xff), memory.read(IF));

    // A corrupted backing byte cannot leak non-hardware high bits.
    memory.bytes[IF] = 0x40;
    try std.testing.expectEqual(@as(u8, 0xe0), memory.read(IF));
}
