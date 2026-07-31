//! RTC-free MBC3 address space with proof-oriented per-access metadata.

const std = @import("std");
const cartridge_mod = @import("../cartridge/mod.zig");
const header = cartridge_mod.header;
const mbc3 = cartridge_mod.mbc3;
const hardware_apu = @import("apu_mmio.zig");
const hardware_dma = @import("dma.zig");
const hardware_timer = @import("timer.zig");
const hardware_joypad = @import("joypad.zig");
const hardware_ppu = @import("ppu_mmio.zig");
const live_dma = @import("live_dma.zig");
const address_space = @import("cartridge_address_space.zig");

pub const SYSTEM_SIZE: usize = 0x10000;
pub const PhysicalOffset = mbc3.RomOffset;
pub const ECHO_START = address_space.ECHO_START;
pub const ECHO_END = address_space.ECHO_END;
pub const ECHO_DELTA = address_space.ECHO_DELTA;
pub const UNUSABLE_START = address_space.UNUSABLE_START;
pub const UNUSABLE_END = address_space.UNUSABLE_END;
pub const INTERRUPT_FLAGS: u16 = 0xff0f;

const DIV: u16 = 0xff04;
const TIMA: u16 = 0xff05;
const TMA: u16 = 0xff06;
const TAC: u16 = 0xff07;
const IF_WRITABLE_MASK: u8 = 0x1f;
const IF_READ_MASK: u8 = 0xe0;
pub const Action = enum {
    read,
    write,
};

pub const Region = enum {
    cartridge_rom,
    cartridge_ram,
    mapper_control,
    cartridge_open_bus,
    cartridge_ram_ignored,
    system_echo,
    joypad_mmio,
    timer_mmio,
    system,
    ppu_mmio,
    apu_mmio,
};
pub const Access = struct {
    logical_address: u16,
    action: Action,
    region: Region,
    physical_offset: ?PhysicalOffset,
    mapper_before: mbc3.State,
    mapper_after: mbc3.State,
    value: u8,
    dma_class: hardware_dma.CpuAccess = .allowed,

    fn withDmaClass(
        self: Access,
        dma_class: hardware_dma.CpuAccess,
    ) Access {
        var result = self;
        result.dma_class = dma_class;
        return result;
    }
};

pub const ReadResult = struct {
    value: u8,
    access: Access,
};

pub const ReadError = error{UnusableAddress} || hardware_apu.Error;
pub const JoypadInputError = error{JoypadNotAttached};

pub const WriteError = error{UnusableAddress} || hardware_apu.Error;

pub const Memory = struct {
    cartridge: cartridge_mod.Cartridge,
    sram: *[header.RAM_SIZE]u8,
    system: *[SYSTEM_SIZE]u8,
    mapper: mbc3.State,
    data_bus: u8,
    timer: ?*hardware_timer.Timer = null,
    joypad: ?*hardware_joypad.State = null,
    ppu: ?*hardware_ppu.State = null,
    apu: ?*hardware_apu.State = null,
    dma: ?*live_dma.Controller = null,

    pub fn init(
        cartridge: cartridge_mod.Cartridge,
        sram: *[header.RAM_SIZE]u8,
        system: *[SYSTEM_SIZE]u8,
        mapper: mbc3.State,
        data_bus: u8,
    ) Memory {
        return .{
            .cartridge = cartridge,
            .sram = sram,
            .system = system,
            .mapper = mapper,
            .data_bus = data_bus,
        };
    }

    pub fn read(self: *Memory, address: u16) ReadError!ReadResult {
        if (address_space.isUnusable(address)) return error.UnusableAddress;
        self.prepareDmaCycle(null);
        const before = self.mapper;
        if (self.dma) |controller| {
            const class = controller.state.cpuAccess(address);
            if (class != .allowed) {
                if (class == .blocked_source_bus) {
                    const transfer = controller.last_transfer orelse
                        unreachable;
                    const resolved = try self.resolveRead(
                        transfer.source_address,
                    );
                    self.data_bus = resolved.value;
                    return .{
                        .value = resolved.value,
                        .access = makeAccess(
                            address,
                            .read,
                            resolved.region,
                            resolved.physical_offset,
                            before,
                            self.mapper,
                            resolved.value,
                        ).withDmaClass(class),
                    };
                }
                const value: u8 = 0xff;
                return .{
                    .value = value,
                    .access = makeDmaAccess(
                        address,
                        .read,
                        before,
                        self.mapper,
                        value,
                        class,
                    ),
                };
            }
        }
        const resolved = try self.resolveRead(address);
        self.data_bus = resolved.value;
        return .{
            .value = resolved.value,
            .access = makeAccess(
                address,
                .read,
                resolved.region,
                resolved.physical_offset,
                before,
                self.mapper,
                resolved.value,
            ),
        };
    }

    pub fn write(
        self: *Memory,
        address: u16,
        value: u8,
    ) WriteError!Access {
        if (address_space.isUnusable(address)) return error.UnusableAddress;
        self.prepareDmaCycle(
            if (address == hardware_dma.DMA_ADDRESS) value else null,
        );
        const class = if (self.dma) |controller|
            controller.state.cpuWriteAccess(address)
        else
            hardware_dma.CpuAccess.allowed;
        if (class == .blocked_oam) {
            self.data_bus = value;
            return makeDmaAccess(
                address,
                .write,
                self.mapper,
                self.mapper,
                value,
                class,
            );
        }
        if (class == .blocked_source_bus)
            return self.writeBlockedSource(address, value);
        return self.writeResolved(address, address, value, .allowed);
    }

    fn writeResolved(
        self: *Memory,
        logical_address: u16,
        address: u16,
        value: u8,
        dma_class: hardware_dma.CpuAccess,
    ) WriteError!Access {
        const before = self.mapper;
        var region: Region = .system;
        var physical_offset: ?PhysicalOffset = null;

        if (try self.writeDevice(address, value)) |device_region| {
            region = device_region;
        } else if (address <= mbc3.ROM_SWITCHED_END) {
            self.mapper = mbc3.transition(before, address, value) catch
                unreachable;
            region = .mapper_control;
        } else if (address >= mbc3.RAM_START and address <= mbc3.RAM_END) {
            switch (mbc3.resolveWrite(before, address) catch unreachable) {
                .control => unreachable,
                .ram => |offset| {
                    self.sram[offset] = value;
                    region = .cartridge_ram;
                    physical_offset = offset;
                },
                .ignored => region = .cartridge_ram_ignored,
            }
        } else if (address_space.isEcho(address)) {
            const target = address_space.echoTarget(address);
            self.system[target] = value;
            region = .system_echo;
            physical_offset = target;
        } else {
            self.system[address] = if (address == INTERRUPT_FLAGS)
                value & IF_WRITABLE_MASK
            else
                value;
        }
        if (address == INTERRUPT_FLAGS) {
            if (self.ppu) |ppu|
                ppu.interrupt_flags = value & IF_WRITABLE_MASK;
        }
        self.data_bus = value;
        return makeAccess(
            logical_address,
            .write,
            region,
            physical_offset,
            before,
            self.mapper,
            value,
        ).withDmaClass(dma_class);
    }

    pub fn attachTimer(self: *Memory, timer: *hardware_timer.Timer) void {
        std.debug.assert(self.timer == null);
        self.timer = timer;
        self.syncTimer();
    }

    pub fn detachTimer(self: *Memory) void {
        self.syncTimer();
        self.timer = null;
    }

    pub fn attachJoypad(
        self: *Memory,
        joypad: *hardware_joypad.State,
    ) hardware_joypad.ValidationError!void {
        std.debug.assert(self.joypad == null);
        try joypad.validate();
        self.joypad = joypad;
        self.syncJoypad();
    }

    pub fn detachJoypad(self: *Memory) void {
        self.syncJoypad();
        self.joypad = null;
    }

    pub fn attachPpu(
        self: *Memory,
        ppu: *hardware_ppu.State,
    ) hardware_ppu.ValidationError!void {
        std.debug.assert(self.ppu == null);
        try ppu.validate();
        ppu.interrupt_flags =
            self.system[INTERRUPT_FLAGS] & IF_WRITABLE_MASK;
        self.ppu = ppu;
        self.syncPpu();
    }

    pub fn detachPpu(self: *Memory) void {
        self.syncPpu();
        self.ppu = null;
    }

    pub fn attachApu(
        self: *Memory,
        apu: *hardware_apu.State,
    ) hardware_apu.Error!void {
        std.debug.assert(self.apu == null);
        try apu.validate();
        self.apu = apu;
        self.syncApu();
    }

    pub fn detachApu(self: *Memory) void {
        self.syncApu();
        self.apu = null;
    }

    pub fn attachDma(
        self: *Memory,
        controller: *live_dma.Controller,
    ) live_dma.ValidationError!void {
        std.debug.assert(self.dma == null);
        try controller.validate();
        self.dma = controller;
        self.system[hardware_dma.DMA_ADDRESS] = controller.state.page;
    }

    pub fn detachDma(self: *Memory) void {
        const controller = self.dma orelse return;
        std.debug.assert(!controller.prepared);
        self.system[hardware_dma.DMA_ADDRESS] = controller.state.page;
        self.dma = null;
    }

    /// Replaces the committed host action and propagates its interrupt edge.
    pub fn setJoypadPressed(
        self: *Memory,
        pressed: u8,
    ) JoypadInputError!void {
        const joypad = self.joypad orelse return error.JoypadNotAttached;
        if (joypad.setPressed(pressed))
            self.requestInterrupt(hardware_joypad.JOYPAD_INTERRUPT);
        self.syncJoypad();
    }

    /// Advances each attached device by exactly one SM83 M-cycle.
    pub fn tickMcycle(self: *Memory) void {
        self.prepareDmaCycle(null);
        if (self.timer) |timer| {
            if (timer.tickMcycle())
                self.requestInterrupt(hardware_timer.TIMER_INTERRUPT);
            self.syncTimer();
        }
        if (self.joypad) |joypad| {
            if (joypad.tickMcycles(1))
                self.requestInterrupt(hardware_joypad.JOYPAD_INTERRUPT);
            self.syncJoypad();
        }
        if (self.ppu) |ppu| {
            _ = ppu.tickMcycle();
            self.syncPpu();
        }
        if (self.dma) |controller| controller.finishCycle();
    }

    fn readDevice(self: *Memory, address: u16) ReadError!?ResolvedRead {
        if (self.ppu) |ppu| if (ppu.read(address)) |value| return .{
            .value = value,
            .region = .ppu_mmio,
            .physical_offset = null,
        };
        if (self.apu) |apu| if (hardware_apu.isAddress(address)) return .{
            .value = try apu.read(address),
            .region = .apu_mmio,
            .physical_offset = null,
        };
        if (address == hardware_joypad.P1_ADDRESS) {
            if (self.joypad) |joypad| return .{
                .value = joypad.readP1(),
                .region = .joypad_mmio,
                .physical_offset = null,
            };
        }
        if (self.timer) |timer| return switch (address) {
            DIV => .{
                .value = timer.readDiv(),
                .region = .timer_mmio,
                .physical_offset = null,
            },
            TIMA => .{
                .value = timer.readTima(),
                .region = .timer_mmio,
                .physical_offset = null,
            },
            TMA => .{
                .value = timer.readTma(),
                .region = .timer_mmio,
                .physical_offset = null,
            },
            TAC => .{
                .value = timer.readTac(),
                .region = .timer_mmio,
                .physical_offset = null,
            },
            else => null,
        };
        return null;
    }

    fn resolveRead(self: *Memory, address: u16) ReadError!ResolvedRead {
        if (try self.readDevice(address)) |device| return device;
        if (address == INTERRUPT_FLAGS) return .{
            .value = self.system[address] & IF_WRITABLE_MASK | IF_READ_MASK,
            .region = .system,
            .physical_offset = null,
        };
        if (address_space.isCartridge(address)) {
            return switch (mbc3.resolveRead(
                self.mapper,
                address,
            ) catch unreachable) {
                .rom => |offset| .{
                    .value = self.cartridge.readPhysical(offset),
                    .region = .cartridge_rom,
                    .physical_offset = offset,
                },
                .ram => |offset| .{
                    .value = self.sram[offset],
                    .region = .cartridge_ram,
                    .physical_offset = offset,
                },
                .open_bus => .{
                    .value = self.data_bus,
                    .region = .cartridge_open_bus,
                    .physical_offset = null,
                },
            };
        }
        if (address_space.isEcho(address)) return .{
            .value = self.system[address_space.echoTarget(address)],
            .region = .system_echo,
            .physical_offset = address_space.echoTarget(address),
        };
        return .{
            .value = self.system[address],
            .region = .system,
            .physical_offset = null,
        };
    }

    fn writeDevice(
        self: *Memory,
        address: u16,
        value: u8,
    ) WriteError!?Region {
        if (self.ppu) |ppu| if (ppu.read(address) != null) {
            _ = ppu.write(address, value) catch unreachable;
            self.syncPpu();
            return .ppu_mmio;
        };
        if (self.apu) |apu| if (hardware_apu.isAddress(address)) {
            try apu.write(address, value);
            self.syncApu();
            return .apu_mmio;
        };
        if (address == hardware_joypad.P1_ADDRESS) {
            if (self.joypad) |joypad| {
                if (joypad.writeP1(value))
                    self.requestInterrupt(hardware_joypad.JOYPAD_INTERRUPT);
                self.syncJoypad();
                return .joypad_mmio;
            }
        }
        if (self.timer) |timer| switch (address) {
            DIV => timer.writeDiv(),
            TIMA => timer.writeTima(value),
            TMA => timer.writeTma(value),
            TAC => timer.writeTac(value),
            else => return null,
        } else return null;
        self.syncTimer();
        return .timer_mmio;
    }

    fn requestInterrupt(self: *Memory, interrupt: u8) void {
        self.system[INTERRUPT_FLAGS] =
            (self.system[INTERRUPT_FLAGS] | interrupt) & IF_WRITABLE_MASK;
        if (self.ppu) |ppu|
            ppu.interrupt_flags = self.system[INTERRUPT_FLAGS];
    }

    fn syncTimer(self: *Memory) void {
        const timer = self.timer orelse return;
        self.system[DIV] = timer.readDiv();
        self.system[TIMA] = timer.readTima();
        self.system[TMA] = timer.readTma();
        self.system[TAC] = timer.tac;
    }

    fn syncJoypad(self: *Memory) void {
        const joypad = self.joypad orelse return;
        self.system[hardware_joypad.P1_ADDRESS] = joypad.readP1();
    }

    fn syncPpu(self: *Memory) void {
        const ppu = self.ppu orelse return;
        inline for (.{
            hardware_ppu.LCDC_ADDRESS,
            hardware_ppu.STAT_ADDRESS,
            hardware_ppu.SCY_ADDRESS,
            hardware_ppu.SCX_ADDRESS,
            hardware_ppu.LY_ADDRESS,
            hardware_ppu.LYC_ADDRESS,
            hardware_ppu.WY_ADDRESS,
        }) |address| self.system[address] = ppu.read(address).?;
        self.system[INTERRUPT_FLAGS] =
            ppu.interrupt_flags & IF_WRITABLE_MASK;
    }

    fn syncApu(self: *Memory) void {
        const apu = self.apu orelse return;
        @memcpy(
            self.system[hardware_apu.FIRST_ADDRESS .. hardware_apu.LAST_ADDRESS + 1],
            &apu.registers,
        );
    }

    fn prepareDmaCycle(self: *Memory, ff46_page: ?u8) void {
        const controller = self.dma orelse return;
        if (controller.prepared) {
            std.debug.assert(ff46_page == null);
            return;
        }
        const source_byte = if (controller.nextSourceAddress()) |address|
            self.readDmaSource(address)
        else
            null;
        const transition = controller.advance(
            source_byte,
            ff46_page,
        ) catch unreachable;
        if (transition.transfer) |transfer|
            self.system[transfer.destination_address] = transfer.value;
        self.system[hardware_dma.DMA_ADDRESS] = controller.state.page;
    }

    fn readDmaSource(self: *Memory, address: u16) u8 {
        return (self.resolveRead(address) catch unreachable).value;
    }

    fn writeBlockedSource(
        self: *Memory,
        logical_address: u16,
        value: u8,
    ) WriteError!Access {
        const controller = self.dma.?;
        const transfer = controller.last_transfer orelse unreachable;
        if (transfer.source_address < 0xa000)
            return self.writeResolved(
                logical_address,
                transfer.source_address,
                value,
                .blocked_source_bus,
            );
        self.system[transfer.destination_address] &= value;
        self.data_bus = value;
        return makeDmaAccess(
            logical_address,
            .write,
            self.mapper,
            self.mapper,
            value,
            .blocked_source_bus,
        );
    }
};

const ResolvedRead = struct {
    value: u8,
    region: Region,
    physical_offset: ?PhysicalOffset,
};

fn makeAccess(
    logical_address: u16,
    action: Action,
    region: Region,
    physical_offset: ?PhysicalOffset,
    mapper_before: mbc3.State,
    mapper_after: mbc3.State,
    value: u8,
) Access {
    return .{
        .logical_address = logical_address,
        .action = action,
        .region = region,
        .physical_offset = physical_offset,
        .mapper_before = mapper_before,
        .mapper_after = mapper_after,
        .value = value,
    };
}

fn makeDmaAccess(
    logical_address: u16,
    action: Action,
    mapper_before: mbc3.State,
    mapper_after: mbc3.State,
    value: u8,
    dma_class: hardware_dma.CpuAccess,
) Access {
    return makeAccess(
        logical_address,
        action,
        .system,
        null,
        mapper_before,
        mapper_after,
        value,
    ).withDmaClass(dma_class);
}

const Fixture = @import("cartridge_memory_test_support.zig").Fixture(
    cartridge_mod,
    header,
    Memory,
    SYSTEM_SIZE,
);

test "echo reads map E000 through FDFF onto C000 through DDFF" {
    var fixture = try Fixture.init(std.testing.allocator, 0);
    defer fixture.deinit(std.testing.allocator);
    const cases = [_]struct {
        echo: u16,
        canonical: u16,
        value: u8,
    }{
        .{ .echo = 0xe000, .canonical = 0xc000, .value = 0x12 },
        .{ .echo = 0xefff, .canonical = 0xcfff, .value = 0x34 },
        .{ .echo = 0xf000, .canonical = 0xd000, .value = 0x56 },
        .{ .echo = 0xfdff, .canonical = 0xddff, .value = 0x78 },
    };
    for (cases) |case| {
        fixture.system[case.canonical] = case.value;
        const result = try fixture.memory.read(case.echo);
        try std.testing.expectEqual(case.value, result.value);
        try std.testing.expectEqual(Region.system_echo, result.access.region);
        try std.testing.expectEqual(
            @as(?PhysicalOffset, case.canonical),
            result.access.physical_offset,
        );
        try std.testing.expectEqual(case.value, fixture.memory.data_bus);
        try std.testing.expectEqualDeep(
            result.access.mapper_before,
            result.access.mapper_after,
        );
    }
}

test "echo writes update canonical WRAM without storing an echo copy" {
    var fixture = try Fixture.init(std.testing.allocator, 0);
    defer fixture.deinit(std.testing.allocator);
    fixture.system[0xe000] = 0xa5;
    fixture.system[0xfdff] = 0xb6;

    const first = try fixture.memory.write(0xe000, 0x91);
    try std.testing.expectEqual(@as(u8, 0x91), fixture.system[0xc000]);
    try std.testing.expectEqual(@as(u8, 0xa5), fixture.system[0xe000]);
    try std.testing.expectEqual(Region.system_echo, first.region);
    try std.testing.expectEqual(@as(?PhysicalOffset, 0xc000), first.physical_offset);
    try std.testing.expectEqual(@as(u8, 0x91), fixture.memory.data_bus);

    const last = try fixture.memory.write(0xfdff, 0x37);
    try std.testing.expectEqual(@as(u8, 0x37), fixture.system[0xddff]);
    try std.testing.expectEqual(@as(u8, 0xb6), fixture.system[0xfdff]);
    try std.testing.expectEqual(@as(?PhysicalOffset, 0xddff), last.physical_offset);

    _ = try fixture.memory.write(0xd000, 0x42);
    try std.testing.expectEqual(
        @as(u8, 0x42),
        (try fixture.memory.read(0xf000)).value,
    );
}

test "unusable FEA0 through FEFF fails closed without changing the latch" {
    var fixture = try Fixture.init(std.testing.allocator, 0x6a);
    defer fixture.deinit(std.testing.allocator);
    const mapper = fixture.memory.mapper;
    fixture.system[UNUSABLE_START] = 0x12;
    fixture.system[UNUSABLE_END] = 0x34;

    for ([_]u16{ UNUSABLE_START, UNUSABLE_END }) |address| {
        try std.testing.expectError(
            error.UnusableAddress,
            fixture.memory.read(address),
        );
        try std.testing.expectEqual(@as(u8, 0x6a), fixture.memory.data_bus);
        try std.testing.expectEqualDeep(mapper, fixture.memory.mapper);
    }

    try std.testing.expectError(
        error.UnusableAddress,
        fixture.memory.write(UNUSABLE_START, 0x91),
    );
    try std.testing.expectError(
        error.UnusableAddress,
        fixture.memory.write(UNUSABLE_END, 0xa2),
    );
    try std.testing.expectEqual(@as(u8, 0x12), fixture.system[UNUSABLE_START]);
    try std.testing.expectEqual(@as(u8, 0x34), fixture.system[UNUSABLE_END]);
    try std.testing.expectEqual(@as(u8, 0x6a), fixture.memory.data_bus);
    try std.testing.expectEqualDeep(mapper, fixture.memory.mapper);
}

test "unattached MMIO remains ordinary system memory and ticks are inert" {
    var fixture = try Fixture.init(std.testing.allocator, 0);
    defer fixture.deinit(std.testing.allocator);
    fixture.system[hardware_joypad.P1_ADDRESS] = 0x12;
    fixture.system[DIV] = 0x34;
    fixture.system[INTERRUPT_FLAGS] = 1;

    for ([_]u16{ hardware_joypad.P1_ADDRESS, DIV }) |address| {
        const read = try fixture.memory.read(address);
        try std.testing.expectEqual(fixture.system[address], read.value);
        try std.testing.expectEqual(Region.system, read.access.region);
    }
    const write = try fixture.memory.write(TIMA, 0x56);
    try std.testing.expectEqual(Region.system, write.region);
    fixture.memory.tickMcycle();
    try std.testing.expectEqual(@as(u8, 0x56), fixture.system[TIMA]);
    try std.testing.expectEqual(@as(u8, 1), fixture.system[INTERRUPT_FLAGS]);
}

test "timer MMIO routes all registers and one-cycle ticks request IF" {
    var fixture = try Fixture.init(std.testing.allocator, 0);
    defer fixture.deinit(std.testing.allocator);
    var timer = hardware_timer.Timer{
        .div_counter = 12,
        .tima = 0xff,
        .tma = 0x42,
        .tac = 0x05,
    };
    fixture.system[INTERRUPT_FLAGS] = 1;
    fixture.memory.attachTimer(&timer);

    const tac = try fixture.memory.read(TAC);
    try std.testing.expectEqual(@as(u8, 0xfd), tac.value);
    try std.testing.expectEqual(Region.timer_mmio, tac.access.region);
    try std.testing.expectEqual(@as(?PhysicalOffset, null), tac.access.physical_offset);

    fixture.memory.tickMcycle();
    try std.testing.expectEqual(hardware_timer.ReloadState.reloading, timer.reload_state);
    try std.testing.expectEqual(@as(u8, 0), fixture.system[TIMA]);
    try std.testing.expectEqual(@as(u8, 1), fixture.system[INTERRUPT_FLAGS]);
    fixture.memory.tickMcycle();
    try std.testing.expectEqual(@as(u8, 0x42), fixture.system[TIMA]);
    try std.testing.expectEqual(
        @as(u8, 1 | hardware_timer.TIMER_INTERRUPT),
        fixture.system[INTERRUPT_FLAGS],
    );
    fixture.memory.tickMcycle();

    for ([_]struct { address: u16, value: u8 }{
        .{ .address = DIV, .value = 0xaa },
        .{ .address = TIMA, .value = 0x77 },
        .{ .address = TMA, .value = 0x66 },
        .{ .address = TAC, .value = 0x06 },
    }) |write_case| {
        const access = try fixture.memory.write(
            write_case.address,
            write_case.value,
        );
        try std.testing.expectEqual(Region.timer_mmio, access.region);
        try std.testing.expectEqual(write_case.value, access.value);
    }
    try std.testing.expectEqual(@as(u16, 0), timer.div_counter);
    try std.testing.expectEqual(@as(u8, 0x77), timer.tima);
    try std.testing.expectEqual(@as(u8, 0x66), timer.tma);
    try std.testing.expectEqual(@as(u3, 0x06), timer.tac);
    try std.testing.expectEqual(@as(u8, 0x06), fixture.system[TAC]);
}

test "joypad MMIO and committed actions propagate selected-line interrupts" {
    var fixture = try Fixture.init(std.testing.allocator, 0);
    defer fixture.deinit(std.testing.allocator);
    var invalid = hardware_joypad.State{ .p1 = 0 };
    try std.testing.expectError(
        error.InvalidHighBits,
        fixture.memory.attachJoypad(&invalid),
    );

    const right = hardware_joypad.Key.right.mask();
    var joypad = try hardware_joypad.State.init(0xff, right, 3, 0);
    try fixture.memory.attachJoypad(&joypad);
    try std.testing.expectEqual(
        @as(u8, 0xff),
        (try fixture.memory.read(hardware_joypad.P1_ADDRESS)).value,
    );
    const select = try fixture.memory.write(
        hardware_joypad.P1_ADDRESS,
        0x20,
    );
    try std.testing.expectEqual(Region.joypad_mmio, select.region);
    try std.testing.expectEqual(@as(u8, 0x20), select.value);
    try std.testing.expectEqual(@as(u8, 0xee), joypad.readP1());
    try std.testing.expectEqual(@as(u8, 0xee), fixture.system[hardware_joypad.P1_ADDRESS]);
    try std.testing.expect(
        fixture.system[INTERRUPT_FLAGS] &
            hardware_joypad.JOYPAD_INTERRUPT != 0,
    );

    fixture.system[INTERRUPT_FLAGS] = hardware_timer.TIMER_INTERRUPT;
    try fixture.memory.setJoypadPressed(0);
    try fixture.memory.setJoypadPressed(right);
    try std.testing.expectEqual(
        hardware_timer.TIMER_INTERRUPT | hardware_joypad.JOYPAD_INTERRUPT,
        fixture.system[INTERRUPT_FLAGS],
    );
    fixture.memory.detachJoypad();
    try std.testing.expectError(
        error.JoypadNotAttached,
        fixture.memory.setJoypadPressed(0),
    );
}

fn expectAccess(
    actual: Access,
    logical_address: u16,
    action: Action,
    region: Region,
    physical_offset: ?PhysicalOffset,
    mapper_before: mbc3.State,
    mapper_after: mbc3.State,
    value: u8,
) !void {
    try std.testing.expectEqual(logical_address, actual.logical_address);
    try std.testing.expectEqual(action, actual.action);
    try std.testing.expectEqual(region, actual.region);
    try std.testing.expectEqual(physical_offset, actual.physical_offset);
    try std.testing.expectEqualDeep(mapper_before, actual.mapper_before);
    try std.testing.expectEqualDeep(mapper_after, actual.mapper_after);
    try std.testing.expectEqual(value, actual.value);
}
