const std = @import("std");
const cartridge = @import("cartridge/mod.zig");
const machine = @import("runner/machine.zig");
const runner = @import("runner/mod.zig");

const PROGRAM_START: u16 = 0x0200;
const DIV: u16 = 0xff04;
const IF: u16 = 0xff0f;
const IE: u16 = 0xffff;
const TIMA: u16 = 0xff05;
const TMA: u16 = 0xff06;
const TAC: u16 = 0xff07;

const Fixture = struct {
    rom: *[cartridge.header.ROM_SIZE]u8,
    sram: *[cartridge.header.RAM_SIZE]u8,
    system: *[runner.cartridge_memory.SYSTEM_SIZE]u8,
    flat: runner.Memory,
    cartridge_memory: runner.cartridge_memory.Memory,

    fn init(program: []const u8) !Fixture {
        const allocator = std.testing.allocator;
        const rom = try allocator.create([cartridge.header.ROM_SIZE]u8);
        errdefer allocator.destroy(rom);
        const sram = try allocator.create([cartridge.header.RAM_SIZE]u8);
        errdefer allocator.destroy(sram);
        const system = try allocator.create(
            [runner.cartridge_memory.SYSTEM_SIZE]u8,
        );
        errdefer allocator.destroy(system);
        var flat = try runner.Memory.init(allocator);
        errdefer flat.deinit();
        @memset(rom, 0);
        @memset(sram, 0);
        @memset(system, 0);
        @memcpy(
            rom[PROGRAM_START .. PROGRAM_START + program.len],
            program,
        );
        @memcpy(
            flat.bytes[PROGRAM_START .. PROGRAM_START + program.len],
            program,
        );
        rom[cartridge.header.CARTRIDGE_TYPE_OFFSET] =
            cartridge.header.CARTRIDGE_TYPE_MBC3_RAM_BATTERY;
        rom[cartridge.header.ROM_SIZE_CODE_OFFSET] =
            cartridge.header.ROM_SIZE_CODE_1_MIB;
        rom[cartridge.header.RAM_SIZE_CODE_OFFSET] =
            cartridge.header.RAM_SIZE_CODE_32_KIB;
        rom[cartridge.header.HEADER_CHECKSUM_OFFSET] =
            cartridge.header.headerChecksum(rom);
        std.mem.writeInt(
            u16,
            rom[cartridge.header.GLOBAL_CHECKSUM_OFFSET..cartridge.header.HEADER_END][0..2],
            cartridge.header.globalChecksum(rom),
            .big,
        );
        const loaded = try cartridge.Cartridge.init(rom);
        return .{
            .rom = rom,
            .sram = sram,
            .system = system,
            .flat = flat,
            .cartridge_memory = runner.cartridge_memory.Memory.init(
                loaded,
                sram,
                system,
                .{},
                0xff,
            ),
        };
    }

    fn deinit(self: *Fixture) void {
        const allocator = std.testing.allocator;
        self.flat.deinit();
        allocator.destroy(self.system);
        allocator.destroy(self.sram);
        allocator.destroy(self.rom);
        self.* = undefined;
    }

    fn write(self: *Fixture, address: u16, value: u8) void {
        self.flat.write(address, value);
        self.system[address] = value;
    }
};

test "cartridge restore preserves complete timer and HALT checkpoint" {
    var fixture = try Fixture.init(&.{0x00});
    defer fixture.deinit();
    const checkpoint = runner.timer.Timer{
        .div_counter = 0xabcc,
        .tima = 0x42,
        .tma = 0x31,
        .tac = 0x05,
        .reload_state = .reloaded,
    };
    const restored = try machine.CartridgeMachine.restore(
        &fixture.cartridge_memory,
        .{ .pc = PROGRAM_START, .halted = true },
        checkpoint,
        true,
    );
    try std.testing.expectEqualDeep(checkpoint, restored.timer);
    try std.testing.expect(restored.cpu.halted);
    try std.testing.expect(restored.halt_bug);
    try std.testing.expectEqual(@as(u8, 0xab), fixture.system[DIV]);

    var attached = runner.timer.Timer{};
    fixture.cartridge_memory.attachTimer(&attached);
    defer fixture.cartridge_memory.detachTimer();
    try std.testing.expectError(
        error.TimerAlreadyAttached,
        machine.CartridgeMachine.restore(
            &fixture.cartridge_memory,
            .{},
            checkpoint,
            false,
        ),
    );
}

test "cartridge scheduler mirrors flat instruction and timer transitions" {
    var fixture = try Fixture.init(&.{
        0x3e, 0x42, // LD A,42
        0xea, 0x00, 0xc0, // LD (C000),A
        0x00, // NOP
    });
    defer fixture.deinit();
    fixture.write(TIMA, 0xff);
    fixture.write(TMA, 0x31);
    fixture.write(TAC, 0x05);
    var flat = machine.Machine.init(
        &fixture.flat,
        .{ .pc = PROGRAM_START },
    );
    var attached = try machine.CartridgeMachine.init(
        &fixture.cartridge_memory,
        .{ .pc = PROGRAM_START },
    );
    flat.timer.div_counter = 0x000f;
    attached.timer.div_counter = 0x000f;

    for (0..3) |_| {
        const expected = try flat.step();
        const actual = try attached.step();
        try expectEquivalent(expected, actual);
        try std.testing.expect(actual.hasCanonicalShape());
        try expectSynchronized(&fixture, flat, attached);
    }
    try std.testing.expectEqual(@as(u8, 0x42), fixture.system[0xc000]);
    try std.testing.expectEqual(@as(u8, 0x42), fixture.flat.read(0xc000));
}

test "cartridge scheduler mirrors HALT idle wake and following instruction" {
    var fixture = try Fixture.init(&.{0x00});
    defer fixture.deinit();
    fixture.write(IE, 1);
    var flat = machine.Machine.init(
        &fixture.flat,
        .{ .pc = PROGRAM_START, .halted = true },
    );
    var attached = try machine.CartridgeMachine.init(
        &fixture.cartridge_memory,
        .{ .pc = PROGRAM_START, .halted = true },
    );

    const idle = try attached.step();
    try expectEquivalent(try flat.step(), idle);
    try std.testing.expectEqual(machine.SchedulerEvent.halt_idle, idle.event);
    try std.testing.expect(idle.hasCanonicalShape());
    try std.testing.expectEqualDeep(idle.mapper_before, idle.mapper_after);

    fixture.write(IF, 1);
    const wake = try attached.step();
    try expectEquivalent(try flat.step(), wake);
    try std.testing.expectEqual(machine.SchedulerEvent.halt_wake, wake.event);
    try std.testing.expect(wake.hasCanonicalShape());

    const instruction = try attached.step();
    try expectEquivalent(try flat.step(), instruction);
    try std.testing.expectEqual(
        machine.SchedulerEvent.instruction,
        instruction.event,
    );
    try std.testing.expect(instruction.hasCanonicalShape());
    var dirty_idle = idle;
    dirty_idle.service.cycles[0] = .{
        .kind = .dummy_read,
        .access = instruction.instruction.?.accesses[0],
    };
    try std.testing.expect(!dirty_idle.hasCanonicalShape());
    try expectSynchronized(&fixture, flat, attached);
}

test "cartridge HALT and service advance attached devices by exact M-cycles" {
    var fixture = try Fixture.init(&.{0x00});
    defer fixture.deinit();
    var ppu = runner.ppu_mmio.State{
        .timing = .{
            .lcd_enabled = true,
            .coincidence = true,
            .lyc_interrupt_line = true,
        },
        .lcdc = 0x80,
    };
    try fixture.cartridge_memory.attachPpu(&ppu);
    defer fixture.cartridge_memory.detachPpu();
    var attached = try machine.CartridgeMachine.init(
        &fixture.cartridge_memory,
        .{ .pc = PROGRAM_START, .sp = 0xc000, .halted = true },
    );

    const idle = try attached.step();
    try std.testing.expectEqual(@as(u3, 1), idle.m_cycles);
    try std.testing.expectEqual(@as(u16, 4), ppu.timing.dot);

    fixture.system[IE] = 1;
    fixture.system[IF] = 0;
    ppu.timing = .{
        .lcd_enabled = true,
        .line = 144,
        .dot = 0,
    };
    ppu.interrupt_flags = 0;
    attached.cpu.ime = true;
    const wake = try attached.step();
    try std.testing.expectEqual(
        machine.SchedulerEvent.halt_wake,
        wake.event,
    );
    try std.testing.expectEqual(@as(u3, 1), wake.m_cycles);
    try std.testing.expectEqual(@as(u16, 4), ppu.timing.dot);
    try std.testing.expectEqual(@as(u8, 1), fixture.system[IF]);
    try std.testing.expect(wake.hasCanonicalShape());

    const service = try attached.step();
    try std.testing.expectEqual(
        machine.SchedulerEvent.interrupt_service,
        service.event,
    );
    try std.testing.expectEqual(@as(u3, 5), service.m_cycles);
    try std.testing.expectEqual(@as(u16, 24), ppu.timing.dot);
    try std.testing.expectEqual(@as(u16, 0x0040), attached.cpu.pc);
    try std.testing.expectEqual(@as(u8, 0), fixture.system[IF]);
    try std.testing.expect(service.hasCanonicalShape());
}

test "cartridge scheduler preserves interrupt service metadata and aliases" {
    const cases = [_]struct {
        pc: u16,
        sp: u16,
        ie: u8,
        interrupt_flags: u8,
        halted: bool,
        index: ?u3,
        m_cycles: u3,
    }{
        .{
            .pc = 0x2345,
            .sp = 0xc102,
            .ie = 1,
            .interrupt_flags = 1,
            .halted = false,
            .index = 0,
            .m_cycles = 5,
        },
        .{
            .pc = 0x2345,
            .sp = 0xc102,
            .ie = 1,
            .interrupt_flags = 1,
            .halted = true,
            .index = 0,
            .m_cycles = 6,
        },
        .{
            .pc = 0,
            .sp = 0,
            .ie = 1,
            .interrupt_flags = 1,
            .halted = false,
            .index = null,
            .m_cycles = 5,
        },
        .{
            .pc = 0x0200,
            .sp = 0,
            .ie = 1,
            .interrupt_flags = 3,
            .halted = false,
            .index = 1,
            .m_cycles = 5,
        },
    };
    for (cases) |case| {
        var fixture = try Fixture.init(&.{0x00});
        defer fixture.deinit();
        fixture.write(IE, case.ie);
        fixture.write(IF, case.interrupt_flags);
        const cpu = runner.Cpu{
            .pc = case.pc,
            .sp = case.sp,
            .ime = true,
            .halted = case.halted,
        };
        var flat = machine.Machine.init(&fixture.flat, cpu);
        var attached = try machine.CartridgeMachine.init(
            &fixture.cartridge_memory,
            cpu,
        );
        const expected = try flat.step();
        const actual = try attached.step();
        try expectEquivalent(expected, actual);
        try std.testing.expectEqual(
            machine.SchedulerEvent.interrupt_service,
            actual.event,
        );
        try std.testing.expectEqual(case.index, actual.interrupt_index);
        try std.testing.expectEqual(case.m_cycles, actual.m_cycles);
        try std.testing.expectEqual(case.m_cycles, actual.service.count);
        try std.testing.expect(actual.hasCanonicalShape());
        try expectSynchronized(&fixture, flat, attached);
    }
}

test "cartridge HALT bug duplicates opcode fetch with mapper metadata" {
    var fixture = try Fixture.init(&.{
        0x76, // HALT
        0x06, // LD B,d8
        0x99,
    });
    defer fixture.deinit();
    fixture.write(IE, 1);
    fixture.write(IF, 1);
    const cpu = runner.Cpu{ .pc = PROGRAM_START };
    var flat = machine.Machine.init(&fixture.flat, cpu);
    var attached = try machine.CartridgeMachine.init(
        &fixture.cartridge_memory,
        cpu,
    );

    const halt = try attached.step();
    try expectEquivalent(try flat.step(), halt);
    try std.testing.expect(halt.after.halt_bug);
    try std.testing.expect(halt.hasCanonicalShape());

    const duplicated = try attached.step();
    try expectEquivalent(try flat.step(), duplicated);
    try std.testing.expectEqual(@as(u8, 0x06), duplicated.after.cpu.b);
    try std.testing.expectEqual(
        duplicated.instruction.?.instruction.cycles[0].address,
        duplicated.instruction.?.instruction.cycles[1].address,
    );
    try std.testing.expectEqual(
        duplicated.instruction.?.accesses[0].?.physical_offset,
        duplicated.instruction.?.accesses[1].?.physical_offset,
    );
    try std.testing.expect(duplicated.hasCanonicalShape());
}

test "cartridge result rejects event and access metadata mutations" {
    var fixture = try Fixture.init(&.{0x00});
    defer fixture.deinit();
    fixture.write(IE, 1);
    fixture.write(IF, 1);
    var attached = try machine.CartridgeMachine.init(
        &fixture.cartridge_memory,
        .{ .pc = 0x2345, .sp = 0xc102, .ime = true },
    );
    const honest = try attached.step();
    try std.testing.expect(honest.hasCanonicalShape());

    var forged = honest;
    forged.mapper_before.rom_bank_register +%= 1;
    try std.testing.expect(!forged.hasCanonicalShape());
    forged = honest;
    forged.mapper_after.rom_bank_register +%= 1;
    try std.testing.expect(!forged.hasCanonicalShape());
    const honest_projection = honest.schedulerResult();
    try std.testing.expectEqualDeep(
        honest_projection,
        forged.schedulerResult(),
    );
    forged = honest;
    forged.m_cycles = 4;
    try std.testing.expect(!forged.hasCanonicalShape());
    forged = honest;
    forged.service.count = 4;
    try std.testing.expect(!forged.hasCanonicalShape());
    forged = honest;
    forged.service.cycles[0].access.?.logical_address +%= 1;
    try std.testing.expect(!forged.hasCanonicalShape());
    forged = honest;
    forged.service.cycles[3].access.?.value +%= 1;
    try std.testing.expect(!forged.hasCanonicalShape());
    forged = honest;
    forged.service.cycles[1].kind = .no_access;
    try std.testing.expect(!forged.hasCanonicalShape());
    forged = honest;
    forged.service.cycles[3].access.?.mapper_before.rom_bank_register = 7;
    try std.testing.expect(!forged.hasCanonicalShape());

    var instruction_fixture = try Fixture.init(&.{0x00});
    defer instruction_fixture.deinit();
    var instruction_machine = try machine.CartridgeMachine.init(
        &instruction_fixture.cartridge_memory,
        .{ .pc = PROGRAM_START },
    );
    const instruction = try instruction_machine.step();
    try std.testing.expect(instruction.hasCanonicalShape());
    forged = instruction;
    forged.mapper_before.rom_bank_register +%= 1;
    try std.testing.expect(!forged.hasCanonicalShape());
    forged = instruction;
    forged.mapper_after.rom_bank_register +%= 1;
    try std.testing.expect(!forged.hasCanonicalShape());
    forged = instruction;
    forged.instruction.?.accesses[0].?.logical_address +%= 1;
    try std.testing.expect(!forged.hasCanonicalShape());
    forged = instruction;
    forged.instruction.?.accesses[0].?.value +%= 1;
    try std.testing.expect(!forged.hasCanonicalShape());
    forged = instruction;
    forged.instruction.?.accesses[5] =
        forged.instruction.?.accesses[0];
    try std.testing.expect(!forged.hasCanonicalShape());

    var halt_fixture = try Fixture.init(&.{0x00});
    defer halt_fixture.deinit();
    var halt_machine = try machine.CartridgeMachine.init(
        &halt_fixture.cartridge_memory,
        .{ .pc = PROGRAM_START, .halted = true },
    );
    const idle = try halt_machine.step();
    try std.testing.expect(idle.hasCanonicalShape());
    forged = idle;
    forged.mapper_after.rom_bank_register +%= 1;
    try std.testing.expect(!forged.hasCanonicalShape());
}

test "cartridge machine rejects an already attached timer" {
    var fixture = try Fixture.init(&.{0x00});
    defer fixture.deinit();
    var external_timer = runner.timer.Timer{};
    fixture.cartridge_memory.attachTimer(&external_timer);
    defer fixture.cartridge_memory.detachTimer();
    try std.testing.expectError(
        error.TimerAlreadyAttached,
        machine.CartridgeMachine.init(
            &fixture.cartridge_memory,
            .{ .pc = PROGRAM_START },
        ),
    );
}

fn expectEquivalent(
    expected: machine.StepResult,
    actual: machine.CartridgeStepResult,
) !void {
    const projected = actual.schedulerResult();
    try std.testing.expectEqualDeep(expected.before, projected.before);
    try std.testing.expectEqualDeep(expected.after, projected.after);
    try std.testing.expectEqual(expected.event, projected.event);
    try std.testing.expectEqual(expected.m_cycles, projected.m_cycles);
    try std.testing.expectEqual(
        expected.interrupt_index,
        projected.interrupt_index,
    );
    if (expected.instruction) |expected_instruction| {
        const actual_instruction = projected.instruction orelse
            return error.TestExpectedEqual;
        try std.testing.expectEqualDeep(
            expected_instruction.before,
            actual_instruction.before,
        );
        try std.testing.expectEqualDeep(
            expected_instruction.after,
            actual_instruction.after,
        );
        try std.testing.expectEqualDeep(
            expected_instruction.decoded,
            actual_instruction.decoded,
        );
        try std.testing.expectEqual(
            expected_instruction.cycle_count,
            actual_instruction.cycle_count,
        );
        try std.testing.expectEqualSlices(
            runner.BusCycle,
            expected_instruction.activeCycles(),
            actual_instruction.activeCycles(),
        );
    } else {
        try std.testing.expect(projected.instruction == null);
    }
}

fn expectSynchronized(
    fixture: *Fixture,
    flat: machine.Machine,
    attached: machine.CartridgeMachine,
) !void {
    try std.testing.expectEqualDeep(flat.cpu, attached.cpu);
    try std.testing.expectEqualDeep(flat.timer, attached.timer);
    inline for (.{ IF, IE, TIMA, TMA, TAC, @as(u16, 0xc000) }) |address|
        try std.testing.expectEqual(
            fixture.flat.read(address),
            fixture.system[address],
        );
}
