const std = @import("std");
const subject = @import("dma_binding.zig");
const runner = @import("../runner/mod.zig");
const machine = @import("../runner/machine.zig");
const dma = @import("../runner/dma.zig");
const memory = runner.cartridge_memory;
const cartridge = @import("../cartridge/mod.zig");
const mapper = @import("../cartridge/mbc3.zig");

const PROGRAM_START: u16 = 0x0200;
const IF: u16 = 0xff0f;
const IE: u16 = 0xffff;

test "DMA binding derives FF46 restart and transfer memory obligations" {
    const steps = [_]runner.CartridgeStepTrace{
        accessStep(dma.DMA_ADDRESS, .write, 0xc0),
        idleTailStep(),
        accessStep(dma.DMA_ADDRESS, .write, 0xd0),
        systemStep(0xff80),
    };
    var trace = try subject.generateTrace(
        std.testing.allocator,
        10,
        15,
        .{ .clock = 10 },
        &steps,
        &.{ 0x42, 0x43 },
    );
    defer trace.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 5), trace.rows.len);
    try std.testing.expectEqual(@as(u32, 15), trace.final_mcycle);
    try std.testing.expect(
        trace.rows[2].transition.transfer != null,
    );
    try std.testing.expectEqual(
        dma.Event{ .transfer_and_write = .{
            .source_byte = 0x43,
            .page = 0xd0,
        } },
        trace.rows[3].transition.event,
    );
    const access = (try subject.transferAccess(trace.rows[2])).?;
    try std.testing.expectEqual(@as(u16, 0xc000), access.source_address);
    try std.testing.expectEqual(@as(u16, 0xfe00), access.destination_address);
    try std.testing.expectEqual(@as(u8, 0x42), access.value);

    var witness = try subject.generateWitness(
        std.testing.allocator,
        trace,
        &steps,
    );
    defer witness.deinit();
    try std.testing.expectEqual(@as(u32, 4), witness.log_size);
}

test "DMA binding fails closed on blocked CPU access and source arity" {
    try std.testing.expectError(
        error.InvalidDmaAccessMetadata,
        subject.generateTrace(
            std.testing.allocator,
            2,
            3,
            .{
                .clock = 2,
                .page = 0xc0,
                .copied = 1,
                .phase = .transfer,
            },
            &.{systemStep(0xc000)},
            &.{0x11},
        ),
    );
    try std.testing.expectError(
        error.MissingDmaSourceByte,
        subject.generateTrace(
            std.testing.allocator,
            2,
            3,
            .{
                .clock = 2,
                .page = 0xc0,
                .phase = .transfer,
            },
            &.{systemStep(0xff80)},
            &.{},
        ),
    );
}

test "DMA binding uses post-transition read and write blocking boundaries" {
    const first_read = accessStepWithClass(
        0xc123,
        .read,
        0x55,
        .blocked_source_bus,
    );
    try std.testing.expectError(
        error.UnsupportedBlockedCpuAccess,
        subject.generateTrace(
            std.testing.allocator,
            10,
            11,
            .{
                .clock = 10,
                .page = 0xc0,
                .phase = .transfer,
            },
            &.{first_read},
            &.{0xf0},
        ),
    );
    const first_write = accessStepWithClass(
        0xc000,
        .write,
        0x0f,
        .blocked_source_bus,
    );
    try std.testing.expectError(
        error.UnsupportedBlockedCpuAccess,
        subject.generateTrace(
            std.testing.allocator,
            20,
            21,
            .{
                .clock = 20,
                .page = 0xc0,
                .phase = .transfer,
            },
            &.{first_write},
            &.{0xf0},
        ),
    );
    try std.testing.expectError(
        error.InvalidDmaAccessMetadata,
        subject.generateTrace(
            std.testing.allocator,
            30,
            31,
            .{
                .clock = 30,
                .page = 0xc0,
                .phase = .transfer,
            },
            &.{accessStep(0xc123, .read, 0x55)},
            &.{0xf0},
        ),
    );

    var finish = try subject.generateTrace(
        std.testing.allocator,
        40,
        41,
        .{
            .clock = 40,
            .page = 0xc0,
            .copied = dma.OAM_LENGTH,
            .phase = .finishing,
        },
        &.{systemStep(0xc123)},
        &.{},
    );
    defer finish.deinit(std.testing.allocator);
    try std.testing.expectEqual(dma.Phase.idle, finish.final_state.phase);

    var warm_read = try subject.generateTrace(
        std.testing.allocator,
        50,
        51,
        .{
            .clock = 50,
            .page = 0xc0,
            .phase = .startup,
        },
        &.{accessStep(dma.OAM_START, .read, 0x77)},
        &.{},
    );
    defer warm_read.deinit(std.testing.allocator);
    const warm_write = accessStepWithClass(
        dma.OAM_START,
        .write,
        0x11,
        .blocked_oam,
    );
    try std.testing.expectError(
        error.UnsupportedBlockedCpuAccess,
        subject.generateTrace(
            std.testing.allocator,
            60,
            61,
            .{
                .clock = 60,
                .page = 0xc0,
                .phase = .startup,
            },
            &.{warm_write},
            &.{},
        ),
    );
}

test "DMA binding rejects CPU-class metadata relabeling" {
    var relabeled = systemStep(0xff80);
    relabeled.accesses[0].?.dma_class = .blocked_source_bus;
    try std.testing.expectError(
        error.InvalidDmaAccessMetadata,
        subject.generateTrace(
            std.testing.allocator,
            70,
            71,
            .{ .clock = 70 },
            &.{relabeled},
            &.{},
        ),
    );
}

test "DMA binding consumes canonical instruction HALT and wake M-cycles" {
    var fixture = try Fixture.init(&.{0x00});
    defer fixture.deinit();

    var scheduler = try machine.CartridgeMachine.init(
        &fixture.memory,
        .{ .pc = PROGRAM_START },
    );
    const instruction = try scheduler.step();
    try std.testing.expectEqual(
        machine.SchedulerEvent.instruction,
        instruction.event,
    );
    try expectMachineTrace(
        &.{instruction},
        .{
            .clock = 20,
            .page = 0x80,
            .copied = 1,
            .phase = .transfer,
        },
        &.{0x11},
    );

    scheduler = try machine.CartridgeMachine.init(
        &fixture.memory,
        .{ .pc = PROGRAM_START, .halted = true },
    );
    const idle = try scheduler.step();
    try std.testing.expectEqual(machine.SchedulerEvent.halt_idle, idle.event);
    try std.testing.expectError(
        error.UnsupportedActiveDmaHalt,
        subject.generateFromMachineExecution(
            std.testing.allocator,
            30,
            31,
            .{
                .clock = 30,
                .page = 0xc0,
                .copied = 1,
                .phase = .transfer,
            },
            &.{idle},
            &.{0x22},
        ),
    );
    var forged_halt = try subject.generateFromMachineExecution(
        std.testing.allocator,
        30,
        31,
        .{ .clock = 30 },
        &.{idle},
        &.{},
    );
    defer forged_halt.deinit(std.testing.allocator);
    const forged_transition = try dma.Transition.apply(
        .{
            .clock = 30,
            .page = 0xc0,
            .copied = 1,
            .phase = .transfer,
        },
        .{ .transfer = 0x22 },
    );
    forged_halt.rows[0].transition = forged_transition;
    forged_halt.final_state = forged_transition.after;
    try std.testing.expectError(
        error.UnsupportedActiveDmaHalt,
        subject.generateMachineExecutionWitness(
            std.testing.allocator,
            forged_halt,
            &.{idle},
        ),
    );

    fixture.system[IE] = 1;
    fixture.system[IF] = 1;
    scheduler = try machine.CartridgeMachine.init(
        &fixture.memory,
        .{ .pc = PROGRAM_START, .halted = true },
    );
    const wake = try scheduler.step();
    try std.testing.expectEqual(machine.SchedulerEvent.halt_wake, wake.event);
    try std.testing.expectError(
        error.UnsupportedActiveDmaHalt,
        subject.generateFromMachineExecution(
            std.testing.allocator,
            40,
            41,
            .{
                .clock = 40,
                .page = 0xc0,
                .copied = 1,
                .phase = .transfer,
            },
            &.{wake},
            &.{0x33},
        ),
    );
}

test "DMA machine witness rejects state clock and provenance mutations" {
    var fixture = try Fixture.init(&.{0x00});
    defer fixture.deinit();
    var scheduler = try machine.CartridgeMachine.init(
        &fixture.memory,
        .{ .pc = PROGRAM_START },
    );
    const result = try scheduler.step();
    const initial = dma.State{ .clock = 50 };
    var trace = try subject.generateFromMachineExecution(
        std.testing.allocator,
        50,
        51,
        initial,
        &.{result},
        &.{},
    );
    defer trace.deinit(std.testing.allocator);

    var witness = try subject.generateMachineExecutionWitness(
        std.testing.allocator,
        trace,
        &.{result},
    );
    witness.deinit();

    var forged_result = result;
    forged_result.before.cpu.a +%= 1;
    try std.testing.expectError(
        error.InvalidSchedulerStep,
        subject.generateMachineExecutionWitness(
            std.testing.allocator,
            trace,
            &.{forged_result},
        ),
    );

    trace.rows[0].provenance.cycle = 1;
    try std.testing.expectError(
        error.DisconnectedDmaTrace,
        subject.generateMachineExecutionWitness(
            std.testing.allocator,
            trace,
            &.{result},
        ),
    );
    trace.rows[0].provenance.cycle = 0;

    trace.rows[0].mcycle += 1;
    try std.testing.expectError(
        error.DisconnectedDmaTrace,
        subject.generateMachineExecutionWitness(
            std.testing.allocator,
            trace,
            &.{result},
        ),
    );
    trace.rows[0].mcycle -= 1;

    trace.rows[0].transition.after.clock += 1;
    try std.testing.expectError(
        error.InvalidDmaTransition,
        subject.generateMachineExecutionWitness(
            std.testing.allocator,
            trace,
            &.{result},
        ),
    );
    trace.rows[0].transition.after.clock -= 1;

    trace.final_state.page -%= 1;
    try std.testing.expectError(
        error.InvalidDmaTraceEndpoint,
        subject.generateMachineExecutionWitness(
            std.testing.allocator,
            trace,
            &.{result},
        ),
    );
}

test "DMA binding schedules pinned service cycles and FF46 stack alias" {
    var fixture = try Fixture.init(&.{0x00});
    defer fixture.deinit();
    fixture.system[IE] = 1;
    fixture.system[IF] = 1;
    var scheduler = try machine.CartridgeMachine.init(
        &fixture.memory,
        .{
            .pc = PROGRAM_START,
            .sp = 0xfffe,
            .ime = true,
        },
    );
    const service = try scheduler.step();
    try std.testing.expectEqual(
        machine.SchedulerEvent.interrupt_service,
        service.event,
    );
    try std.testing.expectEqual(service.m_cycles, service.service.count);
    try expectMachineTrace(
        &.{service},
        .{
            .clock = 60,
            .page = 0x80,
            .copied = 1,
            .phase = .transfer,
        },
        &.{ 1, 2, 3, 4, 5 },
    );

    fixture.system[IE] = 1;
    fixture.system[IF] = 1;
    scheduler = try machine.CartridgeMachine.init(
        &fixture.memory,
        .{
            .pc = 0x1200,
            .sp = dma.DMA_ADDRESS + 1,
            .ime = true,
        },
    );
    const alias = try scheduler.step();
    var trace = try subject.generateFromMachineExecution(
        std.testing.allocator,
        70,
        75,
        .{ .clock = 70 },
        &.{alias},
        &.{},
    );
    defer trace.deinit(std.testing.allocator);
    try std.testing.expectEqual(
        dma.Event{ .write_ff46 = 0x12 },
        trace.rows[3].transition.event,
    );
    try std.testing.expectEqual(
        dma.Event.tick,
        trace.rows[4].transition.event,
    );
}

test "DMA binding rejects blocked pinned service bus cycle" {
    var fixture = try Fixture.init(&.{0x00});
    defer fixture.deinit();
    fixture.system[IE] = 1;
    fixture.system[IF] = 1;
    var scheduler = try machine.CartridgeMachine.init(
        &fixture.memory,
        .{
            .pc = PROGRAM_START,
            .sp = 0x8002,
            .ime = true,
        },
    );
    const service = try scheduler.step();
    try std.testing.expectError(
        error.InvalidDmaAccessMetadata,
        subject.generateFromMachineExecution(
            std.testing.allocator,
            80,
            85,
            .{
                .clock = 80,
                .page = 0x80,
                .copied = 1,
                .phase = .transfer,
            },
            &.{service},
            &.{ 1, 2, 3, 4, 5 },
        ),
    );
}

fn idleTailStep() runner.CartridgeStepTrace {
    var result = systemStep(0xff80);
    result.instruction.cycle_count = 2;
    result.instruction.cycles[1] = .{
        .address = 0xff80,
        .value = 0,
        .action = .idle,
    };
    return result;
}

fn systemStep(address: u16) runner.CartridgeStepTrace {
    return accessStep(address, .read, 0);
}

fn accessStep(
    address: u16,
    action: memory.Action,
    value: u8,
) runner.CartridgeStepTrace {
    return accessStepWithClass(address, action, value, .allowed);
}

fn accessStepWithClass(
    address: u16,
    action: memory.Action,
    value: u8,
    dma_class: dma.CpuAccess,
) runner.CartridgeStepTrace {
    var result: runner.CartridgeStepTrace = undefined;
    result.instruction.cycle_count = 1;
    result.instruction.cycles[0] = .{
        .address = address,
        .value = value,
        .action = switch (action) {
            .read => .read,
            .write => .write,
        },
    };
    result.accesses = [_]?memory.Access{null} ** 6;
    result.accesses[0] = .{
        .logical_address = address,
        .action = action,
        .region = .system,
        .physical_offset = null,
        .mapper_before = mapper.State{},
        .mapper_after = mapper.State{},
        .value = value,
        .dma_class = dma_class,
    };
    return result;
}

fn expectMachineTrace(
    results: []const machine.CartridgeStepResult,
    initial: dma.State,
    source_bytes: []const u8,
) !void {
    var cycle_count: u32 = 0;
    for (results) |result| cycle_count += result.m_cycles;
    const final_mcycle = initial.clock + cycle_count;
    var trace = try subject.generateFromMachineExecution(
        std.testing.allocator,
        initial.clock,
        final_mcycle,
        initial,
        results,
        source_bytes,
    );
    defer trace.deinit(std.testing.allocator);
    try std.testing.expectEqual(
        @as(usize, @intCast(cycle_count)),
        trace.rows.len,
    );
    var at: usize = 0;
    for (results, 0..) |result, execution_row| {
        for (0..result.m_cycles) |cycle| {
            try std.testing.expectEqual(
                @as(u32, @intCast(execution_row)),
                trace.rows[at].provenance.execution_row,
            );
            try std.testing.expectEqual(
                @as(u3, @intCast(cycle)),
                trace.rows[at].provenance.cycle,
            );
            at += 1;
        }
    }
    var witness = try subject.generateMachineExecutionWitness(
        std.testing.allocator,
        trace,
        results,
    );
    witness.deinit();
}

const Fixture = struct {
    rom: *[cartridge.header.ROM_SIZE]u8,
    sram: *[cartridge.header.RAM_SIZE]u8,
    system: *[runner.cartridge_memory.SYSTEM_SIZE]u8,
    memory: runner.cartridge_memory.Memory,

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
        @memset(rom, 0);
        @memset(sram, 0);
        @memset(system, 0);
        @memcpy(
            rom[PROGRAM_START .. PROGRAM_START + program.len],
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
            .memory = runner.cartridge_memory.Memory.init(
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
        allocator.destroy(self.system);
        allocator.destroy(self.sram);
        allocator.destroy(self.rom);
        self.* = undefined;
    }
};
