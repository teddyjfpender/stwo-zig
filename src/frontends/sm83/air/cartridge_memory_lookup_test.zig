const std = @import("std");
const core_air_utils = @import("stwo_core").air.utils;
const M31 = @import("stwo_core").fields.m31.M31;
const cartridge = @import("../cartridge/mod.zig");
const runner = @import("../runner/mod.zig");
const cartridge_access = @import("cartridge_access.zig");
const execution = @import("execution.zig");
const lookup = @import("cartridge_memory_lookup.zig");

const Fixture = struct {
    rom: *[cartridge.header.ROM_SIZE]u8,
    sram: *[lookup.SRAM_SIZE]u8,
    system: *[lookup.SYSTEM_SIZE]u8,
    memory: runner.cartridge_memory.Memory,

    fn init(allocator: std.mem.Allocator) !Fixture {
        const rom = try allocator.create([cartridge.header.ROM_SIZE]u8);
        errdefer allocator.destroy(rom);
        const sram = try allocator.create([lookup.SRAM_SIZE]u8);
        errdefer allocator.destroy(sram);
        const system = try allocator.create([lookup.SYSTEM_SIZE]u8);
        errdefer allocator.destroy(system);
        @memset(rom, 0);
        @memset(sram, 0);
        @memset(system, 0);
        const program = [_]u8{
            0x7e, 0x77, 0x7e, 0x77,
            0x77, 0x7e, 0x77, 0x77,
            0x7e, 0x77, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        };
        @memcpy(rom[0..program.len], &program);
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
        return .{
            .rom = rom,
            .sram = sram,
            .system = system,
            .memory = runner.cartridge_memory.Memory.init(
                try cartridge.Cartridge.init(rom),
                sram,
                system,
                .{ .ram_enabled = true },
                0,
            ),
        };
    }

    fn deinit(self: *Fixture, allocator: std.mem.Allocator) void {
        allocator.destroy(self.system);
        allocator.destroy(self.sram);
        allocator.destroy(self.rom);
        self.* = undefined;
    }
};

const Run = struct {
    steps: [16]runner.CartridgeStepTrace,
    initial_system: []u8,
    initial_sram: []u8,
    final_system: []u8,
    final_sram: []u8,
    allocator: std.mem.Allocator,

    fn init(allocator: std.mem.Allocator, fixture: *Fixture) !Run {
        fixture.system[0x8000] = 0x11;
        fixture.system[0xc000] = 0x22;
        fixture.sram[0x6000] = 0x33;
        const initial_system = try allocator.dupe(u8, fixture.system);
        errdefer allocator.free(initial_system);
        const initial_sram = try allocator.dupe(u8, fixture.sram);
        errdefer allocator.free(initial_sram);

        var cpu = runner.Cpu{};
        var steps: [16]runner.CartridgeStepTrace = undefined;
        for (&steps, 0..) |*step, index| {
            switch (index) {
                0 => cpu.setHl(0x8000),
                1 => {
                    cpu.setHl(0x8001);
                    cpu.a = 0x21;
                },
                2 => cpu.setHl(0xe000),
                3 => {
                    cpu.setHl(0xfdff);
                    cpu.a = 0x43;
                },
                4 => {
                    cpu.setHl(0x4000);
                    cpu.a = 3;
                },
                5 => cpu.setHl(0xa000),
                6 => {
                    cpu.setHl(0xbfff);
                    cpu.a = 0x65;
                },
                7 => {
                    cpu.setHl(0);
                    cpu.a = 0;
                },
                8 => cpu.setHl(0xa000),
                9 => {
                    cpu.setHl(0xbfff);
                    cpu.a = 0x87;
                },
                else => {},
            }
            step.* = try runner.stepCartridge(&cpu, &fixture.memory);
        }
        const final_system = try allocator.dupe(u8, fixture.system);
        errdefer allocator.free(final_system);
        const final_sram = try allocator.dupe(u8, fixture.sram);
        return .{
            .steps = steps,
            .initial_system = initial_system,
            .initial_sram = initial_sram,
            .final_system = final_system,
            .final_sram = final_sram,
            .allocator = allocator,
        };
    }

    fn initial(self: Run) !lookup.Images {
        return .{
            .system = try @import("../memory.zig").Image.init(
                self.initial_system,
            ),
            .sram = try lookup.SramImage.init(self.initial_sram),
        };
    }

    fn final(self: Run) !lookup.Images {
        return .{
            .system = try @import("../memory.zig").Image.init(
                self.final_system,
            ),
            .sram = try lookup.SramImage.init(self.final_sram),
        };
    }

    fn deinit(self: *Run) void {
        self.allocator.free(self.final_sram);
        self.allocator.free(self.final_system);
        self.allocator.free(self.initial_sram);
        self.allocator.free(self.initial_system);
        self.* = undefined;
    }
};

test "memory phase clock orders scheduler CPU and devices without field wrap" {
    try std.testing.expectEqual(
        @as(u32, 1),
        try lookup.memory_clock.phaseClock(
            0,
            lookup.memory_clock.ACTION_PHASE,
        ),
    );
    try std.testing.expectEqual(
        @as(u32, 2),
        try lookup.memory_clock.phaseClock(
            0,
            lookup.memory_clock.SCHEDULER_PHASE,
        ),
    );
    try std.testing.expectEqual(
        @as(u32, 3),
        try lookup.memory_clock.phaseClock(
            0,
            lookup.memory_clock.CPU_PHASE,
        ),
    );
    try std.testing.expectEqual(
        @as(u32, 4),
        try lookup.memory_clock.phaseClock(
            0,
            lookup.memory_clock.SERVICE_RESAMPLE_PHASE,
        ),
    );
    try std.testing.expectEqual(
        @as(u32, 5),
        try lookup.memory_clock.phaseClock(
            0,
            lookup.memory_clock.SERVICE_ACK_PHASE,
        ),
    );
    try std.testing.expectEqual(
        @as(u32, 6),
        try lookup.memory_clock.phaseClock(
            0,
            lookup.memory_clock.TICK_PHASE,
        ),
    );
    try std.testing.expectEqual(
        @as(u32, 7),
        try lookup.memory_clock.phaseClock(
            0,
            lookup.memory_clock.JOYPAD_TICK_PHASE,
        ),
    );
    try std.testing.expectEqual(
        @as(u32, 8),
        try lookup.memory_clock.phaseClock(
            0,
            lookup.memory_clock.PPU_PHASE,
        ),
    );
    try std.testing.expectEqual(
        @as(u32, 9),
        try lookup.memory_clock.phaseClock(
            0,
            lookup.memory_clock.DMA_PHASE,
        ),
    );
    try std.testing.expectEqual(
        @as(u32, 11),
        try lookup.memory_clock.phaseClock(
            1,
            lookup.memory_clock.ACTION_PHASE,
        ),
    );
    _ = try lookup.memory_clock.phaseClock(
        lookup.memory_clock.MAX_FINAL_MCYCLE - 1,
        lookup.memory_clock.TICK_PHASE,
    );
    try std.testing.expectError(
        error.MemoryClockOutsideField,
        lookup.memory_clock.phaseClock(
            lookup.memory_clock.MAX_FINAL_MCYCLE + 1,
            lookup.memory_clock.TICK_PHASE,
        ),
    );
    try std.testing.expectError(
        error.InvalidMemoryClockPhase,
        lookup.memory_clock.phaseClock(
            0,
            lookup.memory_clock.PHASES,
        ),
    );
}

test "memory clock differences admit 28 bits and reject the boundary" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit(std.testing.allocator);
    var run = try Run.init(std.testing.allocator, &fixture);
    defer run.deinit();
    const initial = try run.initial();
    const final = try run.final();
    var accesses = [_]lookup.Access{.{}} ** execution.N_BUS_CYCLES;
    accesses[0] = .{
        .enabled = true,
        .address = 0xc000,
        .previous_clock = 1,
        .previous_value = 0x22,
        .clock = (@as(u32, 1) << 27) + 2,
        .next_value = 0x22,
    };
    var interaction = try lookup.generateInteraction(
        std.testing.allocator,
        &accesses,
        0,
        initial,
        final,
        lookup.Relation.dummy(),
    );
    interaction.deinit();

    accesses[0].clock = (@as(u32, 1) << 28) + 2;
    try std.testing.expectError(
        error.MemoryClockDifferenceTooLarge,
        lookup.generateInteraction(
            std.testing.allocator,
            &accesses,
            0,
            initial,
            final,
            lookup.Relation.dummy(),
        ),
    );
}

test "cartridge memory lookup authenticates system echo and physical SRAM" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit(std.testing.allocator);
    var run = try Run.init(std.testing.allocator, &fixture);
    defer run.deinit();
    const initial = try run.initial();
    const final = try run.final();

    var witness = try lookup.generateWitness(
        std.testing.allocator,
        &run.steps,
        initial,
        final,
    );
    defer witness.deinit();

    var mcycle: u32 = 0;
    for (run.steps, 0..) |step, row_index| {
        const storage = try core_air_utils.circleBitReversedIndex(
            4,
            row_index,
        );
        var row: [lookup.N_MAIN_COLUMNS]M31 = undefined;
        for (&row, witness.main) |*value, column|
            value.* = column[storage];
        const validated = try cartridge_access.ValidatedStep.init(step);
        try std.testing.expect((try lookup.evaluate(
            execution.columns(step.instruction, mcycle),
            lookup.accessColumns(validated),
            row,
        )).allZero());
        mcycle += step.instruction.cycle_count;
    }

    const expected = [_]u17{
        0x8000,
        0x8001,
        0xc000,
        0xddff,
        0x16000,
        0x17fff,
    };
    var actual: [expected.len]u17 = undefined;
    var count: usize = 0;
    for (witness.accesses) |access| {
        if (!access.enabled) continue;
        actual[count] = access.address;
        count += 1;
    }
    try std.testing.expectEqual(expected.len, count);
    try std.testing.expectEqualSlices(u17, &expected, &actual);
    try std.testing.expectEqual(@as(u8, 0x21), final.system.bytes[0x8001]);
    try std.testing.expectEqual(@as(u8, 0x43), final.system.bytes[0xddff]);
    try std.testing.expectEqual(@as(u8, 0), final.system.bytes[0xfdff]);
    try std.testing.expectEqual(@as(u8, 0x65), final.sram.bytes[0x7fff]);

    var interaction = try lookup.generateInteraction(
        std.testing.allocator,
        witness.accesses,
        4,
        initial,
        final,
        lookup.Relation.dummy(),
    );
    defer interaction.deinit();
    try lookup.verifyCancellation(interaction.claims);

    const first_padding_storage =
        try core_air_utils.circleBitReversedIndex(
            lookup.BOUNDARY_LOG_SIZE,
            lookup.KEY_COUNT,
        );
    try std.testing.expect(
        witness.final_clocks[first_padding_storage].isZero(),
    );
}

test "cartridge memory lookup rejects semantic and lookup mutations" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit(std.testing.allocator);
    var run = try Run.init(std.testing.allocator, &fixture);
    defer run.deinit();
    const initial = try run.initial();
    const final = try run.final();
    var witness = try lookup.generateWitness(
        std.testing.allocator,
        &run.steps,
        initial,
        final,
    );
    defer witness.deinit();

    const first = findAccess(witness.accesses, 0x8000);
    const first_cycle = first % execution.N_BUS_CYCLES;
    const offset = first_cycle * lookup.N_ACCESS_COLUMNS;
    var row: [lookup.N_MAIN_COLUMNS]M31 = undefined;
    const storage = try core_air_utils.circleBitReversedIndex(4, 0);
    for (&row, witness.main) |*value, column|
        value.* = column[storage];
    const validated = try cartridge_access.ValidatedStep.init(run.steps[0]);
    const machine = execution.columns(run.steps[0].instruction, 0);
    const sources = lookup.accessColumns(validated);

    row[offset + 1] = M31.fromCanonical(0x12);
    try std.testing.expect(
        !(try lookup.evaluate(machine, sources, row)).allZero(),
    );
    for (&row, witness.main) |*value, column|
        value.* = column[storage];
    row[offset] = M31.one();
    try std.testing.expect(
        !(try lookup.evaluate(machine, sources, row)).allZero(),
    );
    for (&row, witness.main) |*value, column|
        value.* = column[storage];
    const inactive = (execution.N_BUS_CYCLES - 1) *
        lookup.N_ACCESS_COLUMNS;
    row[inactive + 2] = M31.one();
    try std.testing.expect(
        !(try lookup.evaluate(machine, sources, row)).allZero(),
    );

    var forged = try std.testing.allocator.dupe(
        lookup.Access,
        witness.accesses,
    );
    defer std.testing.allocator.free(forged);

    forged[first].address = 0x8002;
    try expectLookupRejection(forged, initial, final);
    forged[first] = witness.accesses[first];
    forged[first].previous_value ^= 1;
    try expectLookupRejection(forged, initial, final);

    const echo = findAccess(witness.accesses, 0xc000);
    forged[first] = witness.accesses[first];
    forged[echo].address = 0xe000;
    try expectLookupRejection(forged, initial, final);
    forged[echo] = witness.accesses[echo];

    const sram = findAccess(witness.accesses, 0x17fff);
    forged[sram].next_value ^= 1;
    try expectLookupRejection(forged, initial, final);

    var drifted_system = try std.testing.allocator.dupe(
        u8,
        run.final_system,
    );
    defer std.testing.allocator.free(drifted_system);
    drifted_system[0x8001] ^= 1;
    const drifted = lookup.Images{
        .system = try @import("../memory.zig").Image.init(drifted_system),
        .sram = final.sram,
    };
    try std.testing.expectError(
        error.FinalMemoryMismatch,
        lookup.generateWitness(
            std.testing.allocator,
            &run.steps,
            initial,
            drifted,
        ),
    );
}

test "cartridge memory lookup rejects tail access padding and hidden MMIO drift" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit(std.testing.allocator);
    var run = try Run.init(std.testing.allocator, &fixture);
    defer run.deinit();
    const initial = try run.initial();
    const final = try run.final();

    var forged_steps = run.steps;
    const tail_index = forged_steps[10].instruction.cycle_count;
    forged_steps[10].accesses[tail_index] = forged_steps[0].accesses[1];
    try std.testing.expectError(
        error.InvalidInactiveAccess,
        lookup.generateWitness(
            std.testing.allocator,
            &forged_steps,
            initial,
            final,
        ),
    );

    var hidden_system = try std.testing.allocator.dupe(
        u8,
        run.final_system,
    );
    defer std.testing.allocator.free(hidden_system);
    hidden_system[0xff0f] ^= 0x10;
    const hidden = lookup.Images{
        .system = try @import("../memory.zig").Image.init(hidden_system),
        .sram = final.sram,
    };
    var witness = try lookup.generateWitness(
        std.testing.allocator,
        &run.steps,
        initial,
        final,
    );
    defer witness.deinit();
    var interaction = try lookup.generateInteraction(
        std.testing.allocator,
        witness.accesses,
        4,
        initial,
        hidden,
        lookup.Relation.dummy(),
    );
    defer interaction.deinit();
    try std.testing.expectError(
        error.CartridgeMemoryLookupSumNonZero,
        lookup.verifyCancellation(interaction.claims),
    );
}

test "log17 boundary padding is exact and fail closed" {
    const system = try std.testing.allocator.alloc(u8, lookup.SYSTEM_SIZE);
    defer std.testing.allocator.free(system);
    const sram = try std.testing.allocator.alloc(u8, lookup.SRAM_SIZE);
    defer std.testing.allocator.free(sram);
    const clocks = try std.testing.allocator.alloc(u32, lookup.KEY_COUNT);
    defer std.testing.allocator.free(clocks);
    @memset(system, 0);
    @memset(sram, 0);
    @memset(clocks, 0);
    const images = lookup.Images{
        .system = try @import("../memory.zig").Image.init(system),
        .sram = try lookup.SramImage.init(sram),
    };
    const relation = lookup.Relation.dummy();
    const first_padding = try lookup.boundaryEntry(
        lookup.KEY_COUNT,
        images,
        clocks,
        images,
    );
    _ = try lookup.boundaryPairForRow(
        lookup.KEY_COUNT,
        first_padding,
        relation,
    );
    var forged = first_padding;
    forged.final_value = 1;
    try std.testing.expectError(
        error.InvalidBoundaryPadding,
        lookup.boundaryPairForRow(lookup.KEY_COUNT, forged, relation),
    );
    var real = try lookup.boundaryEntry(0xffff, images, clocks, images);
    real.address = 0;
    try std.testing.expectError(
        error.InvalidBoundaryEntry,
        lookup.boundaryPairForRow(0xffff, real, relation),
    );
    try std.testing.expectError(
        error.InvalidBoundaryClocks,
        lookup.boundaryEntry(
            0,
            images,
            clocks[0 .. lookup.KEY_COUNT - 1],
            images,
        ),
    );
    try std.testing.expectError(
        error.InvalidSramLength,
        lookup.SramImage.init(sram[0 .. lookup.SRAM_SIZE - 1]),
    );
}

test "public memory lookup entries reject constructor-bypassing short images" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit(std.testing.allocator);
    var run = try Run.init(std.testing.allocator, &fixture);
    defer run.deinit();
    const initial = try run.initial();
    const final = try run.final();
    const short_system = lookup.Images{
        .system = .{ .bytes = initial.system.bytes[0 .. lookup.SYSTEM_SIZE - 1] },
        .sram = initial.sram,
    };
    const short_sram = lookup.Images{
        .system = final.system,
        .sram = .{ .bytes = final.sram.bytes[0 .. lookup.SRAM_SIZE - 1] },
    };

    try expectShapeRejections(&run.steps, short_system, final, error.InvalidSystemMemoryShape);
    try expectShapeRejections(&run.steps, initial, short_sram, error.InvalidSramShape);
}

fn findAccess(accesses: []const lookup.Access, address: u17) usize {
    for (accesses, 0..) |access, index|
        if (access.enabled and access.address == address) return index;
    unreachable;
}

fn expectLookupRejection(
    accesses: []const lookup.Access,
    initial: lookup.Images,
    final: lookup.Images,
) !void {
    var interaction = try lookup.generateInteraction(
        std.testing.allocator,
        accesses,
        4,
        initial,
        final,
        lookup.Relation.dummy(),
    );
    defer interaction.deinit();
    try std.testing.expectError(
        error.CartridgeMemoryLookupSumNonZero,
        lookup.verifyCancellation(interaction.claims),
    );
}

fn expectShapeRejections(
    steps: []const runner.CartridgeStepTrace,
    initial: lookup.Images,
    final: lookup.Images,
    expected: anyerror,
) !void {
    try std.testing.expectError(expected, lookup.generateWitness(std.testing.allocator, steps, initial, final));
    const accesses =
        [_]lookup.Access{.{}} ** (16 * execution.N_BUS_CYCLES);
    try std.testing.expectError(expected, lookup.generateInteraction(
        std.testing.allocator,
        &accesses,
        4,
        initial,
        final,
        lookup.Relation.dummy(),
    ));
    const clocks = try std.testing.allocator.alloc(u32, lookup.KEY_COUNT);
    defer std.testing.allocator.free(clocks);
    @memset(clocks, 0);
    try std.testing.expectError(expected, lookup.boundaryEntry(0, initial, clocks, final));
}
