const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;
const action_schedule = @import("action_schedule.zig");
const base_statement = @import("cartridge_proof_statement.zig");
const cartridge = @import("cartridge/mod.zig");
const environment = @import("environment_statement.zig");
const subject = @import("machine_environment_verifier.zig");
const machine_statement = @import("machine_environment_statement.zig");
const memory = @import("memory.zig");
const memory_lookup = @import("air/cartridge_memory_lookup.zig");
const intermediate_observation =
    @import("air/intermediate_ram_observation_lookup.zig");
const timer_binding = @import("air/timer_binding.zig");
const dma = @import("runner/dma.zig");
const joypad = @import("runner/joypad.zig");
const machine = @import("runner/machine.zig");
const ppu_mmio = @import("runner/ppu_mmio.zig");
const timer = @import("runner/timer.zig");

const no_actions = [0]action_schedule.Action{};
const regions = [_]@import("ram_observation.zig").Region{
    .{ .space = .system, .start = 0xc000, .length = 1 },
};
const samples = [_]intermediate_observation.Sample{
    .{ .mcycle = 100, .key = 0xc000, .expected = 0 },
};

const Fixture = struct {
    rom_bytes: *[cartridge.header.ROM_SIZE]u8,
    initial_system: *[memory_lookup.SYSTEM_SIZE]u8,
    final_system: *[memory_lookup.SYSTEM_SIZE]u8,
    initial_sram: *[memory_lookup.SRAM_SIZE]u8,
    final_sram: *[memory_lookup.SRAM_SIZE]u8,
    allocator: std.mem.Allocator,

    fn init(allocator: std.mem.Allocator) !Fixture {
        const rom_bytes =
            try allocator.create([cartridge.header.ROM_SIZE]u8);
        errdefer allocator.destroy(rom_bytes);
        const initial_system =
            try allocator.create([memory_lookup.SYSTEM_SIZE]u8);
        errdefer allocator.destroy(initial_system);
        const final_system =
            try allocator.create([memory_lookup.SYSTEM_SIZE]u8);
        errdefer allocator.destroy(final_system);
        const initial_sram =
            try allocator.create([memory_lookup.SRAM_SIZE]u8);
        errdefer allocator.destroy(initial_sram);
        const final_sram =
            try allocator.create([memory_lookup.SRAM_SIZE]u8);
        errdefer allocator.destroy(final_sram);
        @memset(rom_bytes, 0);
        @memset(initial_system, 0);
        @memset(final_system, 0);
        @memset(initial_sram, 0);
        @memset(final_sram, 0);
        setHeader(rom_bytes);
        setDeviceRegisters(initial_system);
        setDeviceRegisters(final_system);
        return .{
            .rom_bytes = rom_bytes,
            .initial_system = initial_system,
            .final_system = final_system,
            .initial_sram = initial_sram,
            .final_sram = final_sram,
            .allocator = allocator,
        };
    }

    fn deinit(self: *Fixture) void {
        self.allocator.destroy(self.final_sram);
        self.allocator.destroy(self.initial_sram);
        self.allocator.destroy(self.final_system);
        self.allocator.destroy(self.initial_system);
        self.allocator.destroy(self.rom_bytes);
        self.* = undefined;
    }

    fn rom(self: *const Fixture) !cartridge.Cartridge {
        return cartridge.Cartridge.init(self.rom_bytes);
    }

    fn initialImages(self: *const Fixture) !memory_lookup.Images {
        return .{
            .system = try memory.Image.init(self.initial_system),
            .sram = try memory_lookup.SramImage.init(self.initial_sram),
        };
    }

    fn finalImages(self: *const Fixture) !memory_lookup.Images {
        return .{
            .system = try memory.Image.init(self.final_system),
            .sram = try memory_lookup.SramImage.init(self.final_sram),
        };
    }

    fn statement(self: *const Fixture) !machine_statement.ExecutionStatement {
        const cartridge_value = try self.rom();
        const initial_images = try self.initialImages();
        const final_images = try self.finalImages();
        const base = base_statement.init(
            4,
            .{ .cpu = .{}, .mcycle = 100 },
            .{ .cpu = .{}, .mcycle = 116 },
            .{},
            .{},
            cartridge_value,
            initial_images,
            final_images,
        );
        const environment_statement = try environment.init(
            base,
            cartridge_value,
            initial_images,
            final_images,
            &no_actions,
            .{},
            .{},
            4,
            .{},
            .{},
            4,
            &regions,
            &samples,
            4,
        );
        var result = try machine_statement.init(
            environment_statement,
            machineState(),
            machineState(),
            .{},
            .{},
            .{},
            .{},
            .{ .clock = 100 },
            .{ .clock = 116 },
            0,
            4,
            4,
            4,
            initial_images,
            final_images,
        );
        result.dma_execution_lookup_claims.execution_count = 16;
        result.dma_execution_lookup_claims.dma_count = 16;
        return result;
    }
};

test "machine verifier preflight fails closed on public and proof shape" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const statement = try fixture.statement();
    const rom = try fixture.rom();
    const initial_images = try fixture.initialImages();
    const final_images = try fixture.finalImages();

    try subject.testing.validatePublicAndShape(
        statement,
        rom,
        initial_images,
        final_images,
        &no_actions,
        &regions,
        &samples,
        4,
    );
    try std.testing.expectError(
        error.InvalidProofShape,
        subject.testing.validatePublicAndShape(
            statement,
            rom,
            initial_images,
            final_images,
            &no_actions,
            &regions,
            &samples,
            3,
        ),
    );

    var mutated = statement;
    mutated.base.action_digest[0] ^= 1;
    try std.testing.expectError(
        error.ActionDigestMismatch,
        subject.testing.validatePublicAndShape(
            mutated,
            rom,
            initial_images,
            final_images,
            &no_actions,
            &regions,
            &samples,
            4,
        ),
    );
    mutated = statement;
    mutated.version += 1;
    try std.testing.expectError(
        error.InvalidMachineEnvironmentVersion,
        subject.testing.validatePublicAndShape(
            mutated,
            rom,
            initial_images,
            final_images,
            &no_actions,
            &regions,
            &samples,
            4,
        ),
    );
    mutated = statement;
    mutated.final_dma.page = 1;
    try std.testing.expectError(
        error.FinalDmaPageMismatch,
        subject.testing.validatePublicAndShape(
            mutated,
            rom,
            initial_images,
            final_images,
            &no_actions,
            &regions,
            &samples,
            4,
        ),
    );
    inline for (.{ "scy", "scx", "wy" }) |field| {
        mutated = statement;
        @field(mutated.final_ppu, field) = 1;
        try std.testing.expectError(
            error.FinalPpuRegisterMismatch,
            subject.testing.validatePublicAndShape(
                mutated,
                rom,
                initial_images,
                final_images,
                &no_actions,
                &regions,
                &samples,
                4,
            ),
        );
    }
}

test "machine verifier rejects uncancelled and count-mutated claims" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const statement = try fixture.statement();
    try subject.testing.validateLookupClaims(statement);

    var mutated = statement;
    mutated.ppu_if_memory_claim = QM31.one();
    try std.testing.expectError(
        error.CartridgeMemoryLookupSumNonZero,
        subject.testing.validateLookupClaims(mutated),
    );
    mutated = statement;
    mutated.ppu_execution_policy_claims.ppu = QM31.one();
    try std.testing.expectError(
        error.PpuExecutionPolicyLookupSumNonZero,
        subject.testing.validateLookupClaims(mutated),
    );
    mutated = statement;
    mutated.interrupt_service_memory_lookup_claims.service_count = 1;
    try std.testing.expectError(
        error.InterruptServiceCountMismatch,
        subject.testing.validateLookupClaims(mutated),
    );
    mutated = statement;
    mutated.dma_execution_lookup_claims.dma_count -= 1;
    try std.testing.expectError(
        error.DmaExecutionCountMismatch,
        subject.testing.validateLookupClaims(mutated),
    );
}

fn machineState() machine.MachineState {
    return .{
        .cpu = .{},
        .halt_bug = false,
        .div_counter = 0,
        .tima = 0,
        .tma = 0,
        .tac = 0,
        .timer_reload = .running,
        .interrupt_flags = 0,
        .interrupt_enable = 0,
    };
}

fn setHeader(bytes: *[cartridge.header.ROM_SIZE]u8) void {
    bytes[cartridge.header.CARTRIDGE_TYPE_OFFSET] =
        cartridge.header.CARTRIDGE_TYPE_MBC3_RAM_BATTERY;
    bytes[cartridge.header.ROM_SIZE_CODE_OFFSET] =
        cartridge.header.ROM_SIZE_CODE_1_MIB;
    bytes[cartridge.header.RAM_SIZE_CODE_OFFSET] =
        cartridge.header.RAM_SIZE_CODE_32_KIB;
    bytes[cartridge.header.HEADER_CHECKSUM_OFFSET] =
        cartridge.header.headerChecksum(bytes);
    std.mem.writeInt(
        u16,
        bytes[cartridge.header.GLOBAL_CHECKSUM_OFFSET..cartridge.header.HEADER_END][0..2],
        cartridge.header.globalChecksum(bytes),
        .big,
    );
}

fn setDeviceRegisters(bytes: []u8) void {
    const joypad_state = joypad.State{};
    const timer_state = timer.Timer{};
    bytes[joypad.P1_ADDRESS] = joypad_state.readP1();
    inline for (0..4) |register| {
        bytes[timer_binding.FIRST_ADDRESS + register] =
            timer_binding.readTimerRegister(
                timer_state,
                @enumFromInt(register),
            );
    }
    bytes[ppu_mmio.LCDC_ADDRESS] = 0;
    bytes[ppu_mmio.STAT_ADDRESS] = 0x80;
    bytes[ppu_mmio.SCY_ADDRESS] = 0;
    bytes[ppu_mmio.SCX_ADDRESS] = 0;
    bytes[ppu_mmio.LY_ADDRESS] = 0;
    bytes[ppu_mmio.LYC_ADDRESS] = 0;
    bytes[ppu_mmio.WY_ADDRESS] = 0;
    bytes[dma.DMA_ADDRESS] = (dma.State{}).page;
}
