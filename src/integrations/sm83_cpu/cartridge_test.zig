//! CPU-backend roundtrip and adversarial gate for cartridge execution proofs.

const std = @import("std");
const core_air_utils = @import("stwo_core").air.utils;
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const pcs_core = @import("stwo_core").pcs;
const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
const prover = @import("stwo_prover_engine");
const proving_error = prover.prove.ProvingError;
const frontend = @import("stwo_sm83_frontend");
const cartridge = frontend.cartridge;
const memory = frontend.memory;
const runner = frontend.runner;
const memory_lookup = frontend.air.cartridge_memory_lookup;
const access_air = frontend.air.cartridge_access;
const access_component = frontend.air.cartridge_access_component;
const execution = frontend.air.execution;
const rom_lookup = frontend.air.cartridge_rom_lookup;
const cartridge_prover = frontend.cartridge_prover;

const Engine = cartridge_prover.ProverEngineForBackend(CpuBackend);
pub const Fixture = struct {
    rom_bytes: *[cartridge.header.ROM_SIZE]u8,
    initial_system: *[memory_lookup.SYSTEM_SIZE]u8,
    final_system: *[memory_lookup.SYSTEM_SIZE]u8,
    initial_sram: *[memory_lookup.SRAM_SIZE]u8,
    final_sram: *[memory_lookup.SRAM_SIZE]u8,
    steps: [16]runner.CartridgeStepTrace,
    initial_mapper: cartridge.State,
    final_mapper: cartridge.State,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) !Fixture {
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

        // Select bank 2, authenticate a switched-bank byte, mirror it through
        // WRAM/echo, enable SRAM, then write and read one SRAM byte.
        const program = [_]u8{
            0x3e, 0x02, // LD A,$02
            0xea, 0x00, 0x20, // LD ($2000),A
            0xfa, 0x00, 0x40, // LD A,($4000)
            0xea, 0x00, 0xc0, // LD ($c000),A
            0xfa, 0x00, 0xe0, // LD A,($e000)
            0x3e, 0x0a, // LD A,$0a
            0xea, 0x00, 0x00, // LD ($0000),A
            0x3e, 0x55, // LD A,$55
            0xea, 0x00, 0xa0, // LD ($a000),A
            0xfa, 0x00, 0xa0, // LD A,($a000)
            0x00, 0x00, 0x00,
            0x00, 0x00, 0x00,
        };
        @memcpy(rom_bytes[0..program.len], &program);
        rom_bytes[2 * cartridge.header.ROM_BANK_SIZE] = 0x99;
        rom_bytes[cartridge.header.CARTRIDGE_TYPE_OFFSET] =
            cartridge.header.CARTRIDGE_TYPE_MBC3_RAM_BATTERY;
        rom_bytes[cartridge.header.ROM_SIZE_CODE_OFFSET] =
            cartridge.header.ROM_SIZE_CODE_1_MIB;
        rom_bytes[cartridge.header.RAM_SIZE_CODE_OFFSET] =
            cartridge.header.RAM_SIZE_CODE_32_KIB;
        rom_bytes[cartridge.header.HEADER_CHECKSUM_OFFSET] =
            cartridge.header.headerChecksum(rom_bytes);
        std.mem.writeInt(
            u16,
            rom_bytes[cartridge.header.GLOBAL_CHECKSUM_OFFSET..cartridge.header.HEADER_END][0..2],
            cartridge.header.globalChecksum(rom_bytes),
            .big,
        );
        const loaded_cartridge =
            try cartridge.Cartridge.init(rom_bytes);
        var address_space = frontend.CartridgeMemory.init(
            loaded_cartridge,
            final_sram,
            final_system,
            .{},
            0,
        );
        var cpu = runner.Cpu{};
        var steps: [16]runner.CartridgeStepTrace = undefined;
        for (&steps) |*step_value|
            step_value.* = try runner.stepCartridge(
                &cpu,
                &address_space,
            );
        return .{
            .rom_bytes = rom_bytes,
            .initial_system = initial_system,
            .final_system = final_system,
            .initial_sram = initial_sram,
            .final_sram = final_sram,
            .steps = steps,
            .initial_mapper = .{},
            .final_mapper = address_space.mapper,
            .allocator = allocator,
        };
    }

    pub fn rom(self: *const Fixture) !cartridge.Cartridge {
        return cartridge.Cartridge.init(self.rom_bytes);
    }

    pub fn initialImages(self: *const Fixture) !memory_lookup.Images {
        return .{
            .system = try memory.Image.init(self.initial_system),
            .sram = try memory_lookup.SramImage.init(self.initial_sram),
        };
    }

    pub fn finalImages(self: *const Fixture) !memory_lookup.Images {
        return .{
            .system = try memory.Image.init(self.final_system),
            .sram = try memory_lookup.SramImage.init(self.final_sram),
        };
    }

    pub fn deinit(self: *Fixture) void {
        self.allocator.destroy(self.final_sram);
        self.allocator.destroy(self.initial_sram);
        self.allocator.destroy(self.final_system);
        self.allocator.destroy(self.initial_system);
        self.allocator.destroy(self.rom_bytes);
        self.* = undefined;
    }
};

pub var proof_run_mutex: std.Thread.Mutex = .{};

test "cartridge CPU proof roundtrip and adversarial boundaries" {
    proof_run_mutex.lock();
    defer proof_run_mutex.unlock();
    comptime cartridge_prover.assertProverEngine(Engine);

    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    try expectFixtureCoverage(fixture);
    const config = try testConfig();
    const rom = try fixture.rom();
    const initial = try fixture.initialImages();
    const final = try fixture.finalImages();
    try expectDirectRelations(
        std.testing.allocator,
        fixture,
        rom,
        initial,
        final,
    );
    const honest = cartridge_prover.proveExecutionWithEngine(
        Engine,
        std.testing.allocator,
        config,
        rom,
        initial,
        final,
        &fixture.steps,
    ) catch |err| {
        std.debug.print("honest cartridge prove failed: {s}\n", .{
            @errorName(err),
        });
        return err;
    };
    cartridge_prover.verifyExecutionWithEngine(
        Engine,
        std.testing.allocator,
        config,
        rom,
        initial,
        final,
        honest.statement,
        honest.proof,
    ) catch |err| {
        std.debug.print("honest cartridge verify failed: {s}\n", .{
            @errorName(err),
        });
        return err;
    };

    try expectConstraintFailure(
        cartridge_prover.testing.proveInactiveExecutionWithEngine(
            Engine,
            std.testing.allocator,
            config,
            rom,
            initial,
            final,
            &fixture.steps,
        ),
    );
    try expectConstraintFailure(
        cartridge_prover.testing.proveForgedMapperEndpointWithEngine(
            Engine,
            std.testing.allocator,
            config,
            rom,
            initial,
            final,
            &fixture.steps,
        ),
    );
    try expectConstraintFailure(
        cartridge_prover.testing.proveForgedRomByteWithEngine(
            Engine,
            std.testing.allocator,
            config,
            rom,
            initial,
            final,
            &fixture.steps,
        ),
    );
    try expectConstraintFailure(
        cartridge_prover.testing.proveForgedRomMultiplicityWithEngine(
            Engine,
            std.testing.allocator,
            config,
            rom,
            initial,
            final,
            &fixture.steps,
        ),
    );
    for ([_]cartridge_prover.testing.MemoryEndpoint{
        .system,
        .sram,
    }) |endpoint| {
        try expectConstraintFailure(
            cartridge_prover.testing.proveForgedMemoryEndpointWithEngine(
                Engine,
                std.testing.allocator,
                config,
                rom,
                initial,
                final,
                &fixture.steps,
                endpoint,
            ),
        );
    }
    for ([_]cartridge_prover.testing.PackedAccessMutation{
        .region,
        .physical_address,
        .value,
    }) |mutation| {
        try expectConstraintFailure(
            cartridge_prover.testing.proveForgedPackedAccessWithEngine(
                Engine,
                std.testing.allocator,
                config,
                rom,
                initial,
                final,
                &fixture.steps,
                mutation,
            ),
        );
    }

    for ([_]cartridge_prover.testing.PreprocessedMutation{
        .rom,
        .system,
        .sram,
    }) |mutation| {
        const forged =
            cartridge_prover.testing
                .proveNonCanonicalPreprocessedWithEngine(
                Engine,
                std.testing.allocator,
                config,
                rom,
                initial,
                final,
                &fixture.steps,
                mutation,
            ) catch |err| {
                std.debug.print(
                    "noncanonical {s} prove failed: {s}\n",
                    .{ @tagName(mutation), @errorName(err) },
                );
                return err;
            };
        try std.testing.expectError(
            error.InvalidPreprocessedCommitment,
            cartridge_prover.verifyExecutionWithEngine(
                Engine,
                std.testing.allocator,
                config,
                rom,
                initial,
                final,
                forged.statement,
                forged.proof,
            ),
        );
    }
}

fn expectDirectRelations(
    allocator: std.mem.Allocator,
    fixture: Fixture,
    rom: cartridge.Cartridge,
    initial: memory_lookup.Images,
    final: memory_lookup.Images,
) !void {
    const packed_component = access_component.Component{
        .log_size = 4,
        .is_first_column = 0,
        .is_last_column = 1,
        .execution_offset = 0,
        .main_offset = execution.N_MAIN_COLUMNS,
        .initial = fixture.initial_mapper,
        .final = fixture.final_mapper,
        .allow_joypad_mmio = false,
        .allow_timer_mmio = false,
        .allow_ppu_mmio = false,
        .allow_open_bus = false,
    };
    var mcycle: u32 = 0;
    for (fixture.steps, 0..) |step, row| {
        const next = fixture.steps[@min(row + 1, fixture.steps.len - 1)];
        var machine_values: [execution.N_MAIN_COLUMNS]QM31 = undefined;
        for (
            &machine_values,
            execution.columns(step.instruction, mcycle),
        ) |*value, source| value.* = QM31.fromBase(source);
        var current_values: [access_component.N_MAIN_COLUMNS]QM31 =
            undefined;
        for (
            &current_values,
            try access_component.columns(step),
        ) |*value, source| value.* = QM31.fromBase(source);
        var next_values: [access_component.N_MAIN_COLUMNS]QM31 =
            undefined;
        for (
            &next_values,
            try access_component.columns(next),
        ) |*value, source| value.* = QM31.fromBase(source);
        const evaluated = try packed_component.evaluateRow(
            &machine_values,
            &current_values,
            &next_values,
            if (row == 0) QM31.one() else QM31.zero(),
            if (row + 1 == fixture.steps.len)
                QM31.one()
            else
                QM31.zero(),
        );
        if (!evaluated.allZero())
            return error.PackedAccessDirectMismatch;
        mcycle += step.instruction.cycle_count;
    }

    var rom_interaction = try rom_lookup.generate(
        allocator,
        &fixture.steps,
        rom.bytes,
        rom_lookup.Relation.dummy(),
    );
    defer rom_interaction.deinit();
    try rom_lookup.verifyCancellation(rom_interaction.claims);

    var witness = try memory_lookup.generateWitness(
        allocator,
        &fixture.steps,
        initial,
        final,
    );
    defer witness.deinit();
    mcycle = 0;
    for (fixture.steps, 0..) |step, row| {
        const storage = try core_air_utils.circleBitReversedIndex(4, row);
        var memory_values: [memory_lookup.N_MAIN_COLUMNS]M31 =
            undefined;
        for (&memory_values, witness.main) |*value, column|
            value.* = column[storage];
        const validated = try access_air.ValidatedStep.init(step);
        if (!(try memory_lookup.evaluate(
            execution.columns(step.instruction, mcycle),
            memory_lookup.accessColumns(validated),
            memory_values,
        )).allZero()) return error.MutableMemoryDirectMismatch;
        mcycle += step.instruction.cycle_count;
    }
    var memory_interaction = try memory_lookup.generateInteraction(
        allocator,
        witness.accesses,
        4,
        initial,
        final,
        memory_lookup.Relation.dummy(),
    );
    defer memory_interaction.deinit();
    try memory_lookup.verifyCancellation(memory_interaction.claims);
}

fn expectFixtureCoverage(fixture: Fixture) !void {
    var fixed_rom_reads: usize = 0;
    var mapper_writes: usize = 0;
    var switched_reads: usize = 0;
    var system_writes: usize = 0;
    var echo_reads: usize = 0;
    var sram_reads: usize = 0;
    var sram_writes: usize = 0;
    for (fixture.steps) |step| {
        for (step.activeAccesses()) |maybe_access| {
            const access = maybe_access orelse continue;
            switch (access.region) {
                .cartridge_rom => {
                    if (access.logical_address < 0x4000)
                        fixed_rom_reads += 1;
                    if (access.logical_address == 0x4000 and
                        access.physical_offset ==
                            @as(
                                runner.cartridge_memory.PhysicalOffset,
                                2 * cartridge.header.ROM_BANK_SIZE,
                            ))
                        switched_reads += 1;
                },
                .mapper_control => mapper_writes += 1,
                .system => if (access.action == .write and
                    access.logical_address == 0xc000)
                {
                    system_writes += 1;
                },
                .system_echo => if (access.action == .read and
                    access.logical_address == 0xe000)
                {
                    echo_reads += 1;
                },
                .cartridge_ram => switch (access.action) {
                    .read => sram_reads += 1,
                    .write => sram_writes += 1,
                },
                else => {},
            }
        }
    }
    try std.testing.expectEqual(@as(usize, 33), fixed_rom_reads);
    try std.testing.expectEqual(@as(usize, 2), mapper_writes);
    try std.testing.expectEqual(@as(usize, 1), switched_reads);
    try std.testing.expectEqual(@as(usize, 1), system_writes);
    try std.testing.expectEqual(@as(usize, 1), echo_reads);
    try std.testing.expectEqual(@as(usize, 1), sram_reads);
    try std.testing.expectEqual(@as(usize, 1), sram_writes);
    try std.testing.expectEqual(@as(u8, 0x99), fixture.final_system[0xc000]);
    try std.testing.expectEqual(@as(u8, 0x55), fixture.final_sram[0]);
    try std.testing.expectEqual(@as(u7, 2), fixture.final_mapper.rom_bank_register);
    try std.testing.expect(fixture.final_mapper.ram_enabled);
}

pub fn expectConstraintFailure(result: anytype) !void {
    try std.testing.expectError(
        proving_error.ConstraintsNotSatisfied,
        result,
    );
}

pub fn testConfig() !pcs_core.PcsConfig {
    return .{
        .pow_bits = 0,
        .fri_config = try @import("stwo_core").fri.FriConfig.init(
            0,
            1,
            3,
        ),
    };
}
