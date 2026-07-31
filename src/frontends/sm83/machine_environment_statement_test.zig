const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;
const environment = @import("environment_statement.zig");
const memory = @import("memory.zig");
const memory_lookup = @import("air/cartridge_memory_lookup.zig");
const ppu_mmio = @import("runner/ppu_mmio.zig");
const subject = @import("machine_environment_statement.zig");
const dma = @import("runner/dma.zig");
const apu = @import("runner/apu_mmio.zig");
const machine = @import("runner/machine.zig");

fn baseStatement() environment.ExecutionStatement {
    var statement = std.mem.zeroes(environment.ExecutionStatement);
    statement.version = environment.VERSION;
    statement.base.log_size = 4;
    statement.base.initial.mcycle = 100;
    statement.base.final.mcycle = 116;
    statement.initial_joypad = .{};
    statement.final_joypad = .{};
    statement.joypad_log_size = 4;
    statement.initial_timer = .{};
    statement.final_timer = .{};
    statement.timer_log_size = 4;
    statement.intermediate_observation_log_size = 4;
    statement.intermediate_observation_schedule_claim.count = 1;
    return statement;
}

fn machineState(halt_bug: bool) machine.MachineState {
    return .{
        .cpu = .{},
        .halt_bug = halt_bug,
        .div_counter = 0,
        .tima = 0,
        .tma = 0,
        .tac = 0,
        .timer_reload = .running,
        .interrupt_flags = 0,
        .interrupt_enable = 0,
    };
}

fn setPpuRegisters(system: []u8) void {
    system[ppu_mmio.LCDC_ADDRESS] = 0;
    system[ppu_mmio.STAT_ADDRESS] = 0x80;
    system[ppu_mmio.SCY_ADDRESS] = 0;
    system[ppu_mmio.SCX_ADDRESS] = 0;
    system[ppu_mmio.LY_ADDRESS] = 0;
    system[ppu_mmio.LYC_ADDRESS] = 0;
    system[ppu_mmio.WY_ADDRESS] = 0;
    system[dma.DMA_ADDRESS] = (dma.State{}).page;
}

fn images(system: []const u8) memory_lookup.Images {
    return .{
        .system = memory.Image.init(system) catch unreachable,
        .sram = .{ .bytes = &.{} },
    };
}

fn initStatement(
    system: []const u8,
) !subject.ExecutionStatement {
    const base = baseStatement();
    return subject.init(
        base,
        machineState(true),
        machineState(false),
        .{},
        .{},
        .{},
        .{},
        .{ .clock = base.base.initial.mcycle },
        .{ .clock = base.base.final.mcycle },
        0,
        6,
        4,
        5,
        images(system),
        images(system),
    );
}

fn lookupDigest(statement: subject.ExecutionStatement) subject.Digest {
    var channel = subject.Channel{};
    subject.mixLookupClaims(&channel, statement);
    return channel.digestBytes();
}

fn expectDigestChanged(
    expected: subject.Digest,
    actual: subject.Digest,
) !void {
    try std.testing.expect(!std.mem.eql(u8, &expected, &actual));
}

test "v7 keeps v3 canonical and commits complete machine endpoints" {
    const system = try std.testing.allocator.alloc(
        u8,
        memory_lookup.SYSTEM_SIZE,
    );
    defer std.testing.allocator.free(system);
    @memset(system, 0);
    setPpuRegisters(system);

    const statement = try initStatement(system);
    try subject.validateShape(statement);
    try std.testing.expectEqual(subject.VERSION, statement.version);
    try std.testing.expectEqual(@as(u32, 7), subject.VERSION);
    try std.testing.expectEqual(@as(u32, 0x534d_4506), subject.DOMAIN_TAG);
    try std.testing.expect(std.meta.eql(
        baseStatement(),
        statement.base,
    ));
    try std.testing.expect(statement.initial_halt_bug);
    try std.testing.expect(!statement.final_halt_bug);
    try std.testing.expect(
        statement.scheduler_memory_lookup_claims.total().isZero(),
    );
    try std.testing.expect(
        statement.interrupt_service_memory_lookup_claims.total().isZero(),
    );

    var apu_state = apu.State{
        .enabled = true,
        .channel_status = 0x0a,
        .wave_access = .{ .current_byte = 3 },
    };
    apu_state.registers[0] = 0x9a;
    apu_state.registers[apu.REGISTER_COUNT - 1] = 0xbc;
    const encoded = try subject.encodeEndpoint(
        true,
        .{ .scy = 0x12, .scx = 0x34, .wy = 0x56 },
        apu_state,
        .{
            .clock = 100,
            .page = 0x12,
            .phase = .startup,
            .restarting = true,
        },
    );
    const expected_v6 = [_]u8{
        1,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        100,
        0,
        0,
        0,
        0x12,
        0,
        @intFromEnum(dma.Phase.startup),
        1,
        0x12,
        0x34,
        0x56,
    };
    try std.testing.expectEqualSlices(u8, &expected_v6, encoded[0..23]);
    try std.testing.expectEqualSlices(
        u8,
        &apu_state.registers,
        encoded[23 .. 23 + apu.REGISTER_COUNT],
    );
    try std.testing.expectEqualSlices(
        u8,
        &.{ 1, 1, 0x0a, 2, 3 },
        encoded[23 + apu.REGISTER_COUNT ..],
    );

    const digest = subject.publicDigest(statement);
    var changed = statement;
    changed.final_halt_bug = true;
    try expectDigestChanged(digest, subject.publicDigest(changed));
    changed = statement;
    changed.final_dma.page = 3;
    try expectDigestChanged(digest, subject.publicDigest(changed));
    inline for (.{ "scy", "scx", "wy" }) |field| {
        changed = statement;
        @field(changed.final_ppu, field) = 1;
        try expectDigestChanged(digest, subject.publicDigest(changed));
    }
    changed = statement;
    changed.final_apu.registers[0] ^= 1;
    try expectDigestChanged(digest, subject.publicDigest(changed));
    changed = statement;
    changed.final_apu.enabled = true;
    try expectDigestChanged(digest, subject.publicDigest(changed));
    try expectDigestChanged(
        try subject.endpointDigest(false, .{}, .{}, .{ .clock = 100 }),
        try subject.endpointDigest(true, .{}, .{}, .{ .clock = 100 }),
    );
}

test "v7 fails closed on projections, images, geometry, and claims" {
    const system = try std.testing.allocator.alloc(
        u8,
        memory_lookup.SYSTEM_SIZE,
    );
    defer std.testing.allocator.free(system);
    @memset(system, 0);
    setPpuRegisters(system);

    const base = baseStatement();
    var bad_machine = machineState(false);
    bad_machine.cpu.a = 1;
    try std.testing.expectError(
        error.InitialMachineCpuMismatch,
        subject.init(
            base,
            bad_machine,
            machineState(false),
            .{},
            .{},
            .{},
            .{},
            .{ .clock = 100 },
            .{ .clock = 116 },
            0,
            6,
            4,
            5,
            images(system),
            images(system),
        ),
    );
    bad_machine = machineState(false);
    bad_machine.interrupt_flags = 1;
    try std.testing.expectError(
        error.InitialInterruptFlagsMismatch,
        subject.init(
            base,
            bad_machine,
            machineState(false),
            .{},
            .{},
            .{},
            .{},
            .{ .clock = 100 },
            .{ .clock = 116 },
            0,
            6,
            4,
            5,
            images(system),
            images(system),
        ),
    );

    var statement = try initStatement(system);
    statement.version += 1;
    try std.testing.expectError(
        error.InvalidMachineEnvironmentVersion,
        subject.validateShape(statement),
    );
    statement = try initStatement(system);
    statement.ppu_log_size = 3;
    try std.testing.expectError(
        error.InvalidPpuLogSize,
        subject.validateShape(statement),
    );
    statement = try initStatement(system);
    statement.apu_log_size = 3;
    try std.testing.expectError(
        error.InvalidApuLogSize,
        subject.validateShape(statement),
    );
    statement = try initStatement(system);
    statement.expected_service_count = 17;
    try std.testing.expectError(
        error.TooManyInterruptServices,
        subject.validateShape(statement),
    );
    statement = try initStatement(system);
    statement.final_dma.clock += 1;
    try std.testing.expectError(
        error.FinalDmaClockMismatch,
        subject.validateShape(statement),
    );

    system[ppu_mmio.STAT_ADDRESS] = 0;
    try std.testing.expectError(
        error.InitialPpuRegisterMismatch,
        initStatement(system),
    );
    setPpuRegisters(system);
    inline for (.{
        ppu_mmio.SCY_ADDRESS,
        ppu_mmio.SCX_ADDRESS,
        ppu_mmio.WY_ADDRESS,
    }) |address| {
        system[address] = 1;
        try std.testing.expectError(
            error.InitialPpuRegisterMismatch,
            initStatement(system),
        );
        system[address] = 0;
    }
    system[dma.DMA_ADDRESS] = 1;
    try std.testing.expectError(
        error.InitialDmaPageMismatch,
        initStatement(system),
    );
    system[dma.DMA_ADDRESS] = (dma.State{}).page;
    system[apu.FIRST_ADDRESS] = 1;
    try std.testing.expectError(
        error.InitialApuRegisterMismatch,
        initStatement(system),
    );
}

test "v7 transcript and cancellation cover every appended claim family" {
    const system = try std.testing.allocator.alloc(
        u8,
        memory_lookup.SYSTEM_SIZE,
    );
    defer std.testing.allocator.free(system);
    @memset(system, 0);
    setPpuRegisters(system);

    var statement = try initStatement(system);
    statement.dma_execution_lookup_claims.execution_count = 16;
    statement.dma_execution_lookup_claims.dma_count = 16;
    try subject.verifyLookupCancellation(statement);
    const digest = lookupDigest(statement);

    var changed = statement;
    changed.scheduler_memory_lookup_claims.samples[0] =
        QM31.fromU32Unchecked(1, 2, 3, 4);
    try expectDigestChanged(digest, lookupDigest(changed));
    changed.base.base.memory_lookup_claims.boundary =
        changed.scheduler_memory_lookup_claims.samples[0].neg();
    try subject.verifyLookupCancellation(changed);
    changed = statement;
    changed.base.joypad_if_memory_claim = QM31.one();
    changed.base.base.memory_lookup_claims.boundary =
        QM31.one().neg();
    try subject.verifyLookupCancellation(changed);

    inline for (.{ 0, 1, 2, 3, 4, 5 }) |family| {
        changed = statement;
        switch (family) {
            0 => changed.interrupt_service_memory_lookup_claims
                .operations[0] = QM31.one(),
            1 => changed.ppu_mmio_lookup_claims.execution[0][0] =
                QM31.one(),
            2 => changed.ppu_if_memory_claim = QM31.one(),
            3 => changed.dma_execution_lookup_claims.execution[0] =
                QM31.one(),
            4 => changed.dma_memory_claims[0] = QM31.one(),
            5 => changed.ppu_execution_policy_claims.dma = QM31.one(),
            else => unreachable,
        }
        try expectDigestChanged(digest, lookupDigest(changed));
    }
    changed = statement;
    changed.ppu_execution_policy_claims.ppu = QM31.one();
    try expectDigestChanged(digest, lookupDigest(changed));

    changed = statement;
    changed.ppu_if_memory_claim = QM31.one();
    try std.testing.expectError(
        error.CartridgeMemoryLookupSumNonZero,
        subject.verifyLookupCancellation(changed),
    );
    changed = statement;
    changed.ppu_mmio_lookup_claims.ppu[0] = QM31.one();
    try std.testing.expectError(
        error.PpuMmioLookupSumNonZero,
        subject.verifyLookupCancellation(changed),
    );
    changed = statement;
    changed.ppu_execution_policy_claims.ppu = QM31.one();
    try std.testing.expectError(
        error.PpuExecutionPolicyLookupSumNonZero,
        subject.verifyLookupCancellation(changed),
    );
    changed = statement;
    changed.dma_execution_lookup_claims.execution[0] = QM31.one();
    try std.testing.expectError(
        error.DmaExecutionLookupSumNonZero,
        subject.verifyLookupCancellation(changed),
    );
    changed = statement;
    changed.interrupt_service_memory_lookup_claims.service_count = 1;
    try std.testing.expectError(
        error.InterruptServiceCountMismatch,
        subject.verifyLookupCancellation(changed),
    );
    changed = statement;
    changed.dma_execution_lookup_claims.dma_count -= 1;
    try std.testing.expectError(
        error.DmaExecutionCountMismatch,
        subject.verifyLookupCancellation(changed),
    );
}
