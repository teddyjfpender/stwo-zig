//! Honest CPU/SIMD proof gate for the complete v7 machine environment.

const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const pcs_core = @import("stwo_core").pcs;
const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
const frontend = @import("stwo_sm83_frontend");
const cartridge_fixture = @import("cartridge_test.zig");
const test_options = @import("machine_environment_test_options");

const prover = frontend.machine_environment_prover;
const verifier = frontend.machine_environment_verifier;
const ProverEngine = prover.ProverEngineForBackend(CpuBackend);
const VerifierEngine = verifier.ProverEngineForBackend(CpuBackend);

const TRACE_LOG: u8 = test_options.log_size;
const TRACE_SIZE: usize = @as(usize, 1) << @intCast(TRACE_LOG);
const PROGRAM_START: u16 = 0xff80;
const INITIAL_MCYCLE: u32 = 7;
const IF: u16 = 0xff0f;
const IE: u16 = 0xffff;
const OBSERVED: u16 = 0xc100;
const DMA_PAGE: u8 = 0xc0;
const DMA_SOURCE_START: u16 = @as(u16, DMA_PAGE) << 8;

const regions = [_]frontend.ram_observation.Region{.{
    .space = .system,
    .start = OBSERVED,
    .length = 1,
}};
const observations =
    [_]frontend.air.intermediate_ram_observation_lookup.Sample{.{
        .mcycle = INITIAL_MCYCLE,
        .key = OBSERVED,
        .expected = 0x42,
    }};
const actions = [_]frontend.action_schedule.Action{.{
    .mcycle = INITIAL_MCYCLE,
    .pressed = frontend.runner.joypad.Key.a.mask(),
}};

test "machine environment CPU proof roundtrip and adversarial mutations" {
    cartridge_fixture.proof_run_mutex.lock();
    defer cartridge_fixture.proof_run_mutex.unlock();
    comptime {
        prover.assertProverEngine(ProverEngine);
        verifier.assertProverEngine(VerifierEngine);
    }

    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    var scheduler = try frontend.machine.CartridgeMachine.init(
        &fixture.memory,
        .{ .pc = PROGRAM_START, .sp = 0xc000 },
    );
    const initial_timer = scheduler.timer;
    var initial = try Snapshot.capture(
        std.testing.allocator,
        fixture.system,
        fixture.sram,
    );
    defer initial.deinit();
    const results = try std.testing.allocator.alloc(
        frontend.CartridgeMachineStepResult,
        TRACE_SIZE,
    );
    defer std.testing.allocator.free(results);
    for (results) |*result| result.* = try scheduler.step();
    const total_mcycles = totalMcycles(results);
    const dma_transfer_count = @min(
        total_mcycles,
        @as(usize, frontend.runner.dma.OAM_LENGTH),
    );
    const dma_source_bytes =
        fixture.system[DMA_SOURCE_START..][0..dma_transfer_count];
    var final = try Snapshot.capture(
        std.testing.allocator,
        fixture.system,
        fixture.sram,
    );
    defer final.deinit();
    @memcpy(
        final.system[frontend.runner.dma.OAM_START..][0..dma_transfer_count],
        dma_source_bytes,
    );
    const initial_joypad = try frontend.runner.joypad.State.init(
        0xff,
        0,
        3,
        0,
    );
    var final_joypad = initial_joypad;
    try std.testing.expect(
        !final_joypad.setPressed(actions[0].pressed),
    );
    setEndpoints(
        &initial,
        &final,
        initial_timer,
        results[results.len - 1].after,
        initial_joypad,
        final_joypad,
    );
    try expectCoverage(results, total_mcycles, dma_transfer_count);

    const rom = fixture.memory.cartridge;
    const initial_images = try initial.images();
    const final_images = try final.images();
    const input = prover.Input{
        .rom = rom,
        .initial_images = initial_images,
        .final_images = final_images,
        .initial_mcycle = INITIAL_MCYCLE,
        .initial_joypad = initial_joypad,
        .initial_timer = initial_timer,
        .initial_ppu = .{},
        .initial_apu = .{},
        .initial_dma = .{
            .clock = INITIAL_MCYCLE,
            .page = DMA_PAGE,
            .phase = .transfer,
        },
        .actions = &actions,
        .observation_regions = &regions,
        .intermediate_observations = &observations,
        .results = results,
        .dma_source_bytes = dma_source_bytes,
    };
    const config = try cartridge_fixture.testConfig();

    var honest = try prove(config, input);
    var honest_owned = true;
    defer if (honest_owned)
        honest.proof.deinit(std.testing.allocator);
    var public_proof = try cloneProof(
        std.testing.allocator,
        honest.proof,
    );
    var public_owned = true;
    defer if (public_owned)
        public_proof.deinit(std.testing.allocator);
    var lookup_proof = try cloneProof(
        std.testing.allocator,
        honest.proof,
    );
    var lookup_owned = true;
    defer if (lookup_owned)
        lookup_proof.deinit(std.testing.allocator);
    honest_owned = false;
    try verifier.verifyExecutionWithEngine(
        VerifierEngine,
        std.testing.allocator,
        config,
        rom,
        initial_images,
        final_images,
        &actions,
        &regions,
        &observations,
        honest.statement,
        honest.proof,
    );
    try std.testing.expectEqual(
        @as(u32, actions.len),
        honest.statement.base.action_count,
    );
    try std.testing.expectEqualDeep(
        final_joypad,
        honest.statement.base.final_joypad,
    );
    try std.testing.expectEqual(
        TRACE_LOG,
        honest.statement.base.base.log_size,
    );
    try std.testing.expectEqual(
        @as(u32, @intCast(total_mcycles)),
        honest.statement.dma_execution_lookup_claims.execution_count,
    );
    try std.testing.expectEqual(
        @as(u32, @intCast(total_mcycles)),
        honest.statement.dma_execution_lookup_claims.dma_count,
    );
    try std.testing.expectEqual(
        @as(u32, 0),
        honest.statement.expected_service_count,
    );
    try std.testing.expectEqualDeep(
        expectedFinalDma(total_mcycles),
        honest.statement.final_dma,
    );
    try std.testing.expectEqualSlices(
        u8,
        dma_source_bytes,
        final.system[frontend.runner.dma.OAM_START..][0..dma_transfer_count],
    );

    var action_mutation = actions;
    action_mutation[0].pressed = frontend.runner.joypad.Key.b.mask();
    try std.testing.expectError(
        error.ActionDigestMismatch,
        verifier.testing.validatePublicAndShape(
            honest.statement,
            rom,
            initial_images,
            final_images,
            &action_mutation,
            &regions,
            &observations,
            4,
        ),
    );

    var dma_source_mutation =
        try std.testing.allocator.dupe(u8, dma_source_bytes);
    defer std.testing.allocator.free(dma_source_mutation);
    dma_source_mutation[0] ^= 1;
    var forged_input = input;
    forged_input.dma_source_bytes = dma_source_mutation;
    try std.testing.expectError(
        error.InvalidDmaSourceValue,
        prove(config, forged_input),
    );

    var poisoned = try prover.prepare(std.testing.allocator, input);
    var poisoned_owned = true;
    defer if (poisoned_owned)
        poisoned.deinit(std.testing.allocator);
    try prover.testing.poisonPpuPolicySelector(&poisoned);
    poisoned_owned = false;
    try std.testing.expectError(
        error.ConstraintsNotSatisfied,
        prover.testing.provePreparedWithEngine(
            ProverEngine,
            std.testing.allocator,
            config,
            poisoned,
            .{},
        ),
    );

    var public_statement = honest.statement;
    public_statement.final_halt_bug =
        !public_statement.final_halt_bug;
    try verifier.testing.validatePublicAndShape(
        public_statement,
        rom,
        initial_images,
        final_images,
        &actions,
        &regions,
        &observations,
        4,
    );
    public_owned = false;
    try expectVerificationRejected(
        config,
        rom,
        initial_images,
        final_images,
        public_statement,
        public_proof,
        &actions,
    );

    var lookup_statement = honest.statement;
    lookup_statement.scheduler_memory_lookup_claims.samples[0] =
        lookup_statement.scheduler_memory_lookup_claims.samples[0]
            .add(QM31.one());
    lookup_statement.base.base.memory_lookup_claims.boundary =
        lookup_statement.base.base.memory_lookup_claims.boundary
            .sub(QM31.one());
    try verifier.testing.validateLookupClaims(lookup_statement);
    lookup_owned = false;
    try expectVerificationRejected(
        config,
        rom,
        initial_images,
        final_images,
        lookup_statement,
        lookup_proof,
        &actions,
    );

    var vacuous = honest.statement;
    vacuous.dma_execution_lookup_claims.execution_count = 0;
    vacuous.dma_execution_lookup_claims.dma_count = 0;
    try std.testing.expectError(
        error.EmptyDmaExecutionLookup,
        verifier.testing.validateLookupClaims(vacuous),
    );
}

fn cloneProof(
    allocator: std.mem.Allocator,
    source: verifier.Proof,
) !verifier.Proof {
    const Hasher = verifier.Hasher;
    const proof = source.commitment_scheme_proof;

    var commitments = core.pcs.TreeVec(Hasher.Hash).initOwned(
        try allocator.dupe(Hasher.Hash, proof.commitments.items),
    );
    errdefer commitments.deinit(allocator);
    var sampled = core.pcs.TreeVec([][]QM31).initOwned(
        try cloneSlice(
            [][]QM31,
            allocator,
            proof.sampled_values.items,
        ),
    );
    errdefer sampled.deinitDeep(allocator);
    var decommitments = try cloneDecommitments(
        allocator,
        proof.decommitments,
    );
    errdefer {
        for (decommitments.items) |*item| item.deinit(allocator);
        decommitments.deinit(allocator);
    }

    var queried = core.pcs.TreeVec([][]M31).initOwned(
        try cloneSlice(
            [][]M31,
            allocator,
            proof.queried_values.items,
        ),
    );
    errdefer queried.deinitDeep(allocator);
    var first_layer = try cloneFriLayer(
        allocator,
        proof.fri_proof.first_layer,
    );
    errdefer first_layer.deinit(allocator);
    const inner_layers = try allocator.alloc(
        core.fri.FriLayerProof(Hasher),
        proof.fri_proof.inner_layers.len,
    );
    var inner_count: usize = 0;
    errdefer {
        for (inner_layers[0..inner_count]) |*layer|
            layer.deinit(allocator);
        allocator.free(inner_layers);
    }
    for (proof.fri_proof.inner_layers, inner_layers) |layer, *copy| {
        copy.* = try cloneFriLayer(allocator, layer);
        inner_count += 1;
    }
    var last_layer = core.poly.line.LinePoly.initOwned(
        try allocator.dupe(
            QM31,
            proof.fri_proof.last_layer_poly.coefficients(),
        ),
    );
    errdefer last_layer.deinit(allocator);

    return .{ .commitment_scheme_proof = .{
        .config = proof.config,
        .commitments = commitments,
        .sampled_values = sampled,
        .decommitments = decommitments,
        .queried_values = queried,
        .proof_of_work = proof.proof_of_work,
        .fri_proof = .{
            .first_layer = first_layer,
            .inner_layers = inner_layers,
            .last_layer_poly = last_layer,
        },
    } };
}

fn cloneDecommitments(
    allocator: std.mem.Allocator,
    source: core.pcs.TreeVec(
        core.vcs_lifted.verifier.MerkleDecommitmentLifted(
            verifier.Hasher,
        ),
    ),
) !core.pcs.TreeVec(
    core.vcs_lifted.verifier.MerkleDecommitmentLifted(
        verifier.Hasher,
    ),
) {
    const Decommitment =
        core.vcs_lifted.verifier.MerkleDecommitmentLifted(
            verifier.Hasher,
        );
    const items = try allocator.alloc(Decommitment, source.items.len);
    var initialized: usize = 0;
    errdefer {
        for (items[0..initialized]) |*item| item.deinit(allocator);
        allocator.free(items);
    }
    for (source.items, items) |item, *copy| {
        copy.* = .{
            .hash_witness = try allocator.dupe(
                verifier.Hasher.Hash,
                item.hash_witness,
            ),
        };
        initialized += 1;
    }
    return core.pcs.TreeVec(Decommitment).initOwned(items);
}

fn cloneFriLayer(
    allocator: std.mem.Allocator,
    source: core.fri.FriLayerProof(verifier.Hasher),
) !core.fri.FriLayerProof(verifier.Hasher) {
    const witness = try allocator.dupe(QM31, source.fri_witness);
    errdefer allocator.free(witness);
    return .{
        .fri_witness = witness,
        .decommitment = .{
            .hash_witness = try allocator.dupe(
                verifier.Hasher.Hash,
                source.decommitment.hash_witness,
            ),
        },
        .commitment = source.commitment,
    };
}

fn cloneSlice(
    comptime T: type,
    allocator: std.mem.Allocator,
    source: []const T,
) ![]T {
    const result = try allocator.alloc(T, source.len);
    var initialized: usize = 0;
    errdefer {
        if (comptime isSlice(T))
            for (result[0..initialized]) |value|
                freeSlice(@typeInfo(T).pointer.child, allocator, value);
        allocator.free(result);
    }
    for (source, result) |value, *copy| {
        if (comptime isSlice(T)) {
            copy.* = try cloneSlice(
                @typeInfo(T).pointer.child,
                allocator,
                value,
            );
        } else {
            copy.* = value;
        }
        initialized += 1;
    }
    return result;
}

fn freeSlice(
    comptime T: type,
    allocator: std.mem.Allocator,
    values: []T,
) void {
    if (comptime isSlice(T))
        for (values) |value|
            freeSlice(@typeInfo(T).pointer.child, allocator, value);
    allocator.free(values);
}

fn isSlice(comptime T: type) bool {
    return switch (@typeInfo(T)) {
        .pointer => |pointer| pointer.size == .slice,
        else => false,
    };
}

fn prove(
    config: pcs_core.PcsConfig,
    input: prover.Input,
) !prover.ProveOutput {
    return prover.proveExecutionWithEngine(
        ProverEngine,
        std.testing.allocator,
        config,
        input,
        .{},
    );
}

fn expectVerificationRejected(
    config: pcs_core.PcsConfig,
    rom: frontend.cartridge.Cartridge,
    initial_images: frontend.air.cartridge_memory_lookup.Images,
    final_images: frontend.air.cartridge_memory_lookup.Images,
    statement: verifier.ExecutionStatement,
    proof: verifier.Proof,
    provided_actions: []const frontend.action_schedule.Action,
) !void {
    if (verifier.verifyExecutionWithEngine(
        VerifierEngine,
        std.testing.allocator,
        config,
        rom,
        initial_images,
        final_images,
        provided_actions,
        &regions,
        &observations,
        statement,
        proof,
    )) {
        return error.ExpectedMutationRejection;
    } else |_| {}
}

fn expectCoverage(
    results: []const frontend.CartridgeMachineStepResult,
    total_mcycles: usize,
    dma_transfer_count: usize,
) !void {
    try std.testing.expectEqual(TRACE_SIZE, results.len);
    try std.testing.expectEqual(
        TRACE_SIZE,
        total_mcycles,
    );
    try std.testing.expectEqual(
        @min(
            total_mcycles,
            @as(usize, frontend.runner.dma.OAM_LENGTH),
        ),
        dma_transfer_count,
    );
    var instruction_count: usize = 0;
    var service_count: usize = 0;
    for (results) |result| switch (result.event) {
        .instruction => instruction_count += 1,
        .interrupt_service => service_count += 1,
        .halt_idle, .halt_wake => {},
    };
    try std.testing.expectEqual(TRACE_SIZE, instruction_count);
    try std.testing.expectEqual(@as(usize, 0), service_count);
    try std.testing.expectEqual(
        frontend.machine.SchedulerEvent.instruction,
        results[0].event,
    );
    try std.testing.expectEqual(
        frontend.machine.SchedulerEvent.instruction,
        results[2].event,
    );
    try std.testing.expectEqual(@as(?u3, null), results[2].interrupt_index);
    try std.testing.expectEqual(PROGRAM_START + 3, results[2].after.cpu.pc);
    for (results[0 .. TRACE_SIZE - 1], results[1..]) |before, after|
        try std.testing.expectEqualDeep(before.after, after.before);
}

fn expectedFinalDma(total_mcycles: usize) frontend.runner.dma.State {
    const completed =
        total_mcycles > @as(usize, frontend.runner.dma.OAM_LENGTH);
    return .{
        .clock = INITIAL_MCYCLE + @as(u32, @intCast(total_mcycles)),
        .page = DMA_PAGE,
        .copied = if (completed)
            0
        else
            @intCast(total_mcycles),
        .phase = if (completed)
            .idle
        else if (total_mcycles ==
            @as(usize, frontend.runner.dma.OAM_LENGTH))
            .finishing
        else
            .transfer,
    };
}

const Fixture = struct {
    rom: *[frontend.cartridge.header.ROM_SIZE]u8,
    sram: *[frontend.cartridge.header.RAM_SIZE]u8,
    system: *[frontend.runner.cartridge_memory.SYSTEM_SIZE]u8,
    memory: frontend.runner.cartridge_memory.Memory,
    allocator: std.mem.Allocator,

    fn init(allocator: std.mem.Allocator) !Fixture {
        const rom =
            try allocator.create([frontend.cartridge.header.ROM_SIZE]u8);
        errdefer allocator.destroy(rom);
        const sram =
            try allocator.create([frontend.cartridge.header.RAM_SIZE]u8);
        errdefer allocator.destroy(sram);
        const system = try allocator.create(
            [frontend.runner.cartridge_memory.SYSTEM_SIZE]u8,
        );
        errdefer allocator.destroy(system);
        @memset(rom, 0);
        @memset(sram, 0);
        @memset(system, 0);
        system[PROGRAM_START] = 0x00;
        rom[0x40] = 0x18;
        rom[0x41] = 0xfe;
        system[OBSERVED] = 0x42;
        system[IF] = 1;
        system[IE] = 1;
        system[frontend.runner.dma.DMA_ADDRESS] = DMA_PAGE;
        for (
            system[DMA_SOURCE_START .. DMA_SOURCE_START +
                frontend.runner.dma.OAM_LENGTH],
            0..,
        ) |*byte, index| byte.* = @truncate(index + 1);
        setHeader(rom);
        const loaded = try frontend.cartridge.Cartridge.init(rom);
        return .{
            .rom = rom,
            .sram = sram,
            .system = system,
            .memory = frontend.runner.cartridge_memory.Memory.init(
                loaded,
                sram,
                system,
                .{},
                0xff,
            ),
            .allocator = allocator,
        };
    }

    fn deinit(self: *Fixture) void {
        self.allocator.destroy(self.system);
        self.allocator.destroy(self.sram);
        self.allocator.destroy(self.rom);
        self.* = undefined;
    }
};

const Snapshot = struct {
    system: []u8,
    sram: []u8,
    allocator: std.mem.Allocator,

    fn capture(
        allocator: std.mem.Allocator,
        system: []const u8,
        sram: []const u8,
    ) !Snapshot {
        const system_copy = try allocator.dupe(u8, system);
        errdefer allocator.free(system_copy);
        return .{
            .system = system_copy,
            .sram = try allocator.dupe(u8, sram),
            .allocator = allocator,
        };
    }

    fn deinit(self: *Snapshot) void {
        self.allocator.free(self.sram);
        self.allocator.free(self.system);
        self.* = undefined;
    }

    fn images(self: Snapshot) !frontend.air.cartridge_memory_lookup.Images {
        return .{
            .system = try frontend.memory.Image.init(self.system),
            .sram = try frontend.air.cartridge_memory_lookup.SramImage.init(
                self.sram,
            ),
        };
    }
};

fn setHeader(rom: *[frontend.cartridge.header.ROM_SIZE]u8) void {
    rom[frontend.cartridge.header.CARTRIDGE_TYPE_OFFSET] =
        frontend.cartridge.header.CARTRIDGE_TYPE_MBC3_RAM_BATTERY;
    rom[frontend.cartridge.header.ROM_SIZE_CODE_OFFSET] =
        frontend.cartridge.header.ROM_SIZE_CODE_1_MIB;
    rom[frontend.cartridge.header.RAM_SIZE_CODE_OFFSET] =
        frontend.cartridge.header.RAM_SIZE_CODE_32_KIB;
    rom[frontend.cartridge.header.HEADER_CHECKSUM_OFFSET] =
        frontend.cartridge.header.headerChecksum(rom);
    std.mem.writeInt(
        u16,
        rom[frontend.cartridge.header.GLOBAL_CHECKSUM_OFFSET..frontend.cartridge.header.HEADER_END][0..2],
        frontend.cartridge.header.globalChecksum(rom),
        .big,
    );
}

fn setEndpoints(
    initial: *Snapshot,
    final: *Snapshot,
    initial_timer: frontend.runner.timer.Timer,
    final_machine: frontend.machine.MachineState,
    initial_joypad: frontend.runner.joypad.State,
    final_joypad: frontend.runner.joypad.State,
) void {
    initial.system[frontend.runner.joypad.P1_ADDRESS] =
        initial_joypad.readP1();
    final.system[frontend.runner.joypad.P1_ADDRESS] =
        final_joypad.readP1();
    setTimer(initial.system, initial_timer);
    setTimer(final.system, .{
        .div_counter = final_machine.div_counter,
        .tima = final_machine.tima,
        .tma = final_machine.tma,
        .tac = @truncate(final_machine.tac),
        .reload_state = final_machine.timer_reload,
    });
    setPpu(initial.system, .{});
    setPpu(final.system, .{});
    initial.system[frontend.runner.dma.DMA_ADDRESS] = DMA_PAGE;
    final.system[frontend.runner.dma.DMA_ADDRESS] = DMA_PAGE;
}

fn totalMcycles(
    results: []const frontend.CartridgeMachineStepResult,
) usize {
    var count: usize = 0;
    for (results) |result| count += result.m_cycles;
    return count;
}

fn setTimer(
    system: []u8,
    timer: frontend.runner.timer.Timer,
) void {
    system[0xff04] = timer.readDiv();
    system[0xff05] = timer.readTima();
    system[0xff06] = timer.readTma();
    system[0xff07] = timer.readTac();
}

fn setPpu(
    system: []u8,
    ppu: frontend.air.ppu_binding.State,
) void {
    system[frontend.runner.ppu_mmio.LCDC_ADDRESS] = ppu.read(.lcdc);
    system[frontend.runner.ppu_mmio.STAT_ADDRESS] = ppu.read(.stat);
    system[frontend.runner.ppu_mmio.LY_ADDRESS] = ppu.read(.ly);
    system[frontend.runner.ppu_mmio.LYC_ADDRESS] = ppu.read(.lyc);
}
