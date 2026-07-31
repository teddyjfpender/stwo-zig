//! Backend-generic coordinator for complete v7 SM83 machine proofs.

const std = @import("std");
const core_proof = @import("stwo_core").proof;
const M31 = @import("stwo_core").fields.m31.M31;
const pcs_core = @import("stwo_core").pcs;
const prover_api = @import("stwo_prover_api");
const prover_engine = @import("stwo_prover_engine").engine;
const transaction = @import("stwo_prover_engine").transaction;
const environment_prover = @import("environment_prover.zig");
const base_statement = @import("cartridge_proof_statement.zig");
const environment_statement = @import("environment_statement.zig");
const protocol = @import("machine_environment_statement.zig");
const trace_assembly = @import("machine_environment_trace.zig");
const interaction =
    @import("machine_environment_proof_interaction.zig");
const components = @import("machine_environment_proof_components.zig");
const replay_mod = @import("machine_environment_memory_replay.zig");
const cartridge_prover = @import("cartridge_prover.zig");
const cartridge = @import("cartridge/mod.zig");
const action_schedule = @import("action_schedule.zig");
const joypad_trace = @import("joypad_trace.zig");
const ram_observation = @import("ram_observation.zig");
const runner = @import("runner/mod.zig");
const machine = @import("runner/machine.zig");
const machine_trace = @import("air/machine_scheduler_trace.zig");
const memory_lookup = @import("air/cartridge_memory_lookup.zig");
const rom_lookup = @import("air/cartridge_rom_lookup.zig");
const joypad_binding = @import("air/joypad_binding.zig");
const joypad_if = @import("air/joypad_if_memory_lookup.zig");
const timer_binding = @import("air/timer_binding.zig");
const timer_if = @import("air/timer_if_memory_lookup.zig");
const observation =
    @import("air/intermediate_ram_observation_lookup.zig");
const service_memory =
    @import("air/interrupt_service_memory_lookup.zig");
const ppu_binding = @import("air/ppu_binding.zig");
const ppu_execution_policy = @import("ppu_execution_policy.zig");
const ppu_mmio = @import("air/ppu_mmio_lookup.zig");
const ppu_if = @import("air/ppu_if_memory_lookup.zig");
const apu_binding = @import("air/apu_binding.zig");
const apu_execution_lookup = @import("air/apu_execution_lookup.zig");
const dma_binding = @import("air/dma_binding.zig");
const dma_memory = @import("air/dma_memory_lookup.zig");

pub const Hasher = environment_prover.Hasher;
pub const MerkleChannel = environment_prover.MerkleChannel;
pub const Channel = environment_prover.Channel;
pub const Proof = core_proof.StarkProof(Hasher);
pub const ExecutionStatement = protocol.ExecutionStatement;

pub const Input = struct {
    rom: cartridge.Cartridge,
    initial_images: memory_lookup.Images,
    final_images: memory_lookup.Images,
    initial_mcycle: u32,
    initial_joypad: runner.joypad.State,
    initial_timer: runner.timer.Timer,
    initial_ppu: ppu_binding.State,
    initial_apu: runner.apu_mmio.State,
    initial_dma: runner.dma.State,
    actions: []const action_schedule.Action,
    observation_regions: []const ram_observation.Region,
    intermediate_observations: []const observation.Sample,
    results: []const machine.CartridgeStepResult,
    dma_source_bytes: []const u8,
};

pub const ProveOutput = struct {
    statement: ExecutionStatement,
    proof: Proof,
};

pub const PreparedExecution = struct {
    pub const InteractionSourcesState = enum {
        retained,
        released,
    };

    request: ExecutionStatement,
    trace: transaction.PreparedTrace,
    logs: trace_assembly.Logs,
    input: Input,
    joypad: joypad_trace.Trace,
    timer: timer_binding.Trace,
    ppu: ppu_binding.Trace,
    apu: apu_execution_lookup.ExecutionTrace,
    dma: dma_binding.Trace,
    replay: replay_mod.Replay,
    boundary_final_clocks: []M31,
    interaction_sources_state: InteractionSourcesState = .retained,

    pub fn validateGeometry(self: *const PreparedExecution) !void {
        if (self.interaction_sources_state == .released)
            return error.InteractionSourcesReleased;
        var view = trace_assembly.Prepared{
            .trace = self.trace,
            .logs = self.logs,
        };
        try view.validate();
        try self.replay.validate(
            self.replay.allocator,
            self.input.results,
            self.input.initial_images,
            self.input.final_images,
            self.input.initial_mcycle,
            self.joypad.rows,
            self.timer.rows,
            self.ppu.rows,
            self.dma.rows,
            self.input.intermediate_observations,
        );
        if (self.replay.initial_mcycle !=
            self.request.base.base.initial.mcycle or
            self.replay.final_mcycle !=
                self.request.base.base.final.mcycle)
            return error.ReplayClockMismatch;
        if (!equalM31(
            self.boundary_final_clocks,
            self.replay.memory.final_clocks,
        )) return error.BoundaryClockMismatch;
        try apu_execution_lookup.validateAgainstExecution(
            self.apu,
            self.input.results,
            self.input.initial_mcycle,
        );
    }

    pub fn deinit(self: *PreparedExecution, allocator: std.mem.Allocator) void {
        self.trace.deinit(allocator);
        self.releaseInteractionSources(allocator);
        self.* = undefined;
    }

    /// Releases metadata used only to derive the interaction trace.
    ///
    /// Main-column storage was transferred into `trace` during preparation and
    /// is not released here. Calling this method more than once is a no-op.
    pub fn releaseInteractionSources(
        self: *PreparedExecution,
        allocator: std.mem.Allocator,
    ) void {
        if (self.interaction_sources_state == .released) return;
        allocator.free(self.boundary_final_clocks);
        self.replay.deinit();
        self.dma.deinit(allocator);
        self.apu.deinit(allocator);
        self.ppu.deinit(allocator);
        self.timer.deinit(allocator);
        self.joypad.deinit(allocator);
        self.interaction_sources_state = .released;
    }
};

pub fn ProverEngineForBackend(comptime Backend: type) type {
    return prover_engine.ProverEngine(
        Backend,
        Hasher,
        MerkleChannel,
        Channel,
    );
}

pub fn assertProverEngine(comptime Engine: type) void {
    prover_api.assertProverEngine(Engine);
    if (Engine.Hasher != Hasher or
        Engine.MerkleChannel != MerkleChannel or
        Engine.Channel != Channel or
        Engine.ExtendedProof != core_proof.ExtendedStarkProof(Hasher))
    {
        @compileError("SM83 v7 engine uses incompatible protocol types");
    }
}

pub fn proveExecutionWithEngine(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    input: Input,
    options: prover_engine.ProveOptions,
) !ProveOutput {
    comptime assertProverEngine(Engine);
    var output = try transaction.provePreparedEx(
        Engine,
        ProvingSpec,
        false,
        {},
        allocator,
        pcs_config,
        try prepare(allocator, input),
        options,
    );
    const proof = output.proof.proof;
    output.proof.aux.deinit(allocator);
    return .{ .statement = output.statement, .proof = proof };
}

/// Derives every device row, lookup witness, and committed v7 column.
pub fn prepare(
    allocator: std.mem.Allocator,
    input: Input,
) !PreparedExecution {
    if (input.results.len < 16 or
        !std.math.isPowerOfTwo(input.results.len))
        return error.InvalidTraceLength;
    if (input.initial_dma.clock != input.initial_mcycle)
        return error.InitialDmaClockMismatch;
    try validateNoOpenBus(input.results);
    const final_mcycle = try executionFinalMcycle(
        input.initial_mcycle,
        input.results,
    );

    var joypad = try joypad_trace.generateFromMachineExecution(
        allocator,
        input.initial_mcycle,
        final_mcycle,
        input.initial_joypad,
        input.actions,
        input.results,
    );
    var joypad_moved = false;
    defer if (!joypad_moved) joypad.deinit(allocator);
    var timer = try timer_binding.generateFromMachineExecution(
        allocator,
        input.initial_mcycle,
        final_mcycle,
        input.initial_timer,
        input.results,
    );
    var timer_moved = false;
    defer if (!timer_moved) timer.deinit(allocator);
    var ppu = try ppu_binding.generateFromMachineExecution(
        allocator,
        input.initial_mcycle,
        final_mcycle,
        input.initial_ppu,
        input.results,
    );
    var ppu_moved = false;
    defer if (!ppu_moved) ppu.deinit(allocator);
    var apu = try apu_execution_lookup.generateFromMachineExecution(
        allocator,
        input.initial_mcycle,
        input.initial_apu,
        input.results,
    );
    var apu_moved = false;
    defer if (!apu_moved) apu.deinit(allocator);
    var dma = try dma_binding.generateFromMachineExecution(
        allocator,
        input.initial_mcycle,
        final_mcycle,
        input.initial_dma,
        input.results,
        input.dma_source_bytes,
    );
    var dma_moved = false;
    defer if (!dma_moved) dma.deinit(allocator);
    try ppu_execution_policy.validate(input.results, ppu, dma);

    var replay = try replay_mod.generate(
        allocator,
        input.results,
        input.initial_images,
        input.final_images,
        input.initial_mcycle,
        joypad.rows,
        timer.rows,
        ppu.rows,
        dma.rows,
        input.intermediate_observations,
    );
    var replay_moved = false;
    defer if (!replay_moved) replay.deinit();
    const boundary_final_clocks = try allocator.dupe(
        M31,
        replay.memory.final_clocks,
    );
    var boundary_clocks_moved = false;
    defer if (!boundary_clocks_moved)
        allocator.free(boundary_final_clocks);
    var scheduler = try machine_trace.generate(
        allocator,
        input.results,
        &replay,
    );
    defer scheduler.deinit();
    var packed_trace = try cartridge_prover.generatePacked(
        allocator,
        input.results,
        scheduler.log_size,
    );
    defer packed_trace.deinit();
    var joypad_witness =
        try joypad_binding.generateMachineExecutionWitness(
            allocator,
            joypad,
            input.results,
        );
    defer joypad_witness.deinit();
    var joypad_if_witness = try joypad_if.generateWitness(
        allocator,
        joypad_witness.log_size,
        joypad.rows,
        replay.joypad_predecessors,
    );
    defer joypad_if_witness.deinit();
    var timer_witness =
        try timer_binding.generateMachineExecutionWitness(
            allocator,
            timer,
            input.results,
        );
    defer timer_witness.deinit();
    var timer_if_witness = try timer_if.generateWitness(
        allocator,
        timer_witness.log_size,
        timer.rows,
        replay.timer_predecessors,
    );
    defer timer_if_witness.deinit();
    const observation_log_size = try observationLogSize(
        input.intermediate_observations.len,
    );
    var observation_witness = try observation.generateWitness(
        allocator,
        observation_log_size,
        input.intermediate_observations,
        replay.observation_predecessors,
    );
    defer observation_witness.deinit();
    var service_witness = try service_memory.generateWitness(
        allocator,
        input.results,
        .{
            .initial_mcycle = input.initial_mcycle,
            .final_mcycle = final_mcycle,
            .expected_service_count = serviceCount(input.results),
        },
        replay.service_predecessors,
    );
    defer service_witness.deinit();
    var ppu_witness =
        try ppu_binding.generateMachineExecutionWitness(
            allocator,
            ppu,
            input.results,
            input.initial_mcycle,
        );
    defer ppu_witness.deinit();
    var ppu_auxiliary = try ppu_mmio.generateAuxiliaryWitness(
        allocator,
        ppu_witness.log_size,
        ppu.rows,
    );
    defer ppu_auxiliary.deinit();
    var ppu_if_witness = try ppu_if.generateWitness(
        allocator,
        ppu_witness.log_size,
        ppu.rows,
        replay.ppu_predecessors,
    );
    defer ppu_if_witness.deinit();
    var ppu_policy_witness = try ppu_execution_policy.generateWitness(
        allocator,
        ppu_witness.log_size,
        ppu.rows,
        input.results,
    );
    defer ppu_policy_witness.deinit();
    var apu_witness = try apu_binding.generateWitness(
        allocator,
        apu.semantic,
    );
    defer apu_witness.deinit();
    var apu_auxiliary = try apu_execution_lookup.generateAuxiliaryWitness(
        allocator,
        apu,
        input.results,
        input.initial_mcycle,
    );
    defer apu_auxiliary.deinit();
    var dma_witness =
        try dma_binding.generateMachineExecutionWitness(
            allocator,
            dma,
            input.results,
        );
    defer dma_witness.deinit();
    var dma_memory_witness = try dma_memory.generateWitness(
        allocator,
        dma_witness.log_size,
        dma.rows,
        replay.dma_predecessors,
    );
    defer dma_memory_witness.deinit();

    const base = base_statement.init(
        scheduler.log_size,
        scheduler.execution.initial,
        scheduler.execution.final,
        input.results[0].mapper_before,
        input.results[input.results.len - 1].mapper_after,
        input.rom,
        input.initial_images,
        input.final_images,
    );
    const environment = try environment_statement.init(
        base,
        input.rom,
        input.initial_images,
        input.final_images,
        input.actions,
        input.initial_joypad,
        joypad.final_state,
        joypad_witness.log_size,
        input.initial_timer,
        timer.final_state,
        timer_witness.log_size,
        input.observation_regions,
        input.intermediate_observations,
        observation_log_size,
    );
    const request = try protocol.init(
        environment,
        input.results[0].before,
        input.results[input.results.len - 1].after,
        input.initial_ppu,
        ppu.final_state,
        input.initial_apu,
        apu.semantic.final_state,
        input.initial_dma,
        dma.final_state,
        serviceCount(input.results),
        ppu_witness.log_size,
        apu_witness.log_size,
        dma_witness.log_size,
        input.initial_images,
        input.final_images,
    );
    var preprocessed = transaction.OwnedColumns.init(
        try environment_statement.canonicalPreprocessed(
            allocator,
            environment,
            input.rom,
            input.initial_images,
            input.final_images,
            input.actions,
            input.observation_regions,
            input.intermediate_observations,
        ),
    );
    defer preprocessed.deinit(allocator);
    var multiplicity = trace_assembly.OwnedColumn.init(
        rom_lookup.ROM_LOG_SIZE,
        try rom_lookup.committedMultiplicities(
            allocator,
            input.results,
            input.rom.bytes,
        ),
    );
    defer multiplicity.deinit(allocator);

    var assembled = try trace_assembly.assemble(
        allocator,
        .{
            .v3_preprocessed = &preprocessed,
            .machine = &scheduler,
            .packed_access = &packed_trace,
            .memory_replay = &replay,
            .rom_multiplicity = &multiplicity,
            .joypad_binding = &joypad_witness,
            .joypad_if = &joypad_if_witness,
            .timer_binding = &timer_witness,
            .timer_if = &timer_if_witness,
            .observation = &observation_witness,
            .service_memory = &service_witness,
            .ppu_binding = &ppu_witness,
            .ppu_auxiliary = &ppu_auxiliary,
            .ppu_if = &ppu_if_witness,
            .ppu_policy = &ppu_policy_witness,
            .dma_binding = &dma_witness,
            .dma_memory = &dma_memory_witness,
            .apu_binding = &apu_witness,
            .apu_auxiliary = &apu_auxiliary,
        },
    );
    errdefer assembled.deinit(allocator);
    try assembled.validate();
    joypad_moved = true;
    timer_moved = true;
    ppu_moved = true;
    apu_moved = true;
    dma_moved = true;
    replay_moved = true;
    boundary_clocks_moved = true;
    const prepared = PreparedExecution{
        .request = request,
        .trace = assembled.trace,
        .logs = assembled.logs,
        .input = input,
        .joypad = joypad,
        .timer = timer,
        .ppu = ppu,
        .apu = apu,
        .dma = dma,
        .replay = replay,
        .boundary_final_clocks = boundary_final_clocks,
    };
    assembled = undefined;
    return prepared;
}

pub fn requiredCompositionLog(
    execution_log_size: u32,
    joypad_log_size: u32,
    timer_log_size: u32,
    observation_log_size: u32,
    ppu_log_size: u32,
    dma_log_size: u32,
    apu_log_size: u32,
) error{InvalidLogSize}!u32 {
    const base = try cartridge_prover.requiredCompositionLog(
        execution_log_size,
    );
    var result = base;
    inline for (.{
        joypad_log_size,
        timer_log_size,
        observation_log_size,
        dma_log_size,
        apu_log_size,
    }) |log_size| {
        const candidate = std.math.add(u32, log_size, 1) catch
            return error.InvalidLogSize;
        result = @max(result, candidate);
    }
    const ppu_candidate = std.math.add(u32, ppu_log_size, 2) catch
        return error.InvalidLogSize;
    result = @max(result, ppu_candidate);
    return result;
}

const ProvingSpec = struct {
    pub const Statement = ExecutionStatement;
    pub const PreparedInput = PreparedExecution;
    pub const ProverContext = components.Context;
    pub const PreparedInteraction = interaction.Prepared;
    pub const max_components = components.N_COMPONENTS;

    pub fn validateRequest(request: Statement) !void {
        try protocol.validateShape(request);
    }

    pub fn validatePrepared(prepared: *const PreparedInput) !void {
        try prepared.validateGeometry();
    }

    pub fn compositionLog(request: Statement) !u32 {
        return requiredCompositionLog(
            request.base.base.log_size,
            request.base.joypad_log_size,
            request.base.timer_log_size,
            request.base.intermediate_observation_log_size,
            request.ppu_log_size,
            request.dma_log_size,
            request.apu_log_size,
        );
    }

    pub fn beforeMainCommit(channel: *Channel, request: Statement) !void {
        protocol.mixPublic(channel, request);
    }

    pub fn prepareInteraction(
        allocator: std.mem.Allocator,
        channel: *Channel,
        prepared: *PreparedInput,
    ) !PreparedInteraction {
        const generated = try interaction.generate(
            allocator,
            channel,
            .{
                .request = prepared.request,
                .results = prepared.input.results,
                .rom = prepared.input.rom,
                .initial_images = prepared.input.initial_images,
                .final_images = prepared.input.final_images,
                .actions = prepared.input.actions,
                .observation_regions = prepared.input.observation_regions,
                .intermediate_observations = prepared.input.intermediate_observations,
                .joypad_events = prepared.joypad.rows,
                .timer_events = prepared.timer.rows,
                .ppu_events = prepared.ppu.rows,
                .dma_events = prepared.dma.rows,
                .apu_trace = prepared.apu,
                .replay = &prepared.replay,
                .boundary_final_clocks = prepared.boundary_final_clocks,
            },
        );
        prepared.releaseInteractionSources(allocator);
        return generated;
    }

    pub fn deinitPreparedInteraction(
        prepared: *PreparedInteraction,
        allocator: std.mem.Allocator,
    ) void {
        prepared.deinit(allocator);
    }

    pub fn beforeInteractionCommit(
        channel: *Channel,
        request: Statement,
        prepared: *const PreparedInteraction,
    ) !void {
        var claimed = request;
        prepared.claims.applyTo(&claimed);
        protocol.mixLookupClaims(channel, claimed);
    }

    pub fn initProverContext(
        out: *ProverContext,
        _: *Channel,
        request: Statement,
        prepared: *const PreparedInteraction,
    ) !void {
        var claimed = request;
        prepared.claims.applyTo(&claimed);
        try protocol.verifyLookupCancellation(claimed);
        components.init(
            out,
            claimed,
            prepared.rom_relation,
            prepared.memory_relation,
            prepared.action_relation,
            prepared.joypad_mmio_relations,
            prepared.timer_mmio_relations,
            prepared.ppu_mmio_relations,
            prepared.dma_execution_relations,
            prepared.apu_execution_relation,
        );
    }

    pub fn statement(context: *const ProverContext) Statement {
        return context.statement_value;
    }

    pub fn proverComponents(
        context: *const ProverContext,
        out: []components.ProverComponent,
    ) ![]const components.ProverComponent {
        return components.prover(context, out);
    }
};

fn executionFinalMcycle(
    initial: u32,
    results: []const machine.CartridgeStepResult,
) !u32 {
    var mcycle = initial;
    for (results) |result|
        mcycle = std.math.add(u32, mcycle, result.m_cycles) catch
            return error.MachineClockOverflow;
    return mcycle;
}

fn serviceCount(results: []const machine.CartridgeStepResult) u32 {
    var count: u32 = 0;
    for (results) |result| {
        if (result.event == .interrupt_service) count += 1;
    }
    return count;
}

fn validateNoOpenBus(
    results: []const machine.CartridgeStepResult,
) error{UnsupportedOpenBus}!void {
    for (results) |result| {
        if (result.instruction) |instruction| {
            for (instruction.activeAccesses()) |maybe_access| {
                const access = maybe_access orelse continue;
                if (access.region == .cartridge_open_bus)
                    return error.UnsupportedOpenBus;
            }
        }
        for (result.service.activeCycles()) |cycle| {
            const access = cycle.access orelse continue;
            if (access.region == .cartridge_open_bus)
                return error.UnsupportedOpenBus;
        }
    }
}

fn observationLogSize(count: usize) error{InvalidLogSize}!u32 {
    if (count == 0) return error.InvalidLogSize;
    const padded = std.math.ceilPowerOfTwo(
        usize,
        @max(count, 16),
    ) catch return error.InvalidLogSize;
    return @intCast(std.math.log2_int(usize, padded));
}

fn equalM31(left: []const M31, right: []const M31) bool {
    if (left.len != right.len) return false;
    for (left, right) |a, b|
        if (!std.meta.eql(a, b)) return false;
    return true;
}

pub const testing = struct {
    /// Creates a committed non-boolean selector after all host admission has
    /// succeeded. The proving engine must reject this through the PPU policy
    /// AIR, not through `ppu_execution_policy.validate`.
    pub fn poisonPpuPolicySelector(
        prepared: *PreparedExecution,
    ) !void {
        const main = prepared.trace.main.columns orelse
            return error.PreparedInputConsumed;
        const column = &main[
            @import("machine_environment_geometry.zig")
                .PPU_EXECUTION_POLICY_MAIN_OFFSET
        ];
        if (column.values.len == 0) return error.InvalidTraceLength;
        const values: []M31 = @constCast(column.values);
        values[0] = M31.fromCanonical(2);
    }

    /// Consumes `prepared` on every success or error path.
    pub fn provePreparedWithEngine(
        comptime Engine: type,
        allocator: std.mem.Allocator,
        pcs_config: pcs_core.PcsConfig,
        prepared: PreparedExecution,
        options: prover_engine.ProveOptions,
    ) !ProveOutput {
        comptime assertProverEngine(Engine);
        var output = try transaction.provePreparedEx(
            Engine,
            ProvingSpec,
            false,
            {},
            allocator,
            pcs_config,
            prepared,
            options,
        );
        const proof = output.proof.proof;
        output.proof.aux.deinit(allocator);
        return .{ .statement = output.statement, .proof = proof };
    }
};
