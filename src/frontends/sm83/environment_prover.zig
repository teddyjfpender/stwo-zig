//! Backend-generic proof transaction for cartridge execution with joypad input.
const std = @import("std");
const core_air_utils = @import("stwo_core").air.utils;
const channel_blake2s = @import("stwo_core").channel.blake2s;
const M31 = @import("stwo_core").fields.m31.M31;
const pcs_core = @import("stwo_core").pcs;
const pcs_verifier = @import("stwo_core").pcs.verifier;
const core_proof = @import("stwo_core").proof;
const core_verifier = @import("stwo_core").verifier;
const blake2_merkle = @import("stwo_core").vcs_lifted.blake2_merkle;
const prover_api = @import("stwo_prover_api");
const prover_engine = @import("stwo_prover_engine").engine;
const prover_pcs = @import("stwo_prover_engine").pcs;
const transaction = @import("stwo_prover_engine").transaction;
const action_schedule = @import("action_schedule.zig");
const access = @import("air/cartridge_access.zig");
const execution_trace = @import("air/execution_trace.zig");
const family_trace = @import("air/family_trace.zig");
const joypad_binding = @import("air/joypad_binding.zig");
const joypad_if = @import("air/joypad_if_memory_lookup.zig");
const timer_binding = @import("air/timer_binding.zig");
const timer_if = @import("air/timer_if_memory_lookup.zig");
const intermediate_observation =
    @import("air/intermediate_ram_observation_lookup.zig");
const memory_lookup = @import("air/cartridge_memory_lookup.zig");
const rom_lookup = @import("air/cartridge_rom_lookup.zig");
const cartridge = @import("cartridge/mod.zig");
const cartridge_prover = @import("cartridge_prover.zig");
const base_protocol = @import("cartridge_proof_statement.zig");
const components = @import("environment_proof_components.zig");
const interaction = @import("environment_proof_interaction.zig");
const memory_replay = @import("environment_memory_replay.zig");
const protocol = @import("environment_statement.zig");
const joypad_trace = @import("joypad_trace.zig");
const ram_observation = @import("ram_observation.zig");
const runner = @import("runner/mod.zig");
const timer_runner = @import("runner/timer.zig");

pub const Hasher = blake2_merkle.Blake2sPrefixedMerkleHasher;
pub const MerkleChannel = blake2_merkle.Blake2sPrefixedMerkleChannel;
pub const Channel = channel_blake2s.Blake2sChannel;
pub const Proof = core_proof.StarkProof(Hasher);
pub const ExecutionStatement = protocol.ExecutionStatement;
pub const ProveOutput = struct {
    statement: ExecutionStatement,
    proof: Proof,
};
const PreparedExecution = struct {
    request: ExecutionStatement,
    trace: transaction.PreparedTrace,
    steps: []const runner.CartridgeStepTrace,
    rom: cartridge.Cartridge,
    initial_images: memory_lookup.Images,
    final_images: memory_lookup.Images,
    actions: []const action_schedule.Action,
    observations: []const ram_observation.Region,
    intermediate_observations: []const intermediate_observation.Sample,
    joypad: joypad_trace.Trace,
    timer: timer_binding.Trace,
    memory_accesses: []memory_lookup.Access,
    final_clocks: []M31,
    if_accesses: []joypad_if.Access,
    timer_if_accesses: []timer_if.Access,
    intermediate_observation_accesses: []intermediate_observation.Access,

    pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
        self.trace.deinit(allocator);
        self.joypad.deinit(allocator);
        self.timer.deinit(allocator);
        allocator.free(self.memory_accesses);
        allocator.free(self.final_clocks);
        allocator.free(self.if_accesses);
        allocator.free(self.timer_if_accesses);
        allocator.free(self.intermediate_observation_accesses);
        self.* = undefined;
    }
};

const Error = transaction.Error || protocol.Error || error{
    InvalidLogSize,
    InvalidProofShape,
    InvalidPreparedGeometry,
};
pub fn ProverEngineForBackend(comptime Backend: type) type {
    return prover_engine.ProverEngine(Backend, Hasher, MerkleChannel, Channel);
}

pub fn assertProverEngine(comptime Engine: type) void {
    prover_api.assertProverEngine(Engine);
    if (Engine.Hasher != Hasher or
        Engine.MerkleChannel != MerkleChannel or
        Engine.Channel != Channel or
        Engine.ExtendedProof != core_proof.ExtendedStarkProof(Hasher))
    {
        @compileError("SM83 environment engine uses incompatible protocol types");
    }
}
pub fn proveExecutionWithEngine(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    rom: cartridge.Cartridge,
    initial_images: memory_lookup.Images,
    final_images: memory_lookup.Images,
    initial_mcycle: u32,
    initial_joypad: runner.joypad.State,
    initial_timer: timer_runner.Timer,
    actions: []const action_schedule.Action,
    observations: []const ram_observation.Region,
    intermediate_observations: []const intermediate_observation.Sample,
    steps: []const runner.CartridgeStepTrace,
) !ProveOutput {
    comptime assertProverEngine(Engine);
    return takeOutput(
        allocator,
        try provePrepared(
            Engine,
            allocator,
            pcs_config,
            try prepare(
                allocator,
                rom,
                initial_images,
                final_images,
                initial_mcycle,
                initial_joypad,
                initial_timer,
                actions,
                observations,
                intermediate_observations,
                steps,
            ),
        ),
    );
}
pub fn verifyExecutionWithEngine(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    rom: cartridge.Cartridge,
    initial_images: memory_lookup.Images,
    final_images: memory_lookup.Images,
    actions: []const action_schedule.Action,
    observations: []const ram_observation.Region,
    intermediate_observations: []const intermediate_observation.Sample,
    statement: ExecutionStatement,
    proof_in: Proof,
) !void {
    comptime assertProverEngine(Engine);
    protocol.validate(
        statement,
        rom,
        initial_images,
        final_images,
        actions,
        observations,
        intermediate_observations,
    ) catch |err| {
        var invalid = proof_in;
        invalid.deinit(allocator);
        return err;
    };
    if (proof_in.commitment_scheme_proof.commitments.items.len != 4) {
        var invalid = proof_in;
        invalid.deinit(allocator);
        return error.InvalidProofShape;
    }
    var proof = proof_in;
    var proof_moved = false;
    defer if (!proof_moved) proof.deinit(allocator);
    try protocol.verifyPreprocessedRoot(
        Engine,
        allocator,
        pcs_config,
        statement,
        rom,
        initial_images,
        final_images,
        actions,
        observations,
        intermediate_observations,
        proof.commitment_scheme_proof.commitments.items[0],
    );
    var channel = Channel{};
    pcs_config.mixInto(&channel);
    var scheme = try pcs_verifier.CommitmentSchemeVerifier(
        Hasher,
        MerkleChannel,
    ).init(allocator, pcs_config);
    defer scheme.deinit(allocator);
    try scheme.commit(
        allocator,
        proof.commitment_scheme_proof.commitments.items[0],
        &protocol.preprocessedLogSizes(
            statement.base.log_size,
            statement.joypad_log_size,
            statement.timer_log_size,
            statement.intermediate_observation_log_size,
        ),
        &channel,
    );
    protocol.mixPublic(&channel, statement);
    try scheme.commit(
        allocator,
        proof.commitment_scheme_proof.commitments.items[1],
        &protocol.mainLogSizes(
            statement.base.log_size,
            statement.joypad_log_size,
            statement.timer_log_size,
            statement.intermediate_observation_log_size,
        ),
        &channel,
    );
    const rom_relation = try rom_lookup.Relation.draw(allocator, &channel);
    const memory_relation =
        try memory_lookup.Relation.draw(allocator, &channel);
    const action_relation =
        try @import("air/joypad_action_lookup.zig").Relation.draw(
            allocator,
            &channel,
        );
    const mmio_relations =
        try @import("air/joypad_mmio_lookup.zig").Relations.draw(
            allocator,
            &channel,
        );
    const timer_mmio_relations =
        try @import("air/timer_mmio_lookup.zig").Relations.draw(
            allocator,
            &channel,
        );
    try protocol.verifyLookupCancellation(statement);
    protocol.mixLookupClaims(&channel, statement);
    try scheme.commit(
        allocator,
        proof.commitment_scheme_proof.commitments.items[2],
        &protocol.interactionLogSizes(
            statement.base.log_size,
            statement.joypad_log_size,
            statement.timer_log_size,
            statement.intermediate_observation_log_size,
        ),
        &channel,
    );
    var context: components.Context = undefined;
    components.init(
        &context,
        statement,
        rom_relation,
        memory_relation,
        action_relation,
        mmio_relations,
        timer_mmio_relations,
    );
    var storage: [components.N_COMPONENTS]components.VerifierComponent =
        undefined;
    const verifier_components = try components.verifier(&context, &storage);
    proof_moved = true;
    try core_verifier.verify(
        Hasher,
        MerkleChannel,
        allocator,
        verifier_components,
        &channel,
        &scheme,
        proof,
    );
}
pub const testing = struct {
    pub const ForgedWitness = enum {
        joypad,
        timer,
        intermediate_observation,
    };

    pub fn proveForgedWitnessWithEngine(
        comptime Engine: type,
        allocator: std.mem.Allocator,
        pcs_config: pcs_core.PcsConfig,
        rom: cartridge.Cartridge,
        initial_images: memory_lookup.Images,
        final_images: memory_lookup.Images,
        initial_mcycle: u32,
        initial_joypad: runner.joypad.State,
        initial_timer: timer_runner.Timer,
        actions: []const action_schedule.Action,
        observations: []const ram_observation.Region,
        intermediate_observations: []const intermediate_observation.Sample,
        steps: []const runner.CartridgeStepTrace,
        forged: ForgedWitness,
    ) !void {
        const prepared = try prepare(
            allocator,
            rom,
            initial_images,
            final_images,
            initial_mcycle,
            initial_joypad,
            initial_timer,
            actions,
            observations,
            intermediate_observations,
            steps,
        );
        const columns = prepared.trace.main.columns orelse
            return error.PreparedInputConsumed;
        const Target = struct { log_size: u32, column: usize };
        const target: Target = switch (forged) {
            .joypad => .{
                .log_size = prepared.request.joypad_log_size,
                .column = protocol.JOYPAD_BINDING_MAIN_OFFSET,
            },
            .timer => .{
                .log_size = prepared.request.timer_log_size,
                .column = protocol.TIMER_BINDING_MAIN_OFFSET,
            },
            .intermediate_observation => .{
                .log_size = prepared.request.intermediate_observation_log_size,
                .column = protocol.INTERMEDIATE_OBSERVATION_MAIN_OFFSET,
            },
        };
        const storage = try core_air_utils.circleBitReversedIndex(
            target.log_size,
            0,
        );
        const values = @constCast(columns[target.column].values);
        values[storage] = M31.one().sub(values[storage]);
        var output = try provePrepared(
            Engine,
            allocator,
            pcs_config,
            prepared,
        );
        output.proof.proof.deinit(allocator);
        output.proof.aux.deinit(allocator);
    }
};
fn takeOutput(allocator: std.mem.Allocator, output_value: anytype) ProveOutput {
    var output = output_value;
    const proof = output.proof.proof;
    output.proof.aux.deinit(allocator);
    return .{ .statement = output.statement, .proof = proof };
}
fn provePrepared(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    prepared: PreparedExecution,
) !transaction.Output(ExecutionStatement, Engine.ExtendedProof) {
    return transaction.provePreparedEx(
        Engine,
        ProvingSpec,
        false,
        {},
        allocator,
        pcs_config,
        prepared,
        .{},
    );
}

fn prepare(
    allocator: std.mem.Allocator,
    rom: cartridge.Cartridge,
    initial_images: memory_lookup.Images,
    final_images: memory_lookup.Images,
    initial_mcycle: u32,
    initial_joypad: runner.joypad.State,
    initial_timer: timer_runner.Timer,
    actions: []const action_schedule.Action,
    observations: []const ram_observation.Region,
    intermediate_observations: []const intermediate_observation.Sample,
    steps: []const runner.CartridgeStepTrace,
) !PreparedExecution {
    if (steps.len < 16 or !std.math.isPowerOfTwo(steps.len))
        return error.InvalidTraceLength;
    try validateComposedDevices(steps);
    var machine = try execution_trace.generateAt(
        allocator,
        steps,
        initial_mcycle,
    );
    defer machine.deinit();
    var families = try family_trace.generate(allocator, steps);
    defer families.deinit();
    var packed_trace = try cartridge_prover.generatePacked(
        allocator,
        steps,
        machine.log_size,
    );
    defer packed_trace.deinit();
    var joypad = try joypad_trace.generate(
        allocator,
        machine.initial.mcycle,
        machine.final.mcycle,
        initial_joypad,
        actions,
        steps,
    );
    var joypad_moved = false;
    defer if (!joypad_moved) joypad.deinit(allocator);
    var binding = try joypad_binding.generateWitness(
        allocator,
        joypad,
        steps,
    );
    defer binding.deinit();
    var timer_trace = try timer_binding.generateTrace(
        allocator,
        machine.initial.mcycle,
        machine.final.mcycle,
        initial_timer,
        steps,
    );
    var timer_moved = false;
    defer if (!timer_moved) timer_trace.deinit(allocator);
    var timer_witness = try timer_binding.generateWitness(
        allocator,
        timer_trace,
        steps,
    );
    defer timer_witness.deinit();
    const intermediate_observation_log_size =
        try observationLogSize(intermediate_observations.len);
    var replay = try memory_replay.generateDevicesWithObservations(
        allocator,
        steps,
        initial_images,
        final_images,
        initial_mcycle,
        joypad.rows,
        timer_trace.rows,
        intermediate_observations,
    );
    defer replay.deinit();
    var if_witness = try joypad_if.generateWitness(
        allocator,
        binding.log_size,
        joypad.rows,
        replay.predecessors,
    );
    defer if_witness.deinit();
    var timer_if_witness = try timer_if.generateWitness(
        allocator,
        timer_witness.log_size,
        timer_trace.rows,
        replay.timer_predecessors,
    );
    defer timer_if_witness.deinit();
    var intermediate_observation_witness =
        try intermediate_observation.generateWitness(
            allocator,
            intermediate_observation_log_size,
            intermediate_observations,
            replay.observation_predecessors,
        );
    defer intermediate_observation_witness.deinit();

    const first = try access.ValidatedStep.init(steps[0]);
    const last = try access.ValidatedStep.init(steps[steps.len - 1]);
    const initial_mapper = first.mapper_before[0];
    const final_mapper =
        last.mapper_after[steps[steps.len - 1].instruction.cycle_count - 1];
    const base = base_protocol.init(
        machine.log_size,
        machine.initial,
        machine.final,
        initial_mapper,
        final_mapper,
        rom,
        initial_images,
        final_images,
    );
    const request = try protocol.init(
        base,
        rom,
        initial_images,
        final_images,
        actions,
        initial_joypad,
        joypad.final_state,
        binding.log_size,
        initial_timer,
        timer_trace.final_state,
        timer_witness.log_size,
        observations,
        intermediate_observations,
        intermediate_observation_log_size,
    );
    const preprocessed = try protocol.canonicalPreprocessed(
        allocator,
        request,
        rom,
        initial_images,
        final_images,
        actions,
        observations,
        intermediate_observations,
    );
    var preprocessed_moved = false;
    errdefer if (!preprocessed_moved)
        cartridge_prover.freeEvaluations(allocator, preprocessed);
    const main = try allocator.alloc(
        prover_pcs.ColumnEvaluation,
        protocol.N_MAIN_COLUMNS,
    );
    var main_moved = false;
    errdefer if (!main_moved) allocator.free(main);
    cartridge_prover.setEvaluations(
        main[base_protocol.EXECUTION_MAIN_OFFSET..base_protocol.FAMILY_MAIN_OFFSET],
        &machine.main,
        machine.log_size,
    );
    cartridge_prover.setEvaluations(
        main[base_protocol.FAMILY_MAIN_OFFSET..base_protocol.PACKED_ACCESS_MAIN_OFFSET],
        &families.main,
        machine.log_size,
    );
    cartridge_prover.setEvaluations(
        main[base_protocol.PACKED_ACCESS_MAIN_OFFSET..base_protocol.MUTABLE_WITNESS_MAIN_OFFSET],
        &packed_trace.columns,
        machine.log_size,
    );
    cartridge_prover.setEvaluations(
        main[base_protocol.MUTABLE_WITNESS_MAIN_OFFSET..base_protocol.ROM_MULTIPLICITY_MAIN_OFFSET],
        &replay.memory.main,
        machine.log_size,
    );
    const multiplicity = try rom_lookup.committedMultiplicities(
        allocator,
        steps,
        rom.bytes,
    );
    var multiplicity_moved = false;
    errdefer if (!multiplicity_moved) allocator.free(multiplicity);
    main[base_protocol.ROM_MULTIPLICITY_MAIN_OFFSET] = .{
        .log_size = rom_lookup.ROM_LOG_SIZE,
        .values = multiplicity,
    };
    main[base_protocol.FINAL_CLOCK_MAIN_OFFSET] = .{
        .log_size = memory_lookup.BOUNDARY_LOG_SIZE,
        .values = replay.memory.final_clocks,
    };
    cartridge_prover.setEvaluations(
        main[protocol.JOYPAD_BINDING_MAIN_OFFSET..protocol.JOYPAD_IF_MAIN_OFFSET],
        &binding.main,
        binding.log_size,
    );
    cartridge_prover.setEvaluations(
        main[protocol.JOYPAD_IF_MAIN_OFFSET..protocol.TIMER_BINDING_MAIN_OFFSET],
        &if_witness.main,
        binding.log_size,
    );
    cartridge_prover.setEvaluations(
        main[protocol.TIMER_BINDING_MAIN_OFFSET..protocol.TIMER_IF_MAIN_OFFSET],
        &timer_witness.main,
        timer_witness.log_size,
    );
    cartridge_prover.setEvaluations(
        main[protocol.TIMER_IF_MAIN_OFFSET..protocol.INTERMEDIATE_OBSERVATION_MAIN_OFFSET],
        &timer_if_witness.main,
        timer_witness.log_size,
    );
    cartridge_prover.setEvaluations(
        main[protocol.INTERMEDIATE_OBSERVATION_MAIN_OFFSET..],
        &intermediate_observation_witness.main,
        intermediate_observation_log_size,
    );

    const memory_accesses = replay.memory.takeAccesses();
    errdefer allocator.free(memory_accesses);
    const final_clocks = try allocator.dupe(
        M31,
        replay.memory.final_clocks,
    );
    errdefer allocator.free(final_clocks);
    const if_accesses = if_witness.takeAccesses();
    errdefer allocator.free(if_accesses);
    const timer_if_accesses = timer_if_witness.takeAccesses();
    errdefer allocator.free(timer_if_accesses);
    const intermediate_observation_accesses =
        intermediate_observation_witness.takeAccesses();
    errdefer allocator.free(intermediate_observation_accesses);
    machine.disownMain();
    families.disownMain();
    packed_trace.disown();
    replay.memory.disownColumns();
    binding.disown();
    if_witness.disownColumns();
    timer_witness.disown();
    timer_if_witness.disownColumns();
    intermediate_observation_witness.disownColumns();
    preprocessed_moved = true;
    main_moved = true;
    multiplicity_moved = true;
    joypad_moved = true;
    timer_moved = true;
    return .{
        .request = request,
        .trace = try transaction.PreparedTrace.initOwned(
            allocator,
            preprocessed,
            main,
        ),
        .steps = steps,
        .rom = rom,
        .initial_images = initial_images,
        .final_images = final_images,
        .actions = actions,
        .observations = observations,
        .intermediate_observations = intermediate_observations,
        .joypad = joypad,
        .timer = timer_trace,
        .memory_accesses = memory_accesses,
        .final_clocks = final_clocks,
        .if_accesses = if_accesses,
        .timer_if_accesses = timer_if_accesses,
        .intermediate_observation_accesses = intermediate_observation_accesses,
    };
}

fn validateComposedDevices(steps: []const runner.CartridgeStepTrace) !void {
    for (steps) |step| {
        _ = try access.ValidatedStep.init(step);
        for (step.activeAccesses()) |maybe_access| {
            const item = maybe_access orelse continue;
            if (item.region == .ppu_mmio)
                return error.PpuProofNotComposed;
            if (item.region == .cartridge_open_bus)
                return error.UnsupportedOpenBus;
        }
    }
}

pub fn requiredCompositionLog(
    execution_log_size: u32,
    joypad_log_size: u32,
    timer_log_size: u32,
    intermediate_observation_log_size: u32,
) error{InvalidLogSize}!u32 {
    const base = try cartridge_prover.requiredCompositionLog(
        execution_log_size,
    );
    const joypad = std.math.add(u32, joypad_log_size, 1) catch
        return error.InvalidLogSize;
    const timer = std.math.add(u32, timer_log_size, 1) catch
        return error.InvalidLogSize;
    const observation = std.math.add(
        u32,
        intermediate_observation_log_size,
        1,
    ) catch return error.InvalidLogSize;
    return @max(base, joypad, timer, observation);
}

const ProvingSpec = struct {
    pub const Statement = ExecutionStatement;
    pub const PreparedInput = PreparedExecution;
    pub const ProverContext = components.Context;
    pub const PreparedInteraction = interaction.Prepared;
    pub const max_components = components.N_COMPONENTS;

    pub fn validateRequest(request: Statement) Error!void {
        try protocol.validateShape(request);
    }

    pub fn validatePrepared(prepared: *const PreparedInput) Error!void {
        const preprocessed = prepared.trace.preprocessed.columns orelse
            return error.PreparedInputConsumed;
        const main = prepared.trace.main.columns orelse
            return error.PreparedInputConsumed;
        try validateLogs(
            preprocessed,
            &protocol.preprocessedLogSizes(
                prepared.request.base.log_size,
                prepared.request.joypad_log_size,
                prepared.request.timer_log_size,
                prepared.request.intermediate_observation_log_size,
            ),
        );
        try validateLogs(
            main,
            &protocol.mainLogSizes(
                prepared.request.base.log_size,
                prepared.request.joypad_log_size,
                prepared.request.timer_log_size,
                prepared.request.intermediate_observation_log_size,
            ),
        );
    }

    pub fn compositionLog(request: Statement) Error!u32 {
        return requiredCompositionLog(
            request.base.log_size,
            request.joypad_log_size,
            request.timer_log_size,
            request.intermediate_observation_log_size,
        );
    }

    pub fn beforeMainCommit(channel: *Channel, request: Statement) !void {
        protocol.mixPublic(channel, request);
    }

    pub fn prepareInteraction(
        allocator: std.mem.Allocator,
        channel: *Channel,
        prepared: *const PreparedInput,
    ) !PreparedInteraction {
        return interaction.generate(
            allocator,
            channel,
            prepared.steps,
            prepared.rom,
            prepared.initial_images,
            prepared.final_images,
            prepared.actions,
            prepared.request.base.initial.mcycle,
            prepared.request.base.final.mcycle,
            prepared.request.joypad_log_size,
            prepared.joypad.rows,
            prepared.request.timer_log_size,
            prepared.timer.rows,
            prepared.memory_accesses,
            prepared.final_clocks,
            prepared.if_accesses,
            prepared.timer_if_accesses,
            prepared.request.intermediate_observation_log_size,
            prepared.request.intermediate_observation_schedule_claim,
            prepared.intermediate_observation_accesses,
        );
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
        var claimed_statement = request;
        applyClaims(&claimed_statement, prepared.claims);
        protocol.mixLookupClaims(channel, claimed_statement);
    }

    pub fn initProverContext(
        out: *ProverContext,
        _: *Channel,
        request: Statement,
        prepared: *const PreparedInteraction,
    ) !void {
        try interaction.verifyCancellation(prepared.claims);
        var claimed_statement = request;
        applyClaims(&claimed_statement, prepared.claims);
        components.init(
            out,
            claimed_statement,
            prepared.rom_relation,
            prepared.memory_relation,
            prepared.action_relation,
            prepared.mmio_relations,
            prepared.timer_mmio_relations,
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

fn applyClaims(
    statement: *ExecutionStatement,
    claims: interaction.Claims,
) void {
    statement.base.rom_lookup_claims = claims.rom;
    statement.base.memory_lookup_claims = claims.memory;
    statement.action_lookup_claims = claims.actions;
    statement.joypad_mmio_lookup_claims = claims.mmio;
    statement.joypad_if_memory_claim = claims.joypad_if;
    statement.timer_mmio_lookup_claims = claims.timer_mmio;
    statement.timer_if_memory_claim = claims.timer_if;
    statement.intermediate_observation_memory_claim =
        claims.intermediate_observation;
}

fn observationLogSize(count: usize) error{InvalidLogSize}!u32 {
    if (count == 0) return error.InvalidLogSize;
    const padded = std.math.ceilPowerOfTwo(usize, @max(count, 16)) catch
        return error.InvalidLogSize;
    return @intCast(std.math.log2_int(usize, padded));
}

fn validateLogs(
    columns: []const prover_pcs.ColumnEvaluation,
    expected: []const u32,
) Error!void {
    if (columns.len != expected.len)
        return error.InvalidPreparedGeometry;
    for (columns, expected) |column, log_size|
        if (column.log_size != log_size or
            column.values.len != @as(usize, 1) << @intCast(log_size))
            return error.InvalidPreparedGeometry;
}

test "environment prover facade keeps backend selection external" {
    try std.testing.expectEqual(
        @as(u32, 21),
        try requiredCompositionLog(4, 5, 4, 4),
    );
}
