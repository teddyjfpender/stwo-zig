//! Backend-generic proving path for SM83 AIR components.

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
const execution_input = @import("air/execution_input.zig");
const family_trace = @import("air/family_trace.zig");
const memory_lookup = @import("air/memory_lookup.zig");
const execution = @import("air/execution.zig");
const execution_trace = @import("air/execution_trace.zig");
const program_lookup = @import("air/program_lookup.zig");
const rom_mod = @import("rom.zig");
const memory_mod = @import("memory.zig");
const proof_components = @import("proof_components.zig");
const protocol = @import("proof_statement.zig");
const machine = @import("runner/machine.zig");
const runner = @import("runner/mod.zig");

const FAMILY_MAIN_OFFSET = protocol.FAMILY_MAIN_OFFSET;
const MEMORY_ACCESS_OFFSET = protocol.MEMORY_ACCESS_OFFSET;
const ROM_MULTIPLICITY_OFFSET = protocol.ROM_MULTIPLICITY_OFFSET;
const MEMORY_BOUNDARY_OFFSET = protocol.MEMORY_BOUNDARY_OFFSET;
const MEMORY_EXECUTION_INTERACTION_OFFSET = protocol.MEMORY_EXECUTION_INTERACTION_OFFSET;
const PROGRAM_ROM_INTERACTION_OFFSET = protocol.PROGRAM_ROM_INTERACTION_OFFSET;
const MEMORY_BOUNDARY_INTERACTION_OFFSET = protocol.MEMORY_BOUNDARY_INTERACTION_OFFSET;

pub const Hasher = blake2_merkle.Blake2sPrefixedMerkleHasher;
pub const MerkleChannel = blake2_merkle.Blake2sPrefixedMerkleChannel;
pub const Channel = channel_blake2s.Blake2sChannel;
pub const Proof = core_proof.StarkProof(Hasher);

pub const ExecutionStatement = protocol.ExecutionStatement;

pub const ProveOutput = struct {
    statement: ExecutionStatement,
    proof: Proof,
};

const PreparedExecutionInput = struct {
    request: ExecutionStatement,
    trace: transaction.PreparedTrace,
    steps: []execution_input.Step,
    rom: rom_mod.Rom,
    initial_memory: memory_mod.Image,
    final_memory: memory_mod.Image,
    memory_accesses: []memory_lookup.Access,

    pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
        self.trace.deinit(allocator);
        allocator.free(self.steps);
        allocator.free(self.memory_accesses);
        self.* = undefined;
    }
};
const Error = transaction.Error || error{
    EmptyTrace,
    InvalidLogSize,
    InvalidProofShape,
    InvalidTraceLength,
};

/// Binds a caller-selected backend to the SM83 proof protocol.
pub fn ProverEngineForBackend(comptime Backend: type) type {
    return prover_engine.ProverEngine(Backend, Hasher, MerkleChannel, Channel);
}

/// Checks both the shared engine ABI and the SM83 transcript protocol.
pub fn assertProverEngine(comptime Engine: type) void {
    prover_api.assertProverEngine(Engine);
    if (Engine.Hasher != Hasher or
        Engine.MerkleChannel != MerkleChannel or
        Engine.Channel != Channel or
        Engine.ExtendedProof != core_proof.ExtendedStarkProof(Hasher))
    {
        @compileError("SM83 prover engine uses incompatible protocol types");
    }
}

/// Proves a power-of-two batch through the engine selected by the integration.
pub fn proveExecutionWithEngine(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    rom: rom_mod.Rom,
    initial_memory: memory_mod.Image,
    final_memory: memory_mod.Image,
    steps: []const runner.StepTrace,
) !ProveOutput {
    comptime assertProverEngine(Engine);
    return takeProofOutput(
        allocator,
        try provePrepared(
            Engine,
            allocator,
            pcs_config,
            try prepare(
                allocator,
                rom,
                initial_memory,
                final_memory,
                steps,
            ),
        ),
    );
}

/// Proves scheduler-unambiguous ordinary rows.
///
/// Flat scheduler results discard interrupt-service bus provenance and fail
/// closed; use the cartridge machine-environment transaction for those rows.
pub fn proveMachineExecutionWithEngine(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    rom: rom_mod.Rom,
    initial_memory: memory_mod.Image,
    final_memory: memory_mod.Image,
    steps: []const machine.StepResult,
) !ProveOutput {
    comptime assertProverEngine(Engine);
    return takeProofOutput(
        allocator,
        try provePrepared(
            Engine,
            allocator,
            pcs_config,
            try prepareMachine(
                allocator,
                rom,
                initial_memory,
                final_memory,
                steps,
            ),
        ),
    );
}

/// Verifies an ALU8 execution proof with canonical preprocessing.
pub fn verifyExecutionWithEngine(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    rom: rom_mod.Rom,
    initial_memory: memory_mod.Image,
    final_memory: memory_mod.Image,
    statement: ExecutionStatement,
    proof_in: Proof,
) !void {
    comptime assertProverEngine(Engine);
    protocol.validate(statement, rom, initial_memory, final_memory) catch |err| {
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
        rom,
        initial_memory,
        final_memory,
        statement,
        proof.commitment_scheme_proof.commitments.items[0],
    );
    var channel = Channel{};
    pcs_config.mixInto(&channel);
    var scheme = try pcs_verifier.CommitmentSchemeVerifier(Hasher, MerkleChannel).init(
        allocator,
        pcs_config,
    );
    defer scheme.deinit(allocator);

    const preprocessed_log_sizes =
        protocol.preprocessedLogSizes(statement.log_size);
    try scheme.commit(
        allocator,
        proof.commitment_scheme_proof.commitments.items[0],
        &preprocessed_log_sizes,
        &channel,
    );
    protocol.mixPublic(&channel, statement);
    const main_log_sizes = protocol.mainLogSizes(statement.log_size);
    try scheme.commit(
        allocator,
        proof.commitment_scheme_proof.commitments.items[1],
        &main_log_sizes,
        &channel,
    );
    const program_relation = try program_lookup.Relation.draw(allocator, &channel);
    const memory_relation = try memory_lookup.Relation.draw(allocator, &channel);
    try program_lookup.verifyCancellation(statement.program_lookup_claims);
    try memory_lookup.verifyCancellation(statement.memory_lookup_claims);
    protocol.mixLookupClaims(
        &channel,
        statement.program_lookup_claims,
        statement.memory_lookup_claims,
    );
    const interaction_log_sizes =
        protocol.interactionLogSizes(statement.log_size);
    try scheme.commit(
        allocator,
        proof.commitment_scheme_proof.commitments.items[2],
        &interaction_log_sizes,
        &channel,
    );

    var component_context: proof_components.Context = undefined;
    proof_components.init(
        &component_context,
        statement,
        program_relation,
        memory_relation,
        statement.program_lookup_claims,
        statement.memory_lookup_claims,
    );
    var component_storage: [proof_components.N_COMPONENTS]proof_components.VerifierComponent =
        undefined;
    const components = try proof_components.verifier(
        &component_context,
        &component_storage,
    );
    proof_moved = true;
    try core_verifier.verify(
        Hasher,
        MerkleChannel,
        allocator,
        components,
        &channel,
        &scheme,
        proof,
    );
}

/// Adversarial hooks shared by concrete backend integration tests.
pub const testing = struct {
    /// Attempts an all-inactive proof. A sound backend must reject it.
    pub fn proveInactiveExecutionWithEngine(
        comptime Engine: type,
        allocator: std.mem.Allocator,
        pcs_config: pcs_core.PcsConfig,
        rom: rom_mod.Rom,
        initial_memory: memory_mod.Image,
        final_memory: memory_mod.Image,
        steps: []const runner.StepTrace,
    ) !void {
        comptime assertProverEngine(Engine);
        const prepared = try prepare(allocator, rom, initial_memory, final_memory, steps);
        for (0..execution.N_FAMILY_SELECTORS) |selector| {
            @memset(
                @constCast(
                    prepared.trace.main.columns.?[
                        FAMILY_MAIN_OFFSET + selector
                    ].values,
                ),
                M31.zero(),
            );
        }
        var output = try provePrepared(Engine, allocator, pcs_config, prepared);
        output.proof.deinit(allocator);
    }

    /// Mutates a committed after-state without changing the following before-state.
    pub fn proveDisconnectedStateWithEngine(
        comptime Engine: type,
        allocator: std.mem.Allocator,
        pcs_config: pcs_core.PcsConfig,
        rom: rom_mod.Rom,
        initial_memory: memory_mod.Image,
        final_memory: memory_mod.Image,
        steps: []const runner.StepTrace,
    ) !void {
        comptime assertProverEngine(Engine);
        const prepared = try prepare(allocator, rom, initial_memory, final_memory, steps);
        const storage = try core_air_utils.circleBitReversedIndex(
            prepared.request.log_size,
            0,
        );
        const column = execution.N_STATE_COLUMNS + @intFromEnum(execution.StateIndex.b);
        @constCast(prepared.trace.main.columns.?[column].values)[storage] =
            M31.fromCanonical(steps[0].after.b +% 1);
        var output = try provePrepared(Engine, allocator, pcs_config, prepared);
        output.proof.deinit(allocator);
    }

    /// Mutates the fetched opcode after runner validation.
    pub fn proveForgedOpcodeWithEngine(
        comptime Engine: type,
        allocator: std.mem.Allocator,
        pcs_config: pcs_core.PcsConfig,
        rom: rom_mod.Rom,
        initial_memory: memory_mod.Image,
        final_memory: memory_mod.Image,
        steps: []const runner.StepTrace,
    ) !void {
        comptime assertProverEngine(Engine);
        const prepared = try prepare(allocator, rom, initial_memory, final_memory, steps);
        const storage = try core_air_utils.circleBitReversedIndex(
            prepared.request.log_size,
            0,
        );
        const opcode_column = 2 * execution.N_STATE_COLUMNS + 1;
        @constCast(prepared.trace.main.columns.?[opcode_column].values)[storage] =
            M31.fromCanonical(0x81);
        var output = try provePrepared(Engine, allocator, pcs_config, prepared);
        output.proof.deinit(allocator);
    }

    /// Mutates the committed ROM-table multiplicity after lookup generation.
    pub fn proveForgedMultiplicityWithEngine(
        comptime Engine: type,
        allocator: std.mem.Allocator,
        pcs_config: pcs_core.PcsConfig,
        rom: rom_mod.Rom,
        initial_memory: memory_mod.Image,
        final_memory: memory_mod.Image,
        steps: []const runner.StepTrace,
    ) !void {
        comptime assertProverEngine(Engine);
        const prepared = try prepare(allocator, rom, initial_memory, final_memory, steps);
        const storage = try core_air_utils.circleBitReversedIndex(
            rom_mod.LOG_SIZE,
            steps[0].before.pc,
        );
        const column = ROM_MULTIPLICITY_OFFSET;
        const multiplicities = @constCast(prepared.trace.main.columns.?[column].values);
        multiplicities[storage] = multiplicities[storage].add(M31.one());
        var output = try provePrepared(Engine, allocator, pcs_config, prepared);
        output.proof.deinit(allocator);
    }

    pub const MemoryWitnessMutation = enum {
        previous_value,
        previous_clock,
        next_value,
        final_clock,
    };

    /// Mutates one committed field in the first active data-memory access.
    pub fn proveForgedMemoryWithEngine(
        comptime Engine: type,
        allocator: std.mem.Allocator,
        pcs_config: pcs_core.PcsConfig,
        rom: rom_mod.Rom,
        initial_memory: memory_mod.Image,
        final_memory: memory_mod.Image,
        steps: []const runner.StepTrace,
        mutation: MemoryWitnessMutation,
    ) !void {
        comptime assertProverEngine(Engine);
        const prepared = try prepare(allocator, rom, initial_memory, final_memory, steps);
        const access_index = blk: {
            for (prepared.memory_accesses, 0..) |access, index| {
                if (access.enabled) break :blk index;
            }
            return error.NoMemoryAccess;
        };
        const access = prepared.memory_accesses[access_index];
        const row = access_index / execution.N_BUS_CYCLES;
        const cycle = access_index % execution.N_BUS_CYCLES;
        const column = switch (mutation) {
            .previous_clock => MEMORY_ACCESS_OFFSET +
                cycle * memory_lookup.N_ACCESS_COLUMNS,
            .previous_value => MEMORY_ACCESS_OFFSET +
                cycle * memory_lookup.N_ACCESS_COLUMNS + 1,
            .next_value => MEMORY_ACCESS_OFFSET +
                cycle * memory_lookup.N_ACCESS_COLUMNS + 2,
            .final_clock => MEMORY_BOUNDARY_OFFSET,
        };
        const storage = try core_air_utils.circleBitReversedIndex(
            if (mutation == .final_clock) 16 else prepared.request.log_size,
            if (mutation == .final_clock) access.address else row,
        );
        const values = @constCast(prepared.trace.main.columns.?[column].values);
        values[storage] = values[storage].add(M31.one());
        var output = try provePrepared(Engine, allocator, pcs_config, prepared);
        output.proof.deinit(allocator);
    }

    /// Produces a valid proof with a non-canonical unused ROM-table byte.
    pub fn proveNonCanonicalRomWithEngine(
        comptime Engine: type,
        allocator: std.mem.Allocator,
        pcs_config: pcs_core.PcsConfig,
        rom: rom_mod.Rom,
        initial_memory: memory_mod.Image,
        final_memory: memory_mod.Image,
        steps: []const runner.StepTrace,
    ) !ProveOutput {
        comptime assertProverEngine(Engine);
        const prepared = try prepare(allocator, rom, initial_memory, final_memory, steps);
        try protocol.mutateUnusedRomByte(
            prepared.trace.preprocessed.columns.?,
            steps,
        );
        return takeProofOutput(
            allocator,
            try provePrepared(Engine, allocator, pcs_config, prepared),
        );
    }

    /// Produces a valid proof with a non-canonical untouched memory byte.
    pub fn proveNonCanonicalMemoryWithEngine(
        comptime Engine: type,
        allocator: std.mem.Allocator,
        pcs_config: pcs_core.PcsConfig,
        rom: rom_mod.Rom,
        initial_memory: memory_mod.Image,
        final_memory: memory_mod.Image,
        steps: []const runner.StepTrace,
    ) !ProveOutput {
        comptime assertProverEngine(Engine);
        const prepared = try prepare(allocator, rom, initial_memory, final_memory, steps);
        try protocol.mutateUnusedMemoryByte(
            prepared.trace.preprocessed.columns.?,
            prepared.memory_accesses,
        );
        return takeProofOutput(
            allocator,
            try provePrepared(Engine, allocator, pcs_config, prepared),
        );
    }
};

fn takeProofOutput(
    allocator: std.mem.Allocator,
    output_value: anytype,
) ProveOutput {
    var output = output_value;
    const proof = output.proof.proof;
    output.proof.aux.deinit(allocator);
    return .{ .statement = output.statement, .proof = proof };
}

fn provePrepared(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    prepared: PreparedExecutionInput,
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
    rom: rom_mod.Rom,
    initial_memory: memory_mod.Image,
    final_memory: memory_mod.Image,
    steps: []const runner.StepTrace,
) !PreparedExecutionInput {
    const inputs = try allocator.alloc(execution_input.Step, steps.len);
    for (steps, inputs) |step, *input|
        input.* = execution_input.fromInstruction(step);
    return prepareInputsOwned(
        allocator,
        rom,
        initial_memory,
        final_memory,
        inputs,
    );
}

fn prepareMachine(
    allocator: std.mem.Allocator,
    rom: rom_mod.Rom,
    initial_memory: memory_mod.Image,
    final_memory: memory_mod.Image,
    steps: []const machine.StepResult,
) !PreparedExecutionInput {
    const inputs = try allocator.alloc(execution_input.Step, steps.len);
    var inputs_owned = true;
    defer if (inputs_owned) allocator.free(inputs);
    for (steps, inputs) |step, *input|
        input.* = try execution_input.fromMachine(step);
    inputs_owned = false;
    return prepareInputsOwned(
        allocator,
        rom,
        initial_memory,
        final_memory,
        inputs,
    );
}

fn prepareInputsOwned(
    allocator: std.mem.Allocator,
    rom: rom_mod.Rom,
    initial_memory: memory_mod.Image,
    final_memory: memory_mod.Image,
    steps: []execution_input.Step,
) !PreparedExecutionInput {
    errdefer allocator.free(steps);
    if (steps.len == 0) return error.EmptyTrace;
    if (!std.math.isPowerOfTwo(steps.len) or steps.len < 16)
        return error.InvalidTraceLength;
    try initial_memory.validateRom(rom);
    try final_memory.validateRom(rom);

    var machine_trace = try execution_trace.generate(allocator, steps);
    defer machine_trace.deinit();
    var family_witness = try family_trace.generate(allocator, steps);
    defer family_witness.deinit();
    var memory_witness = try memory_lookup.generateWitness(
        allocator,
        steps,
        initial_memory,
        final_memory,
    );
    defer memory_witness.deinit();
    if (machine_trace.log_size != family_witness.log_size)
        return error.InvalidTraceLength;

    const preprocessed = try protocol.canonicalPreprocessed(
        allocator,
        machine_trace.log_size,
        rom,
        initial_memory,
        final_memory,
    );
    var preprocessed_moved = false;
    errdefer if (!preprocessed_moved) {
        for (preprocessed) |column| allocator.free(@constCast(column.values));
        allocator.free(preprocessed);
    };
    const main = try allocator.alloc(
        prover_pcs.ColumnEvaluation,
        protocol.N_MAIN_COLUMNS,
    );
    var main_moved = false;
    errdefer if (!main_moved) allocator.free(main);

    for (main[0..execution.N_MAIN_COLUMNS], machine_trace.main) |*column, values| {
        column.* = .{ .log_size = machine_trace.log_size, .values = values };
    }
    for (
        main[FAMILY_MAIN_OFFSET..ROM_MULTIPLICITY_OFFSET],
        family_witness.main ++ memory_witness.main,
    ) |*column, values| {
        column.* = .{ .log_size = family_witness.log_size, .values = values };
    }
    const multiplicity = try program_lookup.committedMultiplicities(
        allocator,
        steps,
        rom,
    );
    var multiplicity_moved = false;
    errdefer if (!multiplicity_moved) allocator.free(multiplicity);
    main[ROM_MULTIPLICITY_OFFSET] = .{
        .log_size = rom_mod.LOG_SIZE,
        .values = multiplicity,
    };
    main[MEMORY_BOUNDARY_OFFSET] = .{
        .log_size = 16,
        .values = memory_witness.final_clocks,
    };
    const memory_accesses = memory_witness.takeAccesses();
    errdefer allocator.free(memory_accesses);
    const statement = protocol.init(
        machine_trace.log_size,
        machine_trace.initial,
        machine_trace.final,
        rom,
        initial_memory,
        final_memory,
    );
    try protocol.validate(statement, rom, initial_memory, final_memory);
    machine_trace.disownMain();
    family_witness.disownMain();
    memory_witness.disownColumns();
    preprocessed_moved = true;
    main_moved = true;
    multiplicity_moved = true;
    return .{
        .request = statement,
        .trace = try transaction.PreparedTrace.initOwned(
            allocator,
            preprocessed,
            main,
        ),
        .steps = steps,
        .rom = rom,
        .initial_memory = initial_memory,
        .final_memory = final_memory,
        .memory_accesses = memory_accesses,
    };
}

const ProvingSpec = struct {
    pub const Statement = ExecutionStatement;
    pub const PreparedInput = PreparedExecutionInput;
    pub const max_components: usize = proof_components.N_COMPONENTS;

    pub const PreparedInteraction = struct {
        columns: transaction.OwnedColumns,
        program_relation: program_lookup.Relation,
        memory_relation: memory_lookup.Relation,
        program_claims: program_lookup.Claims,
        memory_claims: memory_lookup.Claims,
    };

    pub const ProverContext = proof_components.Context;

    pub fn validateRequest(request: Statement) Error!void {
        try protocol.validateShape(request);
    }

    pub fn validatePrepared(prepared: *const @This().PreparedInput) Error!void {
        const preprocessed = prepared.trace.preprocessed.columns orelse
            return error.PreparedInputConsumed;
        const main = prepared.trace.main.columns orelse
            return error.PreparedInputConsumed;
        try protocol.validatePreparedGeometry(
            preprocessed,
            main,
            prepared.request.log_size,
        );
    }

    pub fn compositionLog(request: Statement) Error!u32 {
        return std.math.add(u32, @max(request.log_size, 16), 1) catch
            return error.InvalidLogSize;
    }

    pub fn beforeMainCommit(channel: *Channel, request: Statement) !void {
        protocol.mixPublic(channel, request);
    }

    pub fn prepareInteraction(
        allocator: std.mem.Allocator,
        channel: *Channel,
        prepared: *const PreparedInput,
    ) !PreparedInteraction {
        const program_relation = try program_lookup.Relation.draw(allocator, channel);
        const memory_relation = try memory_lookup.Relation.draw(allocator, channel);
        var program = try program_lookup.generate(
            allocator,
            prepared.steps,
            prepared.rom,
            program_relation,
        );
        defer program.deinit();
        var memory = try memory_lookup.generateInteraction(
            allocator,
            prepared.memory_accesses,
            prepared.request.log_size,
            prepared.initial_memory,
            prepared.final_memory,
            memory_relation,
        );
        defer memory.deinit();
        const columns = try allocator.alloc(
            prover_pcs.ColumnEvaluation,
            protocol.N_INTERACTION_COLUMNS,
        );
        errdefer allocator.free(columns);
        for (
            columns[0..program_lookup.N_EXECUTION_COLUMNS],
            program.columns[0..program_lookup.N_EXECUTION_COLUMNS],
        ) |*column, values| {
            column.* = .{ .log_size = prepared.request.log_size, .values = values };
        }
        for (
            columns[MEMORY_EXECUTION_INTERACTION_OFFSET..PROGRAM_ROM_INTERACTION_OFFSET],
            memory.columns[0..memory_lookup.N_EXECUTION_COLUMNS],
        ) |*column, values| {
            column.* = .{ .log_size = prepared.request.log_size, .values = values };
        }
        for (
            columns[PROGRAM_ROM_INTERACTION_OFFSET..MEMORY_BOUNDARY_INTERACTION_OFFSET],
            program.columns[program_lookup.N_EXECUTION_COLUMNS..],
        ) |*column, values| {
            column.* = .{ .log_size = rom_mod.LOG_SIZE, .values = values };
        }
        for (
            columns[MEMORY_BOUNDARY_INTERACTION_OFFSET..],
            memory.columns[memory_lookup.N_EXECUTION_COLUMNS..],
        ) |*column, values| {
            column.* = .{ .log_size = 16, .values = values };
        }
        const program_claims = program.claims;
        const memory_claims = memory.claims;
        program.disown();
        memory.disown();
        return .{
            .columns = transaction.OwnedColumns.init(columns),
            .program_relation = program_relation,
            .memory_relation = memory_relation,
            .program_claims = program_claims,
            .memory_claims = memory_claims,
        };
    }

    pub fn deinitPreparedInteraction(
        interaction: *PreparedInteraction,
        allocator: std.mem.Allocator,
    ) void {
        interaction.columns.deinit(allocator);
        interaction.* = undefined;
    }

    pub fn beforeInteractionCommit(
        channel: *Channel,
        _: Statement,
        interaction: *const PreparedInteraction,
    ) !void {
        protocol.mixLookupClaims(
            channel,
            interaction.program_claims,
            interaction.memory_claims,
        );
    }

    pub fn initProverContext(
        out: *ProverContext,
        _: *Channel,
        request: Statement,
        interaction: *const PreparedInteraction,
    ) !void {
        try program_lookup.verifyCancellation(interaction.program_claims);
        try memory_lookup.verifyCancellation(interaction.memory_claims);
        proof_components.init(
            out,
            request,
            interaction.program_relation,
            interaction.memory_relation,
            interaction.program_claims,
            interaction.memory_claims,
        );
    }

    pub fn statement(context: *const ProverContext) Statement {
        return context.statement_value;
    }

    pub fn proverComponents(
        context: *const ProverContext,
        out: []proof_components.ProverComponent,
    ) ![]const proof_components.ProverComponent {
        return proof_components.prover(context, out);
    }
};

test "SM83 prover facade keeps backend selection outside the frontend" {
    switch (@typeInfo(@TypeOf(ProverEngineForBackend))) {
        .@"fn" => {},
        else => @compileError("ProverEngineForBackend must remain a function"),
    }
}
