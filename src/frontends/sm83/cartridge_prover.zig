//! Backend-generic proving for RTC-free MBC3 cartridge execution.
//!
//! CPU-only detached-device mode commits ROM, memory, SRAM, and mapper state.
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
const execution = @import("air/execution.zig");
const execution_trace = @import("air/execution_trace.zig");
const family_trace = @import("air/family_trace.zig");
const access = @import("air/cartridge_access.zig");
const access_component = @import("air/cartridge_access_component.zig");
const machine_access = @import("air/cartridge_machine_access.zig");
const machine_runner = @import("runner/machine.zig");
const rom_lookup = @import("air/cartridge_rom_lookup.zig");
const memory_lookup = @import("air/cartridge_memory_lookup.zig");
const cartridge = @import("cartridge/mod.zig");
const components = @import("cartridge_proof_components.zig");
const protocol = @import("cartridge_proof_statement.zig");
const runner = @import("runner/mod.zig");
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
    memory_accesses: []memory_lookup.Access,
    pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
        self.trace.deinit(allocator);
        allocator.free(self.memory_accesses);
        self.* = undefined;
    }
};
const Error = transaction.Error || error{
    InvalidLogSize,
    InvalidProofShape,
    InvalidPreparedGeometry,
};
pub const PackedTrace = struct {
    columns: [access_component.N_MAIN_COLUMNS][]M31,
    allocator: std.mem.Allocator,
    owned: bool = true,
    pub fn deinit(self: *PackedTrace) void {
        if (self.owned) for (self.columns) |column|
            self.allocator.free(column);
        self.* = undefined;
    }
    pub fn disown(self: *PackedTrace) void {
        self.owned = false;
    }
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
        @compileError("SM83 cartridge engine uses incompatible protocol types");
    }
}
pub fn proveExecutionWithEngine(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    rom: cartridge.Cartridge,
    initial_images: memory_lookup.Images,
    final_images: memory_lookup.Images,
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
    statement: ExecutionStatement,
    proof_in: Proof,
) !void {
    comptime assertProverEngine(Engine);
    protocol.validate(
        statement,
        rom,
        initial_images,
        final_images,
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
        &protocol.preprocessedLogSizes(statement.log_size),
        &channel,
    );
    protocol.mixPublic(&channel, statement);
    try scheme.commit(
        allocator,
        proof.commitment_scheme_proof.commitments.items[1],
        &protocol.mainLogSizes(statement.log_size),
        &channel,
    );
    const rom_relation = try rom_lookup.Relation.draw(
        allocator,
        &channel,
    );
    const memory_relation = try memory_lookup.Relation.draw(
        allocator,
        &channel,
    );
    try rom_lookup.verifyCancellation(statement.rom_lookup_claims);
    try memory_lookup.verifyCancellation(statement.memory_lookup_claims);
    protocol.mixLookupClaims(
        &channel,
        statement.rom_lookup_claims,
        statement.memory_lookup_claims,
    );
    try scheme.commit(
        allocator,
        proof.commitment_scheme_proof.commitments.items[2],
        &protocol.interactionLogSizes(statement.log_size),
        &channel,
    );
    var context: components.Context = undefined;
    components.init(
        &context,
        statement,
        rom_relation,
        memory_relation,
        statement.rom_lookup_claims,
        statement.memory_lookup_claims,
    );
    var storage: [components.N_COMPONENTS]components.VerifierComponent =
        undefined;
    const verifier_components = try components.verifier(
        &context,
        &storage,
    );
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
    pub const PackedAccessMutation = enum {
        region,
        physical_address,
        value,
    };
    pub const MemoryEndpoint = enum { system, sram };
    pub const PreprocessedMutation = enum { rom, system, sram };
    pub fn proveInactiveExecutionWithEngine(
        comptime Engine: type,
        allocator: std.mem.Allocator,
        pcs_config: pcs_core.PcsConfig,
        rom: cartridge.Cartridge,
        initial_images: memory_lookup.Images,
        final_images: memory_lookup.Images,
        steps: []const runner.CartridgeStepTrace,
    ) !void {
        const prepared = try prepare(
            allocator,
            rom,
            initial_images,
            final_images,
            steps,
        );
        for (0..execution.N_FAMILY_SELECTORS) |selector| {
            @memset(
                @constCast(prepared.trace.main.columns.?[
                    protocol.FAMILY_MAIN_OFFSET + selector
                ].values),
                M31.zero(),
            );
        }
        try proveMutation(Engine, allocator, pcs_config, prepared);
    }
    pub fn proveForgedPackedAccessWithEngine(
        comptime Engine: type,
        allocator: std.mem.Allocator,
        pcs_config: pcs_core.PcsConfig,
        rom: cartridge.Cartridge,
        initial_images: memory_lookup.Images,
        final_images: memory_lookup.Images,
        steps: []const runner.CartridgeStepTrace,
        mutation: PackedAccessMutation,
    ) !void {
        const prepared = try prepare(
            allocator,
            rom,
            initial_images,
            final_images,
            steps,
        );
        const leaf_column = switch (mutation) {
            .region => access.REGION_OFFSET +
                @intFromEnum(
                    runner.cartridge_memory.Region.cartridge_rom,
                ),
            .physical_address => access.PHYSICAL_OFFSET,
            .value => access.ACCESS_VALUE_OFFSET,
        };
        try toggleMain(
            prepared,
            protocol.PACKED_ACCESS_MAIN_OFFSET + leaf_column,
            0,
        );
        try proveMutation(Engine, allocator, pcs_config, prepared);
    }
    pub fn proveForgedMapperEndpointWithEngine(
        comptime Engine: type,
        allocator: std.mem.Allocator,
        pcs_config: pcs_core.PcsConfig,
        rom: cartridge.Cartridge,
        initial_images: memory_lookup.Images,
        final_images: memory_lookup.Images,
        steps: []const runner.CartridgeStepTrace,
    ) !void {
        var prepared = try prepare(
            allocator,
            rom,
            initial_images,
            final_images,
            steps,
        );
        prepared.request.final_mapper.rom_bank_register +%= 1;
        try proveMutation(Engine, allocator, pcs_config, prepared);
    }
    pub fn proveForgedMemoryEndpointWithEngine(
        comptime Engine: type,
        allocator: std.mem.Allocator,
        pcs_config: pcs_core.PcsConfig,
        rom: cartridge.Cartridge,
        initial_images: memory_lookup.Images,
        final_images: memory_lookup.Images,
        steps: []const runner.CartridgeStepTrace,
        endpoint: MemoryEndpoint,
    ) !void {
        const prepared = try prepare(
            allocator,
            rom,
            initial_images,
            final_images,
            steps,
        );
        const address = switch (endpoint) {
            .system => memory_lookup.SYSTEM_SIZE - 1,
            .sram => memory_lookup.KEY_COUNT - 1,
        };
        try togglePreprocessed(
            prepared,
            protocol.MEMORY_FINAL_PREPROCESSED,
            memory_lookup.BOUNDARY_LOG_SIZE,
            address,
        );
        try proveMutation(Engine, allocator, pcs_config, prepared);
    }
    pub fn proveForgedRomByteWithEngine(
        comptime Engine: type,
        allocator: std.mem.Allocator,
        pcs_config: pcs_core.PcsConfig,
        rom: cartridge.Cartridge,
        initial_images: memory_lookup.Images,
        final_images: memory_lookup.Images,
        steps: []const runner.CartridgeStepTrace,
    ) !void {
        const prepared = try prepare(
            allocator,
            rom,
            initial_images,
            final_images,
            steps,
        );
        const physical = steps[0].accesses[0].?.physical_offset orelse
            return error.NoRomRead;
        try togglePreprocessed(
            prepared,
            protocol.ROM_VALUE_PREPROCESSED,
            rom_lookup.ROM_LOG_SIZE,
            physical,
        );
        try proveMutation(Engine, allocator, pcs_config, prepared);
    }
    pub fn proveForgedRomMultiplicityWithEngine(
        comptime Engine: type,
        allocator: std.mem.Allocator,
        pcs_config: pcs_core.PcsConfig,
        rom: cartridge.Cartridge,
        initial_images: memory_lookup.Images,
        final_images: memory_lookup.Images,
        steps: []const runner.CartridgeStepTrace,
    ) !void {
        const prepared = try prepare(
            allocator,
            rom,
            initial_images,
            final_images,
            steps,
        );
        const physical = steps[0].accesses[0].?.physical_offset orelse
            return error.NoRomRead;
        try toggleMain(
            prepared,
            protocol.ROM_MULTIPLICITY_MAIN_OFFSET,
            physical,
        );
        try proveMutation(Engine, allocator, pcs_config, prepared);
    }
    pub fn proveNonCanonicalPreprocessedWithEngine(
        comptime Engine: type,
        allocator: std.mem.Allocator,
        pcs_config: pcs_core.PcsConfig,
        rom: cartridge.Cartridge,
        initial_images: memory_lookup.Images,
        final_images: memory_lookup.Images,
        steps: []const runner.CartridgeStepTrace,
        mutation: PreprocessedMutation,
    ) !ProveOutput {
        const prepared = try prepare(
            allocator,
            rom,
            initial_images,
            final_images,
            steps,
        );
        switch (mutation) {
            .rom => try protocol.mutateUnusedRomByte(
                prepared.trace.preprocessed.columns.?,
            ),
            .system => try protocol.mutateUnusedSystemByte(
                prepared.trace.preprocessed.columns.?,
            ),
            .sram => try protocol.mutateUnusedSramByte(
                prepared.trace.preprocessed.columns.?,
            ),
        }
        return takeOutput(
            allocator,
            try provePrepared(Engine, allocator, pcs_config, prepared),
        );
    }
};
fn proveMutation(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    prepared: PreparedExecution,
) !void {
    comptime assertProverEngine(Engine);
    var output = try provePrepared(
        Engine,
        allocator,
        pcs_config,
        prepared,
    );
    output.proof.deinit(allocator);
}
fn toggleMain(
    prepared: PreparedExecution,
    column: usize,
    logical_row: usize,
) !void {
    const columns = prepared.trace.main.columns orelse
        return error.PreparedInputConsumed;
    const storage = try core_air_utils.circleBitReversedIndex(
        columns[column].log_size,
        logical_row,
    );
    const values = @constCast(columns[column].values);
    values[storage] = M31.one().sub(values[storage]);
}
fn togglePreprocessed(
    prepared: PreparedExecution,
    column: usize,
    log_size: u32,
    logical_row: usize,
) !void {
    const columns = prepared.trace.preprocessed.columns orelse
        return error.PreparedInputConsumed;
    const storage = try core_air_utils.circleBitReversedIndex(
        log_size,
        logical_row,
    );
    const values = @constCast(columns[column].values);
    values[storage] = M31.one().sub(values[storage]);
}
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
    steps: []const runner.CartridgeStepTrace,
) !PreparedExecution {
    if (steps.len < 16 or !std.math.isPowerOfTwo(steps.len))
        return error.InvalidTraceLength;
    try validateDetached(steps);
    var machine = try execution_trace.generate(allocator, steps);
    defer machine.deinit();
    var families = try family_trace.generate(allocator, steps);
    defer families.deinit();
    var access_trace = try generatePacked(allocator, steps, machine.log_size);
    defer access_trace.deinit();
    var mutable = try memory_lookup.generateWitness(
        allocator,
        steps,
        initial_images,
        final_images,
    );
    defer mutable.deinit();
    const initial_mapper =
        (try access.ValidatedStep.init(steps[0])).mapper_before[0];
    const last = try access.ValidatedStep.init(steps[steps.len - 1]);
    const final_mapper = last.mapper_after[
        steps[steps.len - 1].instruction.cycle_count - 1
    ];
    const preprocessed = try protocol.canonicalPreprocessed(
        allocator,
        machine.log_size,
        rom,
        initial_images,
        final_images,
    );
    var preprocessed_moved = false;
    errdefer if (!preprocessed_moved) freeEvaluations(
        allocator,
        preprocessed,
    );
    const main = try allocator.alloc(
        prover_pcs.ColumnEvaluation,
        protocol.N_MAIN_COLUMNS,
    );
    var main_moved = false;
    errdefer if (!main_moved) allocator.free(main);
    setEvaluations(
        main[protocol.EXECUTION_MAIN_OFFSET..protocol.FAMILY_MAIN_OFFSET],
        &machine.main,
        machine.log_size,
    );
    setEvaluations(
        main[protocol.FAMILY_MAIN_OFFSET..protocol.PACKED_ACCESS_MAIN_OFFSET],
        &families.main,
        machine.log_size,
    );
    setEvaluations(
        main[protocol.PACKED_ACCESS_MAIN_OFFSET..protocol.MUTABLE_WITNESS_MAIN_OFFSET],
        &access_trace.columns,
        machine.log_size,
    );
    setEvaluations(
        main[protocol.MUTABLE_WITNESS_MAIN_OFFSET..protocol.ROM_MULTIPLICITY_MAIN_OFFSET],
        &mutable.main,
        machine.log_size,
    );
    const multiplicity = try rom_lookup.committedMultiplicities(
        allocator,
        steps,
        rom.bytes,
    );
    var multiplicity_moved = false;
    errdefer if (!multiplicity_moved) allocator.free(multiplicity);
    main[protocol.ROM_MULTIPLICITY_MAIN_OFFSET] = .{
        .log_size = rom_lookup.ROM_LOG_SIZE,
        .values = multiplicity,
    };
    main[protocol.FINAL_CLOCK_MAIN_OFFSET] = .{
        .log_size = memory_lookup.BOUNDARY_LOG_SIZE,
        .values = mutable.final_clocks,
    };
    const memory_accesses = mutable.takeAccesses();
    errdefer allocator.free(memory_accesses);
    const statement = protocol.init(
        machine.log_size,
        machine.initial,
        machine.final,
        initial_mapper,
        final_mapper,
        rom,
        initial_images,
        final_images,
    );
    try protocol.validate(statement, rom, initial_images, final_images);
    machine.disownMain();
    families.disownMain();
    access_trace.disown();
    mutable.disownColumns();
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
        .initial_images = initial_images,
        .final_images = final_images,
        .memory_accesses = memory_accesses,
    };
}
pub fn generatePacked(
    allocator: std.mem.Allocator,
    steps: anytype,
    log_size: u32,
) !PackedTrace {
    var result = PackedTrace{
        .columns = undefined,
        .allocator = allocator,
    };
    var initialized: usize = 0;
    errdefer for (result.columns[0..initialized]) |column|
        allocator.free(column);
    for (&result.columns) |*column| {
        column.* = try allocator.alloc(M31, steps.len);
        @memset(column.*, M31.zero());
        initialized += 1;
    }
    for (steps, 0..) |step, row| {
        const values = if (@TypeOf(step) == runner.CartridgeStepTrace)
            try access_component.columns(step)
        else if (@TypeOf(step) == machine_runner.CartridgeStepResult)
            machine_access.columns(try machine_access.ValidatedStep.init(step))
        else
            @compileError("unsupported cartridge packed-access input");
        const storage = try core_air_utils.circleBitReversedIndex(
            log_size,
            row,
        );
        for (&result.columns, values) |column, value|
            column[storage] = value;
    }
    return result;
}
fn validateDetached(steps: []const runner.CartridgeStepTrace) !void {
    for (steps) |step| {
        _ = try access.ValidatedStep.init(step);
        for (step.activeAccesses()) |maybe_access| {
            const item = maybe_access orelse continue;
            if (item.region == .joypad_mmio or
                item.region == .timer_mmio or
                item.region == .ppu_mmio)
                return error.AttachedDeviceAccess;
            if (item.region == .cartridge_open_bus)
                return error.UnsupportedOpenBus;
        }
    }
}
pub fn setEvaluations(
    destination: []prover_pcs.ColumnEvaluation,
    sources: []const []M31,
    log_size: u32,
) void {
    std.debug.assert(destination.len == sources.len);
    for (destination, sources) |*column, values|
        column.* = .{ .log_size = log_size, .values = values };
}
pub fn freeEvaluations(
    allocator: std.mem.Allocator,
    columns: []prover_pcs.ColumnEvaluation,
) void {
    for (columns) |column| allocator.free(@constCast(column.values));
    allocator.free(columns);
}
fn validateLogs(
    columns: []const prover_pcs.ColumnEvaluation,
    expected: []const u32,
) Error!void {
    if (columns.len != expected.len)
        return error.InvalidPreparedGeometry;
    for (columns, expected) |column, log_size| {
        if (column.log_size != log_size or
            column.values.len != @as(usize, 1) << @intCast(log_size))
            return error.InvalidPreparedGeometry;
    }
}
pub fn requiredCompositionLog(log_size: u32) error{InvalidLogSize}!u32 {
    const access_log = std.math.add(u32, log_size, 1) catch
        return error.InvalidLogSize;
    const rom_log = std.math.add(u32, rom_lookup.ROM_LOG_SIZE, 1) catch
        return error.InvalidLogSize;
    const memory_log = std.math.add(
        u32,
        memory_lookup.BOUNDARY_LOG_SIZE,
        1,
    ) catch return error.InvalidLogSize;
    return @max(access_log, @max(rom_log, memory_log));
}

const ProvingSpec = struct {
    pub const Statement = ExecutionStatement;
    pub const PreparedInput = PreparedExecution;
    pub const ProverContext = components.Context;
    pub const max_components = components.N_COMPONENTS;

    pub const PreparedInteraction = struct {
        columns: transaction.OwnedColumns,
        rom_relation: rom_lookup.Relation,
        memory_relation: memory_lookup.Relation,
        rom_claims: rom_lookup.Claims,
        memory_claims: memory_lookup.Claims,
    };

    pub fn validateRequest(request: Statement) Error!void {
        try protocol.validateShape(request);
    }

    pub fn validatePrepared(prepared: *const PreparedInput) Error!void {
        try validateLogs(
            prepared.trace.preprocessed.columns orelse
                return error.PreparedInputConsumed,
            &protocol.preprocessedLogSizes(prepared.request.log_size),
        );
        try validateLogs(
            prepared.trace.main.columns orelse
                return error.PreparedInputConsumed,
            &protocol.mainLogSizes(prepared.request.log_size),
        );
    }

    pub fn compositionLog(request: Statement) Error!u32 {
        return requiredCompositionLog(request.log_size);
    }

    pub fn beforeMainCommit(channel: *Channel, request: Statement) !void {
        protocol.mixPublic(channel, request);
    }

    pub fn prepareInteraction(
        allocator: std.mem.Allocator,
        channel: *Channel,
        prepared: *const PreparedInput,
    ) !PreparedInteraction {
        const rom_relation = try rom_lookup.Relation.draw(
            allocator,
            channel,
        );
        const memory_relation = try memory_lookup.Relation.draw(
            allocator,
            channel,
        );
        var rom = try rom_lookup.generate(
            allocator,
            prepared.steps,
            prepared.rom.bytes,
            rom_relation,
        );
        defer rom.deinit();
        var mutable = try memory_lookup.generateInteraction(
            allocator,
            prepared.memory_accesses,
            prepared.request.log_size,
            prepared.initial_images,
            prepared.final_images,
            memory_relation,
        );
        defer mutable.deinit();
        const output = try allocator.alloc(
            prover_pcs.ColumnEvaluation,
            protocol.N_INTERACTION_COLUMNS,
        );
        errdefer allocator.free(output);
        setEvaluations(
            output[protocol.ROM_EXECUTION_INTERACTION_OFFSET..protocol.MUTABLE_EXECUTION_INTERACTION_OFFSET],
            rom.columns[0..rom_lookup.N_EXECUTION_COLUMNS],
            prepared.request.log_size,
        );
        setEvaluations(
            output[protocol.MUTABLE_EXECUTION_INTERACTION_OFFSET..protocol.ROM_TABLE_INTERACTION_OFFSET],
            mutable.columns[0..memory_lookup.N_EXECUTION_COLUMNS],
            prepared.request.log_size,
        );
        setEvaluations(
            output[protocol.ROM_TABLE_INTERACTION_OFFSET..protocol.MUTABLE_BOUNDARY_INTERACTION_OFFSET],
            rom.columns[rom_lookup.N_EXECUTION_COLUMNS..],
            rom_lookup.ROM_LOG_SIZE,
        );
        setEvaluations(
            output[protocol.MUTABLE_BOUNDARY_INTERACTION_OFFSET..],
            mutable.columns[memory_lookup.N_EXECUTION_COLUMNS..],
            memory_lookup.BOUNDARY_LOG_SIZE,
        );
        const rom_claims = rom.claims;
        const memory_claims = mutable.claims;
        rom.disown();
        mutable.disown();
        return .{
            .columns = transaction.OwnedColumns.init(output),
            .rom_relation = rom_relation,
            .memory_relation = memory_relation,
            .rom_claims = rom_claims,
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
            interaction.rom_claims,
            interaction.memory_claims,
        );
    }

    pub fn initProverContext(
        out: *ProverContext,
        _: *Channel,
        request: Statement,
        interaction: *const PreparedInteraction,
    ) !void {
        try rom_lookup.verifyCancellation(interaction.rom_claims);
        try memory_lookup.verifyCancellation(interaction.memory_claims);
        components.init(
            out,
            request,
            interaction.rom_relation,
            interaction.memory_relation,
            interaction.rom_claims,
            interaction.memory_claims,
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

test "cartridge prover facade keeps backend selection external" {
    switch (@typeInfo(@TypeOf(ProverEngineForBackend))) {
        .@"fn" => {},
        else => @compileError("ProverEngineForBackend must remain a function"),
    }
    try std.testing.expectEqual(@as(u32, 21), try requiredCompositionLog(4));
    try std.testing.expectEqual(@as(u32, 21), try requiredCompositionLog(18));
}
