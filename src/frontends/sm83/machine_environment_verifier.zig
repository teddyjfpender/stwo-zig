//! Backend-generic verifier for the complete v7 machine environment.
//!
//! The verifier reconstructs the public preprocessing independently, preserves
//! the v6 transcript prefix, and appends the APU protocol tail.

const std = @import("std");
const channel_blake2s = @import("stwo_core").channel.blake2s;
const pcs_core = @import("stwo_core").pcs;
const pcs_verifier = @import("stwo_core").pcs.verifier;
const core_proof = @import("stwo_core").proof;
const core_verifier = @import("stwo_core").verifier;
const blake2_merkle = @import("stwo_core").vcs_lifted.blake2_merkle;
const prover_api = @import("stwo_prover_api");
const prover_engine = @import("stwo_prover_engine").engine;
const transaction = @import("stwo_prover_engine").transaction;
const action_schedule = @import("action_schedule.zig");
const cartridge = @import("cartridge/mod.zig");
const environment_statement = @import("environment_statement.zig");
const geometry = @import("machine_environment_geometry.zig");
const components = @import("machine_environment_proof_components.zig");
const statement_protocol = @import("machine_environment_statement.zig");
const machine_trace = @import("machine_environment_trace.zig");
const ram_observation = @import("ram_observation.zig");
const memory_lookup = @import("air/cartridge_memory_lookup.zig");
const rom_lookup = @import("air/cartridge_rom_lookup.zig");
const action_lookup = @import("air/joypad_action_lookup.zig");
const joypad_mmio = @import("air/joypad_mmio_lookup.zig");
const timer_mmio = @import("air/timer_mmio_lookup.zig");
const ppu_mmio = @import("air/ppu_mmio_lookup.zig");
const dma_execution = @import("air/dma_execution_lookup.zig");
const apu_execution = @import("air/apu_execution_lookup.zig");
const intermediate_observation =
    @import("air/intermediate_ram_observation_lookup.zig");

pub const Hasher = blake2_merkle.Blake2sPrefixedMerkleHasher;
pub const MerkleChannel = blake2_merkle.Blake2sPrefixedMerkleChannel;
pub const Channel = channel_blake2s.Blake2sChannel;
pub const Proof = core_proof.StarkProof(Hasher);
pub const ExecutionStatement = statement_protocol.ExecutionStatement;

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
        @compileError(
            "SM83 machine-environment engine uses incompatible protocol types",
        );
    }
}

/// Consumes `proof_in` on every success and failure path.
pub fn verifyExecutionWithEngine(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    rom: cartridge.Cartridge,
    initial_images: memory_lookup.Images,
    final_images: memory_lookup.Images,
    actions: []const action_schedule.Action,
    observation_regions: []const ram_observation.Region,
    intermediate_observations: []const intermediate_observation.Sample,
    statement: ExecutionStatement,
    proof_in: Proof,
) !void {
    comptime assertProverEngine(Engine);
    preflight(
        statement,
        rom,
        initial_images,
        final_images,
        actions,
        observation_regions,
        intermediate_observations,
        proof_in.commitment_scheme_proof.commitments.items.len,
    ) catch |err| {
        var invalid = proof_in;
        invalid.deinit(allocator);
        return err;
    };

    var proof = proof_in;
    var proof_moved = false;
    defer if (!proof_moved) proof.deinit(allocator);
    try verifyPreprocessedRoot(
        Engine,
        allocator,
        pcs_config,
        statement,
        rom,
        initial_images,
        final_images,
        actions,
        observation_regions,
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

    const logs = logsFor(statement);
    try scheme.commit(
        allocator,
        proof.commitment_scheme_proof.commitments.items[0],
        &logs.preprocessed,
        &channel,
    );
    statement_protocol.mixPublic(&channel, statement);
    try scheme.commit(
        allocator,
        proof.commitment_scheme_proof.commitments.items[1],
        &logs.main,
        &channel,
    );

    const relations = try Relations.draw(allocator, &channel);
    try statement_protocol.verifyLookupCancellation(statement);
    statement_protocol.mixLookupClaims(&channel, statement);
    try scheme.commit(
        allocator,
        proof.commitment_scheme_proof.commitments.items[2],
        &logs.interaction,
        &channel,
    );

    var context: components.Context = undefined;
    components.init(
        &context,
        statement,
        relations.rom,
        relations.memory,
        relations.action,
        relations.joypad_mmio,
        relations.timer_mmio,
        relations.ppu_mmio,
        relations.dma_execution,
        relations.apu_execution,
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

/// Relation order is protocol data: preserve the v6 prefix and append v7.
const Relations = struct {
    rom: rom_lookup.Relation,
    memory: memory_lookup.Relation,
    action: action_lookup.Relation,
    joypad_mmio: joypad_mmio.Relations,
    timer_mmio: timer_mmio.Relations,
    ppu_mmio: ppu_mmio.Relations,
    dma_execution: dma_execution.Relations,
    apu_execution: apu_execution.Relation,

    fn draw(
        allocator: std.mem.Allocator,
        channel: *Channel,
    ) !Relations {
        return .{
            .rom = try rom_lookup.Relation.draw(allocator, channel),
            .memory = try memory_lookup.Relation.draw(
                allocator,
                channel,
            ),
            .action = try action_lookup.Relation.draw(
                allocator,
                channel,
            ),
            .joypad_mmio = try joypad_mmio.Relations.draw(
                allocator,
                channel,
            ),
            .timer_mmio = try timer_mmio.Relations.draw(
                allocator,
                channel,
            ),
            .ppu_mmio = try ppu_mmio.Relations.draw(
                allocator,
                channel,
            ),
            .dma_execution = try dma_execution.Relations.draw(
                allocator,
                channel,
            ),
            .apu_execution = try apu_execution.Relation.draw(
                allocator,
                channel,
            ),
        };
    }
};

const Logs = struct {
    preprocessed: [geometry.N_PREPROCESSED_COLUMNS]u32,
    main: [geometry.N_MAIN_COLUMNS]u32,
    interaction: [geometry.N_INTERACTION_COLUMNS]u32,
};

fn logsFor(statement: ExecutionStatement) Logs {
    const base = statement.base;
    return .{
        .preprocessed = geometry.preprocessedLogSizes(
            base.base.log_size,
            base.joypad_log_size,
            base.timer_log_size,
            base.intermediate_observation_log_size,
            statement.ppu_log_size,
            statement.dma_log_size,
            statement.apu_log_size,
        ),
        .main = geometry.mainLogSizes(
            base.base.log_size,
            base.joypad_log_size,
            base.timer_log_size,
            base.intermediate_observation_log_size,
            statement.ppu_log_size,
            statement.dma_log_size,
            statement.apu_log_size,
        ),
        .interaction = geometry.interactionLogSizes(
            base.base.log_size,
            base.joypad_log_size,
            base.timer_log_size,
            base.intermediate_observation_log_size,
            statement.ppu_log_size,
            statement.dma_log_size,
            statement.apu_log_size,
        ),
    };
}

fn preflight(
    statement: ExecutionStatement,
    rom: cartridge.Cartridge,
    initial_images: memory_lookup.Images,
    final_images: memory_lookup.Images,
    actions: []const action_schedule.Action,
    observation_regions: []const ram_observation.Region,
    intermediate_observations: []const intermediate_observation.Sample,
    commitment_count: usize,
) !void {
    try statement_protocol.validate(
        statement,
        rom,
        initial_images,
        final_images,
        actions,
        observation_regions,
        intermediate_observations,
    );
    if (commitment_count != 4) return error.InvalidProofShape;
}

fn verifyPreprocessedRoot(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    statement: ExecutionStatement,
    rom: cartridge.Cartridge,
    initial_images: memory_lookup.Images,
    final_images: memory_lookup.Images,
    actions: []const action_schedule.Action,
    observation_regions: []const ram_observation.Region,
    intermediate_observations: []const intermediate_observation.Sample,
    actual: Hasher.Hash,
) !void {
    const prefix_columns = try environment_statement.canonicalPreprocessed(
        allocator,
        statement.base,
        rom,
        initial_images,
        final_images,
        actions,
        observation_regions,
        intermediate_observations,
    );
    var prefix = transaction.OwnedColumns.init(prefix_columns);
    defer prefix.deinit(allocator);
    var columns = try machine_trace.extendPreprocessed(
        allocator,
        &prefix,
        statement.ppu_log_size,
        statement.dma_log_size,
        statement.apu_log_size,
    );
    defer columns.deinit(allocator);

    var scheme = try Engine.init(allocator, pcs_config);
    defer Engine.deinit(&scheme, allocator);
    var channel = Engine.Channel{};
    const owned = columns.take();
    try Engine.commit(&scheme, allocator, owned, null, &channel);
    var roots = try scheme.roots(allocator);
    defer roots.deinit(allocator);
    if (roots.items.len != 1 or !std.meta.eql(roots.items[0], actual))
        return error.InvalidPreprocessedCommitment;
}

/// Reuses production preflight logic without constructing a proof container.
pub const testing = struct {
    pub fn validatePublicAndShape(
        statement: ExecutionStatement,
        rom: cartridge.Cartridge,
        initial_images: memory_lookup.Images,
        final_images: memory_lookup.Images,
        actions: []const action_schedule.Action,
        observation_regions: []const ram_observation.Region,
        intermediate_observations: []const intermediate_observation.Sample,
        commitment_count: usize,
    ) !void {
        return preflight(
            statement,
            rom,
            initial_images,
            final_images,
            actions,
            observation_regions,
            intermediate_observations,
            commitment_count,
        );
    }

    pub fn validateLookupClaims(statement: ExecutionStatement) !void {
        return statement_protocol.verifyLookupCancellation(statement);
    }
};
