//! Full Ethereum + incremental-memory V4 proof orchestration.
//!
//! The authenticated physical-V2 VM and all fourteen canonical Ethereum
//! components remain the exact prefix. One changed-only memory bridge appends
//! after them in every commitment and in the component roster. The joined
//! profile is supplied generically by the integration owner and must bind the
//! complete extension statement and relocated bridge before Tree 0.

const std = @import("std");
const pcs_core = @import("stwo_core").pcs;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const prover_api = @import("stwo_prover_api");
const stage_profile = prover_api.stage_profile;
const work_pool = @import("stwo_prover_engine").work_pool;

const logup = @import("../air/logup.zig");
const lookup_physical_v2 =
    @import("../air/lang/lookup_physical_manifest_v2.zig");
const statement = @import("../air/statement.zig");
const statement_v2 = @import("../air/statement_v2.zig");
const public_data_v1 = @import("../air/public_data.zig");
const incremental_public = @import("../air/incremental_public_logup_v4.zig");
const ethereum_statement =
    @import("../air/guest_precompile/ethereum_statement.zig");
const state_chain = @import("../runner/state_chain.zig");
const trace_mod = @import("../runner/trace.zig");
const keccak_calls_mod =
    @import("../runner/guest_precompile/keccakf_call_buffer.zig");
const keccak_rows_mod =
    @import("../runner/guest_precompile/keccakf_v1.zig");
const recovery_calls_mod =
    @import("../runner/guest_precompile/secp256k1_recover_call_buffer.zig");
const recovery_rows_mod =
    @import("../runner/guest_precompile/secp256k1_recover_v1.zig");

const incremental_bridge = @import("incremental_bridge_external_v3.zig");
const incremental_witness = @import("incremental_commitment_witness_v3.zig");
const orchestration = @import("orchestration.zig");
const proof_finalize = @import("proof_finalize.zig");
const proof_workspace = @import("proof_workspace.zig");
const proof_admission =
    @import("../air/guest_precompile/ethereum_proof_admission.zig");
const ethereum_assembly = @import("guest_precompile/ethereum_assembly.zig");
const ethereum_interaction = @import("guest_precompile/ethereum_interaction.zig");
const ethereum_main = @import("guest_precompile/ethereum_main.zig");
const ethereum_preprocessed =
    @import("guest_precompile/ethereum_preprocessed.zig");
const ethereum_transcript = @import("guest_precompile/ethereum_transcript.zig");
const ethereum_types = @import("guest_precompile/ethereum_types.zig");
const ethereum_witness = @import("guest_precompile/ethereum_witness.zig");
const external_tree = @import("guest_precompile/external_profile_tree.zig");
const segment_orchestration =
    @import("guest_precompile/ethereum_segment_orchestration.zig");
const statement_geometry = @import("statement_geometry.zig");
const types = @import("types.zig");

pub const PRODUCTION_ACTIVE = false;
pub const FORMAT_VERSION: u16 = 4;
pub const ExecutionOptions = orchestration.ExecutionOptionsV2;

pub const InteractionClaimsV4 = struct {
    base: *statement.RiscVInteractionClaim,
    ethereum: ethereum_types.ExtensionClaim,
    bridge: QM31,

    pub fn deinit(self: *InteractionClaimsV4, allocator: std.mem.Allocator) void {
        allocator.destroy(self.base);
        self.* = undefined;
    }
};

pub fn ProveOutputV4(comptime Engine: type) type {
    return struct {
        statement: statement_v2.RiscVStatementV2,
        extension: ethereum_statement.Statement,
        bridge_geometry: incremental_bridge.GeometryV3,
        proof: types.ProofForEngine(Engine),
        claims: InteractionClaimsV4,
        public_boundary_identity_sha256: [32]u8,
        profile_identity_sha256: [32]u8,

        const Self = @This();

        pub fn deinitAfterProofMoved(
            self: *Self,
            allocator: std.mem.Allocator,
        ) void {
            self.claims.deinit(allocator);
            self.* = undefined;
        }

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            self.proof.deinit(allocator);
            self.claims.deinit(allocator);
            self.* = undefined;
        }
    };
}

/// Borrowed, process-local result of exactly one statement-geometry and
/// Ethereum-witness construction. This type has no codec and is meaningful
/// only while its owning integration transaction keeps every pointer alive.
pub const PreparedProofInputsV4 = struct {
    workspace: *proof_workspace.ProofWorkspace,
    geometry: *const statement_geometry.V2Geometry,
    ethereum_witness: *const ethereum_witness.Witness,
    extension: *const ethereum_statement.Statement,
};

pub fn prepareStatement(
    allocator: std.mem.Allocator,
    exec_trace: *const trace_mod.Trace,
    opt_chain: ?*const state_chain.StateChainTracker,
    full_witness: *const incremental_witness.FullWitnessV3,
    public_data: @import("../air/public_data_v2.zig").PublicDataV2,
    external_retirements: u32,
) !statement_v2.RiscVStatementV2 {
    if (exec_trace.step_count == 0) return error.EmptyTrace;
    const workspace = try proof_workspace.ProofWorkspace.create(allocator);
    defer workspace.destroy(allocator);
    const built = try statement_geometry.buildExternalV2(
        allocator,
        workspace,
        exec_trace,
        &full_witness.base,
        opt_chain,
        public_data,
        external_retirements,
        .proof,
    );
    return built.statement;
}

pub fn proveWithEngineUsingChannel(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    exec_trace: *const trace_mod.Trace,
    opt_chain: ?*const state_chain.StateChainTracker,
    full_witness: *const incremental_witness.FullWitnessV3,
    expected_statement: *const statement_v2.RiscVStatementV2,
    role_aware_public: *const public_data_v1.PublicData,
    keccak_calls: *const keccak_calls_mod.Frozen,
    keccak_rows: *const keccak_rows_mod.FrozenExecutionRows,
    recovery_calls: *const recovery_calls_mod.Frozen,
    recovery_rows: *const recovery_rows_mod.FrozenExecutionRows,
    profile: anytype,
    recorder: ?*stage_profile.Recorder,
    channel: *Engine.Channel,
    execution: ExecutionOptions,
) !ProveOutputV4(Engine) {
    comptime types.assertProverEngine(Engine);
    if (execution.cpu) |cpu| {
        if (cpu.contention_policy != .strict)
            return error.NonStrictExecutionPolicy;
    }
    if (exec_trace.step_count == 0) return error.EmptyTrace;
    if (!std.meta.eql(pcs_config, try profile.pcsConfig()))
        return error.IncrementalEthereumPcsMismatch;

    var execution_pool: orchestration.ProofExecutionPool = .{};
    try execution_pool.initInPlace(allocator, execution.cpu);
    defer execution_pool.deinit();
    const workspace = try proof_workspace.ProofWorkspace.create(allocator);
    defer workspace.destroy(allocator);
    const external_count = std.math.add(
        usize,
        keccak_calls.len(),
        recovery_calls.len(),
    ) catch return error.InvalidStatement;
    const external_retirements = std.math.cast(u32, external_count) orelse
        return error.InvalidStatement;
    const built = try statement_geometry.buildExternalV2(
        allocator,
        workspace,
        exec_trace,
        &full_witness.base,
        opt_chain,
        expected_statement.public_data,
        external_retirements,
        .proof,
    );
    if (!std.meta.eql(built.statement, expected_statement.*))
        return error.IncrementalEthereumStatementMismatch;
    try incremental_public.validateSharedAuthority(
        &built.statement.public_data,
        role_aware_public,
    );
    if (execution.statement_admission) |admission|
        try admission.admit(&built.statement);
    const core_public = try statement_v2.canonicalCorePublicData(
        &built.statement.public_data,
    );
    _ = try validateClockAuthority(
        exec_trace,
        keccak_calls.len(),
        keccak_rows.rows().len,
        recovery_calls.len(),
        recovery_rows.rows().len,
        core_public.clock,
    );

    var witness = try ethereum_witness.Witness.init(
        allocator,
        keccak_calls.records(),
        keccak_rows.rows(),
        recovery_calls.records(),
        recovery_rows.rows(),
        core_public.clock,
    );
    defer witness.deinit();
    const extension = try ethereum_statement.Statement.canonicalV2(
        &built.statement,
        @intCast(keccak_calls.len()),
        @intCast(recovery_calls.len()),
        witness.shapes(),
    );
    try proof_admission.validateV2(&built.statement, &extension, .proof);

    return provePreparedAfterAdmission(
        Engine,
        allocator,
        pcs_config,
        exec_trace,
        opt_chain,
        full_witness,
        role_aware_public,
        keccak_calls,
        recovery_calls,
        profile,
        recorder,
        channel,
        execution,
        &execution_pool,
        workspace,
        &built,
        &witness,
        &extension,
    );
}

/// Additive one-pass proof entry. The integration owner must coldly mint and
/// retain `prepared`; this function validates its exact statement/extension
/// closure, but never reconstructs statement geometry or an Ethereum witness.
pub fn provePreparedWithEngineUsingChannel(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    exec_trace: *const trace_mod.Trace,
    opt_chain: ?*const state_chain.StateChainTracker,
    full_witness: *const incremental_witness.FullWitnessV3,
    expected_statement: *const statement_v2.RiscVStatementV2,
    role_aware_public: *const public_data_v1.PublicData,
    keccak_calls: *const keccak_calls_mod.Frozen,
    keccak_rows: *const keccak_rows_mod.FrozenExecutionRows,
    recovery_calls: *const recovery_calls_mod.Frozen,
    recovery_rows: *const recovery_rows_mod.FrozenExecutionRows,
    prepared: PreparedProofInputsV4,
    profile: anytype,
    recorder: ?*stage_profile.Recorder,
    channel: *Engine.Channel,
    execution: ExecutionOptions,
) !ProveOutputV4(Engine) {
    comptime types.assertProverEngine(Engine);
    if (execution.cpu) |cpu| {
        if (cpu.contention_policy != .strict)
            return error.NonStrictExecutionPolicy;
    }
    if (exec_trace.step_count == 0) return error.EmptyTrace;
    if (!std.meta.eql(pcs_config, try profile.pcsConfig()))
        return error.IncrementalEthereumPcsMismatch;

    var execution_pool: orchestration.ProofExecutionPool = .{};
    try execution_pool.initInPlace(allocator, execution.cpu);
    defer execution_pool.deinit();

    const external_count = std.math.add(
        usize,
        keccak_calls.len(),
        recovery_calls.len(),
    ) catch return error.InvalidStatement;
    const external_retirements = std.math.cast(u32, external_count) orelse
        return error.InvalidStatement;
    if (!std.meta.eql(prepared.geometry.statement, expected_statement.*) or
        !std.meta.eql(
            prepared.workspace.statement,
            expected_statement.core,
        ) or prepared.extension.counts.external_retirements !=
        external_retirements)
    {
        return error.IncrementalEthereumPreparedStatementMismatch;
    }
    try incremental_public.validateSharedAuthority(
        &expected_statement.public_data,
        role_aware_public,
    );
    if (execution.statement_admission) |admission|
        try admission.admit(expected_statement);
    const core_public = try statement_v2.canonicalCorePublicData(
        &expected_statement.public_data,
    );
    _ = try validateClockAuthority(
        exec_trace,
        keccak_calls.len(),
        keccak_rows.rows().len,
        recovery_calls.len(),
        recovery_rows.rows().len,
        core_public.clock,
    );
    const canonical_extension = try ethereum_statement.Statement.canonicalV2(
        expected_statement,
        @intCast(keccak_calls.len()),
        @intCast(recovery_calls.len()),
        prepared.ethereum_witness.shapes(),
    );
    if (!std.meta.eql(canonical_extension, prepared.extension.*))
        return error.IncrementalEthereumPreparedExtensionMismatch;
    try proof_admission.validateV2(
        expected_statement,
        prepared.extension,
        .proof,
    );

    return provePreparedAfterAdmission(
        Engine,
        allocator,
        pcs_config,
        exec_trace,
        opt_chain,
        full_witness,
        role_aware_public,
        keccak_calls,
        recovery_calls,
        profile,
        recorder,
        channel,
        execution,
        &execution_pool,
        prepared.workspace,
        prepared.geometry,
        prepared.ethereum_witness,
        prepared.extension,
    );
}

fn provePreparedAfterAdmission(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    exec_trace: *const trace_mod.Trace,
    opt_chain: ?*const state_chain.StateChainTracker,
    full_witness: *const incremental_witness.FullWitnessV3,
    role_aware_public: *const public_data_v1.PublicData,
    keccak_calls: *const keccak_calls_mod.Frozen,
    recovery_calls: *const recovery_calls_mod.Frozen,
    profile: anytype,
    recorder: ?*stage_profile.Recorder,
    channel: *Engine.Channel,
    execution: ExecutionOptions,
    execution_pool: *orchestration.ProofExecutionPool,
    workspace: *proof_workspace.ProofWorkspace,
    built: *const statement_geometry.V2Geometry,
    witness: *const ethereum_witness.Witness,
    extension: *const ethereum_statement.Statement,
) !ProveOutputV4(Engine) {
    const core = &workspace.statement;
    var manifest = lookup_physical_v2.Manifest.native();
    const authenticated = try lookup_physical_v2.AuthenticatedStatement.init(
        core,
        &manifest,
    );
    try profile.validateAgainstStatement(
        &built.statement,
        extension,
        role_aware_public,
    );
    const bridge_geometry = profile.bridge_geometry;
    const bridge_rows = full_witness.boundary.bridgeRows();
    if (bridge_rows.len != @as(usize, bridge_geometry.n_rows))
        return error.IncrementalBridgeGeometryMismatch;

    try profile.mixPreTree0(
        &built.statement,
        role_aware_public,
        channel,
    );
    var scheme = try Engine.init(allocator, pcs_config);
    var scheme_owned = true;
    defer if (scheme_owned) Engine.deinit(&scheme, allocator);
    scheme.setCoefficientRetentionPolicy(.never);

    var bridge_tree0 = try incremental_bridge.PreprocessedTraceV3.init(
        allocator,
        &bridge_geometry,
    );
    defer bridge_tree0.deinit();
    const tree0_blocks = [_]external_tree.BorrowedBlock{bridge_tree0.block()};
    const tree0 = try ethereum_preprocessed.generateWithExternalBlocks(
        allocator,
        core,
        extension,
        &tree0_blocks,
    );
    var tree0_moved = false;
    errdefer if (!tree0_moved) freeColumns(allocator, tree0);
    tree0_moved = true;
    try Engine.commit(&scheme, allocator, tree0, recorder, channel);

    var bridge_tree1 = try incremental_bridge.MainTraceV3.init(
        allocator,
        bridge_rows,
        &bridge_geometry,
    );
    defer bridge_tree1.deinit();
    const tree1_blocks = [_]external_tree.BorrowedBlock{bridge_tree1.block()};
    const tree1_logs = try ethereum_main.logSizesWithExternalBlocks(
        allocator,
        core,
        extension,
        &tree1_blocks,
    );
    defer allocator.free(tree1_logs);
    _ = try segment_orchestration.requireTree1Residency(
        tree1_logs,
        pcs_config.fri_config.log_blowup_factor,
        if (execution.cpu) |cpu|
            cpu.host_byte_budget
        else
            std.math.maxInt(usize),
    );
    var retained = try ethereum_main.commitWithExternalBlocks(
        Engine,
        allocator,
        workspace,
        &scheme,
        channel,
        recorder,
        exec_trace,
        &full_witness.base,
        built.base,
        opt_chain,
        witness,
        keccak_calls.records(),
        recovery_calls.records(),
        &tree1_blocks,
    );
    defer retained.deinit(allocator, workspace);

    try profile.mixPostTree1(
        &built.statement,
        role_aware_public,
        channel,
    );
    const interaction_pow = channel.grind(
        @import("../air/transcript/mod.zig").INTERACTION_POW_BITS,
    );
    channel.mixU64(interaction_pow);
    const relations = try ethereum_transcript.Relations.draw(
        allocator,
        channel,
    );
    try full_witness.boundary.verifyMerkleAndPoseidonCancellation(
        &relations.base,
    );

    var bridge_tree2 = try incremental_bridge.InteractionTraceV3.init(
        allocator,
        bridge_rows,
        full_witness.boundary.roots().entry,
        full_witness.boundary.roots().exit,
        &relations.base,
        &bridge_geometry,
    );
    defer bridge_tree2.deinit();
    const bridge_claim = bridge_tree2.claim();
    var bridge_columns = bridge_tree2.ownedColumns();

    const base_claim = try allocator.create(statement.RiscVInteractionClaim);
    var claim_owned = true;
    defer if (claim_owned) allocator.destroy(base_claim);
    var serial_pool: work_pool.WorkPool = undefined;
    var serial_pool_live = false;
    defer if (serial_pool_live) serial_pool.deinit();
    const pool = execution_pool.get() orelse blk: {
        try serial_pool.initInPlaceWithOptions(.{ .worker_count = 1 });
        serial_pool_live = true;
        break :blk &serial_pool;
    };
    const prefix = ethereum_transcript.Prefix{
        .interaction_pow = interaction_pow,
        .relations = relations,
    };
    const extension_claim = try ethereum_interaction
        .generateAndCommitAuthenticatedLookupV2WithExternal(
        Engine,
        allocator,
        workspace,
        &scheme,
        channel,
        recorder,
        &full_witness.base,
        built.base,
        &retained.lookup_source,
        &prefix,
        witness,
        pool,
        base_claim,
        &manifest,
        &authenticated,
        &bridge_columns,
        BridgeClaimMix{ .claim = bridge_claim },
        mixBridgeClaim,
    );
    try extension_claim.validate(extension);

    const canonical = try authenticated.canonicalInteractionClaim(
        core,
        &manifest,
        base_claim,
    );
    const public_boundary = try incremental_public.sum(
        &built.statement.public_data,
        role_aware_public,
        &relations.base,
    );
    try logup.verifyGlobalCancellation(
        &.{
            canonical.view().total(),
            extension_claim.componentSum(),
            bridge_claim,
        },
        public_boundary,
    );

    const base_components = try proof_finalize
        .assembleAuthenticatedLookupV2WithIncrementalBoundaryV3(
        workspace,
        &relations.base,
        base_claim,
        core.nMainColumns(),
        try authenticated.totalInteractionColumns(core, &manifest),
        &manifest,
        &authenticated,
    );
    const ethereum_components = try ethereum_assembly.Assembly(.prover)
        .createAuthenticatedLookupV2(
        allocator,
        &built.statement,
        extension,
        &relations,
        base_components,
        &extension_claim,
        &manifest,
        &authenticated,
    );
    defer ethereum_components.destroy(allocator);
    const roots = full_witness.boundary.roots();
    const assembly = try incremental_bridge.Assembly(.prover).create(
        allocator,
        ethereum_components.active(),
        &bridge_geometry,
        roots.entry,
        roots.exit,
        &relations.base,
        bridge_claim,
    );
    defer assembly.destroy(allocator);

    scheme_owned = false;
    var extended = try Engine.prove(
        allocator,
        assembly.active(),
        channel,
        scheme,
        .{
            .recorder = recorder,
            .cpu_composition_execution = execution.cpu,
        },
    );
    const proof = extended.proof;
    extended.aux.deinit(allocator);
    work_pool.recordProofPublicationForTest(execution_pool.get());
    claim_owned = false;
    return .{
        .statement = built.statement,
        .extension = extension.*,
        .bridge_geometry = bridge_geometry,
        .proof = proof,
        .claims = .{
            .base = base_claim,
            .ethereum = extension_claim,
            .bridge = bridge_claim,
        },
        .public_boundary_identity_sha256 = incremental_public
            .publicBoundaryIdentity(&built.statement.public_data, role_aware_public),
        .profile_identity_sha256 = profile.identity_sha256,
    };
}

const BridgeClaimMix = struct { claim: QM31 };

fn mixBridgeClaim(
    context: BridgeClaimMix,
    channel: anytype,
    _: *const statement.RiscVInteractionClaim,
    _: *const ethereum_types.ExtensionClaim,
) !void {
    incremental_bridge.mixClaim(channel, context.claim);
}

fn validateClockAuthority(
    trace: *const trace_mod.Trace,
    keccak_calls: usize,
    keccak_rows: usize,
    recovery_calls: usize,
    recovery_rows: usize,
    public_clock: u32,
) !u32 {
    if (keccak_calls != keccak_rows or recovery_calls != recovery_rows)
        return error.InvalidStatement;
    const external = std.math.add(usize, keccak_calls, recovery_calls) catch
        return error.InvalidStatement;
    const total = std.math.add(usize, trace.step_count, external) catch
        return error.InvalidStatement;
    if (std.math.cast(u32, total) != public_clock or
        trace.recordedExternalSteps() != external)
    {
        return error.InvalidStatement;
    }
    trace.validateClockRange(0, public_clock, external) catch
        return error.InvalidStatement;
    return std.math.cast(u32, external) orelse error.InvalidStatement;
}

fn freeColumns(
    allocator: std.mem.Allocator,
    columns: []@import("stwo_prover_engine").pcs.ColumnEvaluation,
) void {
    for (columns) |column| allocator.free(@constCast(column.values));
    allocator.free(columns);
}

comptime {
    if (PRODUCTION_ACTIVE or FORMAT_VERSION != 4)
        @compileError("incremental Ethereum orchestration V4 activated");
}
