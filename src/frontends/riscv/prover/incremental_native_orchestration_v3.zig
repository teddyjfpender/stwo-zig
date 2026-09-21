//! Incremental-memory V3 native proof orchestration.
//!
//! The ordinary authenticated V2 VM stays the exact committed prefix. One
//! changed-only memory bridge is appended to Trees 0/1/2 and to the component
//! roster. Profile selection is deliberately supplied through a typed,
//! process-local hook: the frontend never invents an integration authority,
//! while the pointer-free profile remains the value later serialized by its
//! integration owner.

const std = @import("std");
const pcs_core = @import("stwo_core").pcs;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const prover_api = @import("stwo_prover_api");
const stage_profile = prover_api.stage_profile;
const work_pool = @import("stwo_prover_engine").work_pool;

const logup = @import("../air/logup.zig");
const lookup_physical_v2 =
    @import("../air/lang/lookup_physical_manifest_v2.zig");
const relation_challenges = @import("../air/relation_challenges.zig");
const public_data_v2 = @import("../air/public_data_v2.zig");
const statement_mod = @import("../air/statement.zig");
const statement_v2 = @import("../air/statement_v2.zig");
const transcript = @import("../air/transcript/mod.zig");
const state_chain = @import("../runner/state_chain.zig");
const trace_mod = @import("../runner/trace.zig");
const base_component_assembly = @import("base_component_assembly.zig");
const external_tree = @import("guest_precompile/external_profile_tree.zig");
const incremental_bridge = @import("incremental_bridge_external_v3.zig");
const incremental_witness = @import("incremental_commitment_witness_v3.zig");
const orchestration = @import("orchestration.zig");
const proof_workspace = @import("proof_workspace.zig");
const statement_geometry = @import("statement_geometry.zig");
const types = @import("types.zig");

pub const PRODUCTION_ACTIVE = false;
pub const FORMAT_VERSION: u16 = 3;
pub const ProfileIdentity = [32]u8;
pub const ExecutionOptions = orchestration.ExecutionOptionsV2;

/// Borrowed integration profile authority specialized to one proof engine.
/// The context and callbacks are process-local and are never artifact fields.
/// `profile_address` pins the exact pointer-free profile value which the hook
/// validates and mixes; a caller cannot validate one value and publish another.
/// The pre-Tree0 callback owns this exact transcript prefix, in order: the
/// q193 PCS configuration, the complete authenticated V2 public wire/native
/// statement, the authenticated physical-lookup authority, and the sealed V3
/// profile. The post-Tree1 callback mixes the canonical base main/shard frame
/// followed by the bridge descriptor. Claims are mixed separately, base first
/// and bridge second, immediately before Tree2.
pub fn ProfileHookV3(comptime Engine: type) type {
    return struct {
        context: *const anyopaque,
        profile_address: *const anyopaque,
        profile_identity_sha256: ProfileIdentity,
        validate_fn: *const fn (
            *const anyopaque,
            pcs_core.PcsConfig,
            *const statement_v2.RiscVStatementV2,
            *const incremental_bridge.GeometryV3,
            *const lookup_physical_v2.Manifest,
            *const lookup_physical_v2.AuthenticatedStatement,
        ) anyerror!void,
        mix_pre_tree0_fn: *const fn (
            *const anyopaque,
            *const statement_v2.RiscVStatementV2,
            *Engine.Channel,
        ) anyerror!void,
        mix_post_tree1_fn: *const fn (
            *const anyopaque,
            *const statement_v2.RiscVStatementV2,
            *Engine.Channel,
        ) anyerror!void,

        const Self = @This();

        pub fn validate(
            self: Self,
            profile: *const anyopaque,
            pcs_config: pcs_core.PcsConfig,
            statement: *const statement_v2.RiscVStatementV2,
            bridge_geometry: *const incremental_bridge.GeometryV3,
            manifest: *const lookup_physical_v2.Manifest,
            authenticated: *const lookup_physical_v2.AuthenticatedStatement,
        ) !void {
            if (self.profile_address != profile or
                allZero(&self.profile_identity_sha256))
            {
                return error.InvalidIncrementalNativeProfileHook;
            }
            try self.validate_fn(
                self.context,
                pcs_config,
                statement,
                bridge_geometry,
                manifest,
                authenticated,
            );
        }

        pub fn mixPreTree0(
            self: Self,
            statement: *const statement_v2.RiscVStatementV2,
            channel: *Engine.Channel,
        ) !void {
            try self.mix_pre_tree0_fn(self.context, statement, channel);
        }

        pub fn mixPostTree1(
            self: Self,
            statement: *const statement_v2.RiscVStatementV2,
            channel: *Engine.Channel,
        ) !void {
            try self.mix_post_tree1_fn(self.context, statement, channel);
        }
    };
}

pub const InteractionClaimsV3 = struct {
    base: *statement_mod.RiscVInteractionClaim,
    bridge: QM31,

    pub fn deinit(self: *InteractionClaimsV3, allocator: std.mem.Allocator) void {
        allocator.destroy(self.base);
        self.* = undefined;
    }
};

pub fn ProveOutputV3(comptime Engine: type) type {
    return struct {
        statement: statement_v2.RiscVStatementV2,
        bridge_geometry: incremental_bridge.GeometryV3,
        proof: types.ProofForEngine(Engine),
        claims: InteractionClaimsV3,
        profile_identity_sha256: ProfileIdentity,

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

/// Derives the exact authenticated physical-V2 base statement consumed by the
/// V3 profile before any commitment is made. The caller retains `full_witness`
/// and may pass the returned value to the integration profile mint followed by
/// `proveWithEngineUsingChannel`; this helper never rebuilds or takes ownership
/// of the witness.
pub fn prepareStatement(
    allocator: std.mem.Allocator,
    exec_trace: *const trace_mod.Trace,
    opt_chain: ?*const state_chain.StateChainTracker,
    full_witness: *const incremental_witness.FullWitnessV3,
    public_data: public_data_v2.PublicDataV2,
) !statement_v2.RiscVStatementV2 {
    if (exec_trace.step_count == 0) return error.EmptyTrace;
    const workspace = try proof_workspace.ProofWorkspace.create(allocator);
    defer workspace.destroy(allocator);
    const built = try statement_geometry.buildV2(
        allocator,
        workspace,
        exec_trace,
        &full_witness.base,
        opt_chain,
        public_data,
        .proof,
    );
    return built.statement;
}

/// Proves one already-authenticated incremental segment. `full_witness` is
/// borrowed so the materializer can build it exactly once and retain its typed
/// transition custody through proof publication.
pub fn proveWithEngineUsingChannel(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    exec_trace: *const trace_mod.Trace,
    opt_chain: ?*const state_chain.StateChainTracker,
    full_witness: *const incremental_witness.FullWitnessV3,
    expected_statement: *const statement_v2.RiscVStatementV2,
    profile: *const anyopaque,
    profile_hook: ProfileHookV3(Engine),
    recorder: ?*stage_profile.Recorder,
    channel: *Engine.Channel,
    execution: ExecutionOptions,
) !ProveOutputV3(Engine) {
    comptime types.assertProverEngine(Engine);
    if (exec_trace.step_count == 0) return error.EmptyTrace;

    var execution_pool: orchestration.ProofExecutionPool = .{};
    try execution_pool.initInPlace(allocator, execution.cpu);
    defer execution_pool.deinit();

    const workspace = try proof_workspace.ProofWorkspace.create(allocator);
    defer workspace.destroy(allocator);
    const built = try statement_geometry.buildV2(
        allocator,
        workspace,
        exec_trace,
        &full_witness.base,
        opt_chain,
        expected_statement.public_data,
        .proof,
    );
    if (!std.meta.eql(built.statement, expected_statement.*))
        return error.IncrementalNativeStatementMismatch;
    if (execution.statement_admission) |admission|
        try admission.admit(&built.statement);

    const core = &workspace.statement;
    var manifest = lookup_physical_v2.Manifest.native();
    var authenticated = try lookup_physical_v2.AuthenticatedStatement.init(
        core,
        &manifest,
    );
    const base_interaction_columns = try authenticated.totalInteractionColumns(
        core,
        &manifest,
    );
    const bridge_rows = full_witness.boundary.bridgeRows();
    const bridge_geometry = try incremental_bridge.GeometryV3.canonical(
        core,
        std.math.cast(u32, bridge_rows.len) orelse
            return error.IncrementalBridgeGeometryOverflow,
        std.math.cast(u32, base_interaction_columns) orelse
            return error.IncrementalBridgeGeometryOverflow,
    );
    try profile_hook.validate(
        profile,
        pcs_config,
        &built.statement,
        &bridge_geometry,
        &manifest,
        &authenticated,
    );

    try profile_hook.mixPreTree0(&built.statement, channel);
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
    try external_tree.commitPreprocessed(
        Engine,
        allocator,
        core,
        &tree0_blocks,
        &scheme,
        channel,
        recorder,
    );

    var bridge_tree1 = try incremental_bridge.MainTraceV3.init(
        allocator,
        bridge_rows,
        &bridge_geometry,
    );
    defer bridge_tree1.deinit();
    const tree1_blocks = [_]external_tree.BorrowedBlock{bridge_tree1.block()};
    var retained = try external_tree.commitMain(
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
        &tree1_blocks,
        null,
    );
    defer retained.deinit(allocator, workspace);

    try profile_hook.mixPostTree1(&built.statement, channel);
    const interaction_pow = channel.grind(transcript.INTERACTION_POW_BITS);
    channel.mixU64(interaction_pow);
    const relations = try relation_challenges.Relations.draw(allocator, channel);
    try full_witness.boundary.verifyMerkleAndPoseidonCancellation(&relations);

    var bridge_tree2 = try incremental_bridge.InteractionTraceV3.init(
        allocator,
        bridge_rows,
        full_witness.boundary.roots().entry,
        full_witness.boundary.roots().exit,
        &relations,
        &bridge_geometry,
    );
    defer bridge_tree2.deinit();
    const bridge_claim = bridge_tree2.claim();
    var external_columns = bridge_tree2.ownedColumns();

    const base_claim = try allocator.create(statement_mod.RiscVInteractionClaim);
    var claim_owned = true;
    defer if (claim_owned) allocator.destroy(base_claim);
    const mix_context = ClaimMixContext{
        .core = core,
        .manifest = &manifest,
        .authenticated = &authenticated,
        .bridge_claim = bridge_claim,
    };
    try external_tree.commitInteractionAuthenticatedLookupV2(
        Engine,
        allocator,
        workspace,
        &scheme,
        channel,
        recorder,
        &full_witness.base,
        built.base,
        &retained.lookup_source,
        &relations,
        interaction_pow,
        base_claim,
        &external_columns,
        &manifest,
        &authenticated,
        &mix_context,
        mixClaims,
    );

    const canonical = try authenticated.canonicalInteractionClaim(
        core,
        &manifest,
        base_claim,
    );
    const native_sums = try statement_v2.NativePublicSums.init(
        &built.statement.public_data,
        &relations,
    );
    try logup.verifyGlobalCancellation(
        &.{canonical.view().total().add(bridge_claim)},
        native_sums.total,
    );

    try base_component_assembly
        .assembleIntoAuthenticatedLookupV2WithIncrementalBoundaryV3(
        .prover,
        workspace,
        core,
        base_claim,
        &relations,
        core.nMainColumns(),
        base_interaction_columns,
        &manifest,
        &authenticated,
    );
    const roots = full_witness.boundary.roots();
    const assembly = try incremental_bridge.Assembly(.prover).create(
        allocator,
        workspace.components.active(),
        &bridge_geometry,
        roots.entry,
        roots.exit,
        &relations,
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
        .bridge_geometry = bridge_geometry,
        .proof = proof,
        .claims = .{ .base = base_claim, .bridge = bridge_claim },
        .profile_identity_sha256 = profile_hook.profile_identity_sha256,
    };
}

const ClaimMixContext = struct {
    core: *const statement_mod.RiscVStatement,
    manifest: *const lookup_physical_v2.Manifest,
    authenticated: *const lookup_physical_v2.AuthenticatedStatement,
    bridge_claim: QM31,
};

fn mixClaims(
    context: *const ClaimMixContext,
    channel: anytype,
    base_claim: *const statement_mod.RiscVInteractionClaim,
) !void {
    try context.authenticated.mixInteractionClaim(
        channel,
        context.core,
        context.manifest,
        base_claim,
    );
    incremental_bridge.mixClaim(channel, context.bridge_claim);
}

fn allZero(value: *const ProfileIdentity) bool {
    return std.mem.allEqual(u8, value, 0);
}

comptime {
    if (PRODUCTION_ACTIVE or FORMAT_VERSION != 3)
        @compileError("incremental native orchestration V3 activation drifted");
}
