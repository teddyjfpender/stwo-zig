//! Cold verifier for the joined Ethereum + incremental-memory V4 leaf.
//!
//! Every tree shape, fixed column, transcript frame, relation, component, and
//! global cancellation is reconstructed independently. The result owns the
//! actual expanded PCS/FRI proof capture plus pointer-free VM/Ethereum
//! contexts; no digest can mint this capability.

const add = @import("incremental_ethereum_fixed_geometry.zig").add;
const std = @import("std");
const core_verifier = @import("stwo_core").verifier;
const pcs_verifier = @import("stwo_core").pcs.verifier;
const m31 = @import("stwo_core").fields.m31;
const fixed_program_table = @import("stwo_riscv_rv32").air.program.fixed_table;
const program_commitment = @import("stwo_riscv_rv32").air.program.commitment;
const base_assembly = @import("stwo_riscv_rv32").prover.base_component_assembly;
const QM31 = @import("stwo_core").fields.qm31.QM31;

const logup = @import("stwo_riscv_air_lang").evaluation.logup;
const lookup_physical_v2 =
    @import("stwo_riscv_rv32").air.lang.lookup_physical_manifest;
const statement = @import("stwo_riscv_rv32").air.statement;
const public_data_v2 = @import("stwo_riscv_rv32").air.public_data_v2;
const statement_v2 = @import("stwo_riscv_rv32").air.statement_v2;
const public_data_v1 = @import("stwo_riscv_rv32").air.public_data;
const incremental_public = @import("stwo_riscv_rv32").air.incremental_public_logup_v4;
const ethereum_statement =
    @import("../air/guest_precompile/ethereum_statement.zig");
const transcript = @import("stwo_riscv_rv32").air.transcript.api;
const ethereum_context = @import("../recursion/ethereum_leaf_context.zig");
const incremental_bridge = @import("incremental_bridge_external.zig");
const ethereum_assembly = @import("guest_precompile/ethereum_assembly.zig");
const ethereum_interaction = @import("guest_precompile/ethereum_interaction.zig");
const ethereum_main = @import("guest_precompile/ethereum_main.zig");
const ethereum_preprocessed =
    @import("guest_precompile/ethereum_preprocessed.zig");
const ethereum_transcript = @import("guest_precompile/ethereum_transcript.zig");
const ethereum_types = @import("guest_precompile/ethereum_types.zig");
const external_tree = @import("guest_precompile/external_profile_tree.zig");
const proof_capture_sha256 = @import("stwo_riscv_rv32").prover.proof_capture_sha256;
const proof_workspace = @import("stwo_riscv_rv32").prover.proof_workspace;
const types = @import("stwo_riscv_rv32").prover.types;

pub const PRODUCTION_ACTIVE = false;
pub const FORMAT_VERSION: u16 = 4;
pub const COMMITMENT_TREE_COUNT: usize = 4;

pub fn FreshVerifiedCaptureV4(
    comptime Engine: type,
    comptime Profile: type,
) type {
    return struct {
        format_version: u16 = FORMAT_VERSION,
        proof: core_verifier.ProofCapture(types.HasherForEngine(Engine)),
        public_data: statement_v2.OwnedPublicDataV2,
        role_aware_public: incremental_public.OwnedPublicDataV4,
        statement: statement_v2.RiscVStatementV2,
        extension: ethereum_statement.Statement,
        profile: Profile,
        base_claim: *statement.RiscVInteractionClaim,
        extension_claim: ethereum_types.ExtensionClaim,
        bridge_claim: QM31,
        relations: ethereum_transcript.Relations,
        manifest: lookup_physical_v2.Manifest,
        authenticated: lookup_physical_v2.AuthenticatedStatement,
        receipt: statement_v2.VerifiedReceipt,
        public_sums: incremental_public.VerifiedPublicSumsV4,
        ethereum_air: ethereum_context.ContextV1,
        /// Exact field-native checkpoint retained from the successful native
        /// verifier.  Stage-102 recursion consumes this value directly; the
        /// surrounding SHA seals remain transport diagnostics only.
        transcript_final_digest: [8]u32,
        transcript_final_draw_count: u32,
        proof_capture_sha256: [32]u8,
        transcript_identity_sha256: [32]u8,
        identity_sha256: [32]u8,

        const Self = @This();

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            allocator.destroy(self.base_claim);
            self.role_aware_public.deinit();
            self.public_data.deinit();
            self.proof.deinit(allocator);
            self.* = undefined;
        }

        pub fn validate(self: *const Self) !void {
            if (self.format_version != FORMAT_VERSION)
                return error.InvalidIncrementalEthereumFreshCapture;
            try self.public_data.validate();
            const expected_statement = try statement_v2.RiscVStatementV2.init(
                self.statement.core,
                self.public_data.data,
            );
            if (!std.meta.eql(expected_statement, self.statement))
                return error.InvalidIncrementalEthereumFreshCapture;
            try self.role_aware_public.validateAgainst(&self.public_data.data);
            try self.profile.validateAgainstStatement(
                &self.statement,
                &self.extension,
                &self.role_aware_public.value,
            );
            try self.extension_claim.validate(&self.extension);
            try self.receipt.validateAgainst(&self.public_data.data);
            if (self.public_sums.circuit_profile != self.profile.circuitProfile()) return error.InvalidIncrementalEthereumFreshCapture;
            try self.public_sums.validateAgainst(
                &self.public_data.data,
                &self.role_aware_public.value,
                &self.relations.base,
            );
            try self.authenticated.validateAgainst(
                &self.statement.core,
                &self.manifest,
            );
            try self.profile.bridge_geometry.validateAfterPrefix(
                try prefixColumns(
                    &self.statement,
                    &self.extension,
                    &self.authenticated,
                    &self.manifest,
                    self.profile.circuitProfile(),
                ),
            );
            try self.ethereum_air
                .validateAgainstAuthenticatedLookupV2AuthorityWithCircuitProfileV1(
                &self.statement,
                &self.extension,
                &self.extension_claim,
                &self.relations,
                &self.manifest,
                &self.authenticated,
                self.profile.circuitProfile(),
            );
            const canonical = try self.authenticated.canonicalInteractionClaim(
                &self.statement.core,
                &self.manifest,
                self.base_claim,
            );
            try logup.verifyGlobalCancellation(
                &.{
                    canonical.view().total(),
                    self.extension_claim.componentSum(),
                    self.bridge_claim,
                },
                self.public_sums.total,
            );
            try validateTranscriptCheckpoint(
                self.transcript_final_digest,
                self.transcript_final_draw_count,
            );
            const expected_proof_sha = proof_capture_sha256.compute(&self.proof);
            const expected_transcript = transcriptIdentity(
                &self.statement,
                &self.profile,
                self.base_claim,
                &self.extension_claim,
                self.bridge_claim,
                &self.relations,
                &self.ethereum_air,
            );
            const expected_identity = captureIdentity(Engine, Profile, self);
            if (!std.mem.eql(
                u8,
                &expected_proof_sha,
                &self.proof_capture_sha256,
            ) or !std.mem.eql(
                u8,
                &expected_transcript,
                &self.transcript_identity_sha256,
            ) or !std.mem.eql(
                u8,
                &expected_identity,
                &self.identity_sha256,
            )) return error.InvalidIncrementalEthereumFreshCapture;
        }
    };
}

/// Consumes `proof_in` on every path and publishes `capture_out` only after
/// the complete joined AIR/PCS/FRI transaction succeeds.
pub fn verifyWithEngineUsingChannelAndCapture(
    comptime Engine: type,
    comptime Profile: type,
    allocator: std.mem.Allocator,
    statement_value: *const statement_v2.RiscVStatementV2,
    extension: *const ethereum_statement.Statement,
    role_aware_public: *const public_data_v1.PublicData,
    profile: *const Profile,
    proof_in: types.ProofForEngine(Engine),
    base_claim: *const statement.RiscVInteractionClaim,
    extension_claim: *const ethereum_types.ExtensionClaim,
    bridge_claim: QM31,
    channel: *Engine.Channel,
    capture_out: *FreshVerifiedCaptureV4(Engine, Profile),
) !void {
    return verifyWithEngineUsingChannelAndCaptureInternal(
        Engine,
        Profile,
        allocator,
        statement_value,
        extension,
        role_aware_public,
        profile,
        proof_in,
        base_claim,
        extension_claim,
        bridge_claim,
        null,
        null,
        channel,
        capture_out,
    );
}

/// Cold-verifier sibling that consumes the statement's process-local lease
/// only after PCS/FRI verification succeeds. The optional stays populated on
/// every earlier error and becomes null exactly when capture ownership moves.
pub fn verifyWithEngineUsingChannelAndCaptureTakingLease(
    comptime Engine: type,
    comptime Profile: type,
    allocator: std.mem.Allocator,
    statement_value: *const statement_v2.RiscVStatementV2,
    extension: *const ethereum_statement.Statement,
    role_aware_public: *const public_data_v1.PublicData,
    profile: *const Profile,
    proof_in: types.ProofForEngine(Engine),
    base_claim: *const statement.RiscVInteractionClaim,
    extension_claim: *const ethereum_types.ExtensionClaim,
    bridge_claim: QM31,
    validated_lease_inout: *?public_data_v2.PublicDataV2
        .OwnedValidatedLeaseV2,
    channel: *Engine.Channel,
    capture_out: *FreshVerifiedCaptureV4(Engine, Profile),
) !void {
    return verifyWithEngineUsingChannelAndCaptureInternal(
        Engine,
        Profile,
        allocator,
        statement_value,
        extension,
        role_aware_public,
        profile,
        proof_in,
        base_claim,
        extension_claim,
        bridge_claim,
        validated_lease_inout,
        null,
        channel,
        capture_out,
    );
}

/// Independent ELF-derived owner is required by the explicit fixed circuit.
pub fn verifyWithEngineUsingChannelAndCaptureWithProgramAdmissionTakingLease(
    comptime Engine: type,
    comptime Profile: type,
    allocator: std.mem.Allocator,
    statement_value: *const statement_v2.RiscVStatementV2,
    extension: *const ethereum_statement.Statement,
    role_aware_public: *const public_data_v1.PublicData,
    profile: *const Profile,
    proof_in: types.ProofForEngine(Engine),
    base_claim: *const statement.RiscVInteractionClaim,
    extension_claim: *const ethereum_types.ExtensionClaim,
    bridge_claim: QM31,
    validated_lease_inout: *?public_data_v2.PublicDataV2
        .OwnedValidatedLeaseV2,
    program: anytype,
    channel: *Engine.Channel,
    capture_out: *FreshVerifiedCaptureV4(Engine, Profile),
) !void {
    var transferred = false;
    errdefer if (!transferred) {
        var owned = proof_in;
        owned.deinit(allocator);
    };
    const descriptor = profile.fixed_program orelse return error.EthereumFixedProgramAdmissionRequired;
    try program.validateDescriptor(descriptor);
    const rows = try program.rows();
    transferred = true;
    return verifyWithEngineUsingChannelAndCaptureInternal(
        Engine,
        Profile,
        allocator,
        statement_value,
        extension,
        role_aware_public,
        profile,
        proof_in,
        base_claim,
        extension_claim,
        bridge_claim,
        validated_lease_inout,
        rows,
        channel,
        capture_out,
    );
}

fn verifyWithEngineUsingChannelAndCaptureInternal(
    comptime Engine: type,
    comptime Profile: type,
    allocator: std.mem.Allocator,
    statement_value: *const statement_v2.RiscVStatementV2,
    extension: *const ethereum_statement.Statement,
    role_aware_public: *const public_data_v1.PublicData,
    profile: *const Profile,
    proof_in: types.ProofForEngine(Engine),
    base_claim: *const statement.RiscVInteractionClaim,
    extension_claim: *const ethereum_types.ExtensionClaim,
    bridge_claim: QM31,
    validated_lease_inout: ?*?public_data_v2.PublicDataV2
        .OwnedValidatedLeaseV2,
    fixed_rows: ?[]const program_commitment.Row,
    channel: *Engine.Channel,
    capture_out: *FreshVerifiedCaptureV4(Engine, Profile),
) !void {
    var proof = proof_in;
    var proof_moved = false;
    defer if (!proof_moved) proof.deinit(allocator);
    if ((profile.circuitProfile() == .fixed_program_narrow_v1) != (fixed_rows != null)) return error.EthereumFixedProgramAdmissionRequired;
    if (proof.commitment_scheme_proof.commitments.items.len !=
        COMMITMENT_TREE_COUNT)
    {
        return error.InvalidIncrementalEthereumProofShape;
    }
    try statement_value.validate();
    try extension.validateV2WithCircuitProfileV1(statement_value, profile.circuitProfile());
    try extension_claim.validate(extension);
    try incremental_public.validateSharedAuthority(
        &statement_value.public_data,
        role_aware_public,
    );
    try profile.validateAgainstStatement(
        statement_value,
        extension,
        role_aware_public,
    );
    const pcs_config = try profile.pcsConfig();
    if (!std.meta.eql(
        pcs_config,
        proof.commitment_scheme_proof.config,
    )) return error.InvalidIncrementalEthereumProofShape;

    var manifest = lookup_physical_v2.Manifest.native();
    const authenticated = try lookup_physical_v2.AuthenticatedStatement.init(
        &statement_value.core,
        &manifest,
    );
    const prefix = try prefixColumns(
        statement_value,
        extension,
        &authenticated,
        &manifest,
        profile.circuitProfile(),
    );
    try profile.bridge_geometry.validateAfterPrefix(prefix);

    var bridge_tree0 = try incremental_bridge.PreprocessedTraceV3.init(
        allocator,
        &profile.bridge_geometry,
    );
    defer bridge_tree0.deinit();
    var fixed_columns: ?fixed_program_table.ColumnsV1 = if (fixed_rows) |rows| try fixed_program_table.ColumnsV1.init(allocator, rows, statement_value.core.infra_descs[0].log_size) else null;
    defer if (fixed_columns) |*columns| columns.deinit(allocator);
    var tree0_blocks: [2]external_tree.BorrowedBlock = undefined;
    var tree0_block_count: usize = 0;
    var fixed_views: [fixed_program_table.COLUMN_COUNT][]const m31.M31 = undefined;
    if (fixed_columns) |columns| {
        for (columns.values, &fixed_views) |column, *view| view.* = column;
        tree0_blocks[tree0_block_count] = .{ .log_size = columns.log_size, .columns = &fixed_views };
        tree0_block_count += 1;
    }
    tree0_blocks[tree0_block_count] = bridge_tree0.block();
    tree0_block_count += 1;
    const expected_tree0 = try deriveExpectedPreprocessedRootInternal(Engine, allocator, &statement_value.core, extension, &profile.bridge_geometry, pcs_config, fixed_rows);
    if (!std.meta.eql(expected_tree0, proof.commitment_scheme_proof.commitments.items[0]))
        return error.InvalidIncrementalEthereumPreprocessedRoot;

    const empty_main =
        [_][]const @import("stwo_core").fields.m31.M31{&.{}} **
        incremental_bridge.MAIN_COLUMNS;
    const main_shape = external_tree.BorrowedBlock{
        .log_size = profile.bridge_geometry.log_size,
        .columns = &empty_main,
    };
    const empty_interaction =
        [_][]const @import("stwo_core").fields.m31.M31{&.{}} **
        incremental_bridge.INTERACTION_COLUMNS;
    const interaction_shape = external_tree.BorrowedBlock{
        .log_size = profile.bridge_geometry.log_size,
        .columns = &empty_interaction,
    };
    const tree0_logs = try ethereum_preprocessed.logSizesWithExternalBlocks(
        allocator,
        &statement_value.core,
        extension,
        tree0_blocks[0..tree0_block_count],
    );
    defer allocator.free(tree0_logs);
    const tree1_logs = try ethereum_main.logSizesWithExternalBlocks(
        allocator,
        &statement_value.core,
        extension,
        &.{main_shape},
    );
    defer allocator.free(tree1_logs);
    const tree2_prefix = try ethereum_interaction.logSizesAuthenticatedLookupV2(
        allocator,
        &statement_value.core,
        extension,
        &manifest,
        &authenticated,
    );
    defer allocator.free(tree2_prefix);
    const tree2_logs = try external_tree.appendLogSizes(
        allocator,
        tree2_prefix,
        &.{interaction_shape},
    );
    defer allocator.free(tree2_logs);

    try profile.mixPreTree0(statement_value, role_aware_public, channel);
    var scheme = try pcs_verifier.CommitmentSchemeVerifier(
        types.HasherForEngine(Engine),
        Engine.MerkleChannel,
    ).init(allocator, pcs_config);
    defer scheme.deinit(allocator);
    try scheme.commit(
        allocator,
        proof.commitment_scheme_proof.commitments.items[0],
        tree0_logs,
        channel,
    );
    try scheme.commit(
        allocator,
        proof.commitment_scheme_proof.commitments.items[1],
        tree1_logs,
        channel,
    );

    try profile.mixPostTree1(statement_value, role_aware_public, channel);
    if (!channel.verifyPowNonce(
        transcript.INTERACTION_POW_BITS,
        base_claim.interaction_pow,
    )) return error.InvalidIncrementalEthereumInteractionProofOfWork;
    channel.mixU64(base_claim.interaction_pow);
    const relations = try ethereum_transcript.Relations.draw(
        allocator,
        channel,
    );
    try ethereum_transcript.mixInteractionClaimV2(
        channel,
        &statement_value.core,
        &manifest,
        &authenticated,
        base_claim,
        extension_claim,
    );
    try profile.mixFinalClaims(allocator, channel, &statement_value.core, &manifest, &authenticated, base_claim, bridge_claim);
    try scheme.commit(
        allocator,
        proof.commitment_scheme_proof.commitments.items[2],
        tree2_logs,
        channel,
    );

    const canonical = try authenticated.canonicalInteractionClaim(
        &statement_value.core,
        &manifest,
        base_claim,
    );
    const public_sums = try incremental_public.VerifiedPublicSumsV4.initWithCircuitProfile(
        &statement_value.public_data,
        role_aware_public,
        &relations.base,
        profile.circuitProfile(),
    );
    try logup.verifyGlobalCancellation(
        &.{
            canonical.view().total(),
            extension_claim.componentSum(),
            bridge_claim,
        },
        public_sums.total,
    );

    const workspace = try proof_workspace.VerificationWorkspace.create(allocator);
    defer workspace.destroy(allocator);
    workspace.canonical = canonical;
    try base_assembly.assembleIntoAuthenticatedLookupV2WithCircuitLayout(.verifier, workspace, &statement_value.core, base_claim, &relations.base, statement_value.core.nMainColumns(), try authenticated.totalInteractionColumns(&statement_value.core, &manifest), &manifest, &authenticated, profile.circuitProfile().layout());
    if (fixed_rows != null) {
        var indices: [fixed_program_table.COLUMN_COUNT]usize = undefined;
        for (&indices, 0..) |*index, offset| index.* = profile.bridge_geometry.placement.is_first_col_idx - fixed_program_table.COLUMN_COUNT + offset;
        workspace.components.infra[0].fixed_program_columns = indices;
    }
    const base_components = workspace.components.active();
    const ethereum_components = try ethereum_assembly.Assembly(.verifier)
        .createAuthenticatedLookupV2WithCircuitProfileV1(
        allocator,
        statement_value,
        extension,
        &relations,
        base_components,
        extension_claim,
        &manifest,
        &authenticated,
        profile.circuitProfile(),
    );
    defer ethereum_components.destroy(allocator);
    const roots = try incrementalRoots(statement_value);
    const assembly = try incremental_bridge.Assembly(.verifier).create(
        allocator,
        ethereum_components.active(),
        &profile.bridge_geometry,
        roots.entry,
        roots.exit,
        &relations.base,
        bridge_claim,
    );
    defer assembly.destroy(allocator);

    var proof_capture: core_verifier.ProofCapture(
        types.HasherForEngine(Engine),
    ) = undefined;
    var proof_capture_owned = false;
    defer if (proof_capture_owned) proof_capture.deinit(allocator);
    proof_moved = true;
    try core_verifier.verifyWithProofCapture(
        types.HasherForEngine(Engine),
        Engine.MerkleChannel,
        allocator,
        assembly.active(),
        channel,
        &scheme,
        proof,
        &proof_capture,
    );
    proof_capture_owned = true;
    try validateCaptureLogs(
        &proof_capture,
        tree0_logs,
        tree1_logs,
        tree2_logs,
        pcs_config.fri_config.log_blowup_factor,
    );
    try printCompositionDiagnostics(allocator, &statement_value.core, extension, assembly.active(), &proof_capture);
    const transcript_final_digest = channel.digestWords();
    const transcript_final_draw_count = channel.n_draws;
    try validateTranscriptCheckpoint(
        transcript_final_digest,
        transcript_final_draw_count,
    );

    var owned_public = if (validated_lease_inout) |lease|
        try statement_v2.OwnedPublicDataV2.initVerifiedTakingLease(
            allocator,
            &statement_value.public_data,
            lease,
        )
    else
        try statement_v2.OwnedPublicDataV2.initVerified(
            allocator,
            &statement_value.public_data,
        );
    var public_owned = true;
    defer if (public_owned) owned_public.deinit();
    const owned_statement = try statement_v2.RiscVStatementV2.init(
        statement_value.core,
        owned_public.data,
    );
    const receipt = try owned_statement.verifiedReceipt();
    var owned_role_aware = try incremental_public.OwnedPublicDataV4.initVerified(
        allocator,
        &owned_public.data,
        role_aware_public,
    );
    var role_aware_owned = true;
    defer if (role_aware_owned) owned_role_aware.deinit();
    const owned_sums = try incremental_public.VerifiedPublicSumsV4.initWithCircuitProfile(
        &owned_public.data,
        &owned_role_aware.value,
        &relations.base,
        profile.circuitProfile(),
    );
    const ethereum_air = try ethereum_context.ContextV1
        .initVerifiedAuthenticatedLookupV2WithCircuitProfileV1(
        &owned_statement,
        extension,
        extension_claim,
        &relations,
        ethereum_components,
        base_components.len,
        &manifest,
        &authenticated,
        profile.circuitProfile(),
    );
    const owned_claim = try allocator.create(statement.RiscVInteractionClaim);
    var claim_owned = true;
    defer if (claim_owned) allocator.destroy(owned_claim);
    owned_claim.* = base_claim.*;

    var result = FreshVerifiedCaptureV4(Engine, Profile){
        .proof = proof_capture,
        .public_data = owned_public,
        .role_aware_public = owned_role_aware,
        .statement = owned_statement,
        .extension = extension.*,
        .profile = profile.*,
        .base_claim = owned_claim,
        .extension_claim = extension_claim.*,
        .bridge_claim = bridge_claim,
        .relations = relations,
        .manifest = manifest,
        .authenticated = authenticated,
        .receipt = receipt,
        .public_sums = owned_sums,
        .ethereum_air = ethereum_air,
        .transcript_final_digest = transcript_final_digest,
        .transcript_final_draw_count = transcript_final_draw_count,
        .proof_capture_sha256 = proof_capture_sha256.compute(&proof_capture),
        .transcript_identity_sha256 = undefined,
        .identity_sha256 = undefined,
    };
    result.transcript_identity_sha256 = transcriptIdentity(
        &result.statement,
        &result.profile,
        result.base_claim,
        &result.extension_claim,
        result.bridge_claim,
        &result.relations,
        &result.ethereum_air,
    );
    result.identity_sha256 = captureIdentity(Engine, Profile, &result);
    try result.validate();
    capture_out.* = result;
    proof_capture_owned = false;
    public_owned = false;
    role_aware_owned = false;
    claim_owned = false;
}

const prefixColumns = @import("incremental_ethereum_fixed_geometry.zig").prefixColumns;

/// Derive the joined leaf's fixed Tree0 independently of all proof roots.
/// These inputs are admitted circuit geometry: selectors, canonical tables,
/// extension active counts, bridge placement and PCS parameters. No execution
/// values or candidate commitment are accepted by this constructor.
/// The caller still authenticates the complete native statement/profile at
/// its input boundary; this helper checks the fixed geometry it consumes.
pub const deriveExpectedPreprocessedRoot = @import("incremental_ethereum_fixed_geometry.zig").deriveExpectedPreprocessedRoot;

pub const deriveExpectedPreprocessedRootWithFixedProgramV1 = @import("incremental_ethereum_fixed_geometry.zig").deriveExpectedPreprocessedRootWithFixedProgramV1;

const deriveExpectedPreprocessedRootInternal = @import("incremental_ethereum_fixed_geometry.zig").deriveExpectedPreprocessedRootInternal;

/// Opt-in replay attribution after successful native verification. Borrow the
/// authenticated sample values and use the actual assembled components, so the
/// diagnostic cannot substitute another AIR or change the transcript.
fn printCompositionDiagnostics(
    allocator: std.mem.Allocator,
    base: *const statement.RiscVStatement,
    extension: *const ethereum_statement.Statement,
    component_list: []const @import("stwo_core").air.components.Component,
    capture: anytype,
) !void {
    const selected = std.process.getEnvVarOwned(allocator, "STWO_ETHEREUM_COMPOSITION_DIAGNOSTICS") catch |err| {
        if (err == error.EnvironmentVariableNotFound) return;
        return err;
    };
    defer allocator.free(selected);
    if (!std.mem.eql(u8, selected, "1")) return;
    const core = @import("stwo_core");
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const scratch = arena.allocator();
    const trees = try scratch.alloc([][]QM31, capture.sampled_points.len);
    var cursor: usize = 0;
    for (capture.sampled_points, trees) |point_columns, *columns| {
        columns.* = try scratch.alloc([]QM31, point_columns.len);
        for (point_columns, columns.*) |points, *values| {
            if (points.len > capture.sampled_values.len - cursor) return error.InvalidCompositionDiagnosticShape;
            values.* = capture.sampled_values[cursor..][0..points.len];
            cursor += points.len;
        }
    }
    if (cursor != capture.sampled_values.len) return error.InvalidCompositionDiagnosticShape;
    const mask = core.air.components.MaskValues.initOwned(trees);
    const components = core.air.components.Components{
        .components = component_list,
        .n_preprocessed_columns = capture.column_log_sizes[0].len,
    };
    const mask_log_size = core.verifier_types.compositionMaskLogSize(components.compositionLogDegreeBound(), try components.compositionLogSplit()) orelse return error.InvalidCompositionDiagnosticShape;
    const point = core.circle.secureFieldPointFromRandomSeed(capture.oods_seed);
    var accumulator = core.air.accumulation.PointEvaluationAccumulator.init(capture.composition_randomness);
    const opcode_count: usize = @as(usize, base.n_components) * 2;
    const base_count = opcode_count + base.n_infra;
    if (component_list.len != base_count + extension.components.len + 1) return error.InvalidCompositionDiagnosticShape;
    std.debug.print("NATIVE_COMPOSITION_CONTEXT mask_log_size={d} randomness={any} oods_seed={any}\n", .{ mask_log_size, capture.composition_randomness, capture.oods_seed });
    var constraints: usize = 0;
    for (component_list, 0..) |component, ordinal| {
        try component.evaluateConstraintQuotientsAtPoint(point, &mask, &accumulator, mask_log_size);
        constraints += component.nConstraints();
        const name = if (ordinal < opcode_count)
            @tagName(base.component_descs[ordinal / 2].family)
        else if (ordinal < base_count)
            @tagName(base.infra_descs[ordinal - opcode_count].kind)
        else if (ordinal < base_count + extension.components.len)
            @tagName(extension.components[ordinal - base_count].kind)
        else
            "incremental_bridge";
        const section = if (ordinal < base_count) "base" else if (ordinal < base_count + extension.components.len) "ethereum" else "bridge";
        const section_index = if (ordinal < base_count) ordinal else if (ordinal < base_count + extension.components.len) ordinal - base_count else 0;
        const adapter = if (ordinal < opcode_count) (if (ordinal % 2 == 0) "semantic" else "lookup") else "component";
        std.debug.print("NATIVE_COMPOSITION_CHECKPOINT ordinal={d} section={s} index={d} name={s} adapter={s} constraints={d} component_constraints={d} value={any}\n", .{ ordinal, section, section_index, name, adapter, constraints, component.nConstraints(), accumulator.finalize() });
    }
}

fn validateCaptureLogs(
    capture: anytype,
    tree0: []const u32,
    tree1: []const u32,
    tree2: []const u32,
    fri_log_blowup_factor: u32,
) !void {
    if (capture.commitments.len != COMMITMENT_TREE_COUNT or
        capture.column_log_sizes.len != COMMITMENT_TREE_COUNT or
        !matchesExtendedLogs(
            capture.column_log_sizes[0],
            tree0,
            fri_log_blowup_factor,
        ) or
        !matchesExtendedLogs(
            capture.column_log_sizes[1],
            tree1,
            fri_log_blowup_factor,
        ) or
        !matchesExtendedLogs(
            capture.column_log_sizes[2],
            tree2,
            fri_log_blowup_factor,
        ) or
        capture.column_log_sizes[3].len == 0)
    {
        return error.InvalidIncrementalEthereumProofShape;
    }
}

fn matchesExtendedLogs(
    captured: []const u32,
    base: []const u32,
    fri_log_blowup_factor: u32,
) bool {
    if (captured.len != base.len) return false;
    for (captured, base) |actual, log_size| {
        const expected = std.math.add(
            u32,
            log_size,
            fri_log_blowup_factor,
        ) catch return false;
        if (actual != expected) return false;
    }
    return true;
}

test "incremental Ethereum capture pins FRI-extended tree logs" {
    const base0 = [_]u32{ 3, 5 };
    const base1 = [_]u32{4};
    const base2 = [_]u32{ 5, 4, 3 };
    const captured0 = [_]u32{ 4, 6 };
    const captured1 = [_]u32{5};
    const captured2 = [_]u32{ 6, 5, 4 };
    const composition = [_]u32{6};
    const commitments = [_]u8{0} ** COMMITMENT_TREE_COUNT;
    var captured_logs = [_][]const u32{
        &captured0,
        &captured1,
        &captured2,
        &composition,
    };
    const Capture = struct {
        commitments: []const u8,
        column_log_sizes: []const []const u32,
    };
    var capture = Capture{
        .commitments = &commitments,
        .column_log_sizes = &captured_logs,
    };
    try validateCaptureLogs(&capture, &base0, &base1, &base2, 1);

    captured_logs[1] = &base1;
    try std.testing.expectError(
        error.InvalidIncrementalEthereumProofShape,
        validateCaptureLogs(&capture, &base0, &base1, &base2, 1),
    );
    captured_logs[1] = &captured1;
    captured_logs[2] = captured2[0 .. captured2.len - 1];
    try std.testing.expectError(
        error.InvalidIncrementalEthereumProofShape,
        validateCaptureLogs(&capture, &base0, &base1, &base2, 1),
    );
}

const incrementalRoots = @import("incremental_ethereum_capture_authority.zig").incrementalRoots;

const transcriptIdentity = @import("incremental_ethereum_capture_authority.zig").transcriptIdentity;

const captureIdentity = @import("incremental_ethereum_capture_authority.zig").captureIdentity;

const validateTranscriptCheckpoint = @import("incremental_ethereum_capture_authority.zig").validateTranscriptCheckpoint;

comptime {
    if (PRODUCTION_ACTIVE or FORMAT_VERSION != 4 or
        COMMITMENT_TREE_COUNT != 4)
    {
        @compileError("incremental Ethereum verifier V4 activated");
    }
}
