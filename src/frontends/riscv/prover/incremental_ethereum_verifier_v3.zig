//! Cold verifier for the joined Ethereum + incremental-memory V4 leaf.
//!
//! Every tree shape, fixed column, transcript frame, relation, component, and
//! global cancellation is reconstructed independently. The result owns the
//! actual expanded PCS/FRI proof capture plus pointer-free VM/Ethereum
//! contexts; no digest can mint this capability.

const std = @import("std");
const core_verifier = @import("stwo_core").verifier;
const pcs_core = @import("stwo_core").pcs;
const pcs_verifier = @import("stwo_core").pcs.verifier;
const prover_pcs = @import("stwo_prover_engine").pcs;
const m31 = @import("stwo_core").fields.m31;
const QM31 = @import("stwo_core").fields.qm31.QM31;

const logup = @import("../air/logup.zig");
const lookup_physical_v2 =
    @import("../air/lang/lookup_physical_manifest_v2.zig");
const statement = @import("../air/statement.zig");
const public_data_v2 = @import("../air/public_data_v2.zig");
const statement_v2 = @import("../air/statement_v2.zig");
const public_data_v1 = @import("../air/public_data.zig");
const incremental_public = @import("../air/incremental_public_logup_v4.zig");
const ethereum_statement =
    @import("../air/guest_precompile/ethereum_statement.zig");
const transcript = @import("../air/transcript/mod.zig");
const ethereum_context = @import("../recursion/ethereum_leaf_context_v1.zig");
const incremental_bridge = @import("incremental_bridge_external_v3.zig");
const ethereum_assembly = @import("guest_precompile/ethereum_assembly.zig");
const ethereum_interaction = @import("guest_precompile/ethereum_interaction.zig");
const ethereum_main = @import("guest_precompile/ethereum_main.zig");
const ethereum_preprocessed =
    @import("guest_precompile/ethereum_preprocessed.zig");
const ethereum_transcript = @import("guest_precompile/ethereum_transcript.zig");
const ethereum_types = @import("guest_precompile/ethereum_types.zig");
const external_tree = @import("guest_precompile/external_profile_tree.zig");
const base_verifier = @import("verifier.zig");
const proof_capture_sha256 = @import("proof_capture_sha256.zig");
const proof_workspace = @import("proof_workspace.zig");
const types = @import("types.zig");

pub const PRODUCTION_ACTIVE = false;
pub const FORMAT_VERSION: u16 = 4;
pub const COMMITMENT_TREE_COUNT: usize = 4;
const TRANSCRIPT_DOMAIN =
    "stwo.riscv.incremental-ethereum-transcript.v4\x00";
const CAPTURE_DOMAIN =
    "stwo.riscv.incremental-ethereum-fresh-capture.v4\x00";

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
                ),
            );
            try self.ethereum_air
                .validateAgainstAuthenticatedLookupV2Authority(
                &self.statement,
                &self.extension,
                &self.extension_claim,
                &self.relations,
                &self.manifest,
                &self.authenticated,
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
    channel: *Engine.Channel,
    capture_out: *FreshVerifiedCaptureV4(Engine, Profile),
) !void {
    var proof = proof_in;
    var proof_moved = false;
    defer if (!proof_moved) proof.deinit(allocator);
    if (proof.commitment_scheme_proof.commitments.items.len !=
        COMMITMENT_TREE_COUNT)
    {
        return error.InvalidIncrementalEthereumProofShape;
    }
    try statement_value.validate();
    try extension.validateV2(statement_value);
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
    );
    try profile.bridge_geometry.validateAfterPrefix(prefix);

    var bridge_tree0 = try incremental_bridge.PreprocessedTraceV3.init(
        allocator,
        &profile.bridge_geometry,
    );
    defer bridge_tree0.deinit();
    const tree0_blocks = [_]external_tree.BorrowedBlock{bridge_tree0.block()};
    const tree0_columns = try ethereum_preprocessed.generateWithExternalBlocks(
        allocator,
        &statement_value.core,
        extension,
        &tree0_blocks,
    );
    try verifyPreprocessedRoot(
        Engine,
        allocator,
        pcs_config,
        tree0_columns,
        proof.commitment_scheme_proof.commitments.items[0],
    );

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
        &tree0_blocks,
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
    incremental_bridge.mixClaim(channel, bridge_claim);
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
    const public_sums = try incremental_public.VerifiedPublicSumsV4.init(
        &statement_value.public_data,
        role_aware_public,
        &relations.base,
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
    const base_components = try base_verifier
        .assembleComponentsAuthenticatedLookupV2WithIncrementalBoundaryV3(
        workspace,
        &statement_value.core,
        base_claim,
        &relations.base,
        statement_value.core.nMainColumns(),
        try authenticated.totalInteractionColumns(
            &statement_value.core,
            &manifest,
        ),
        &manifest,
        &authenticated,
    );
    const ethereum_components = try ethereum_assembly.Assembly(.verifier)
        .createAuthenticatedLookupV2(
        allocator,
        statement_value,
        extension,
        &relations,
        base_components,
        extension_claim,
        &manifest,
        &authenticated,
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
    const owned_sums = try incremental_public.VerifiedPublicSumsV4.init(
        &owned_public.data,
        &owned_role_aware.value,
        &relations.base,
    );
    const ethereum_air = try ethereum_context.ContextV1
        .initVerifiedAuthenticatedLookupV2(
        &owned_statement,
        extension,
        extension_claim,
        &relations,
        ethereum_components,
        base_components.len,
        &manifest,
        &authenticated,
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

fn prefixColumns(
    native: *const statement_v2.RiscVStatementV2,
    extension: *const ethereum_statement.Statement,
    authenticated: *const lookup_physical_v2.AuthenticatedStatement,
    manifest: *const lookup_physical_v2.Manifest,
) !incremental_bridge.PrefixColumnsV3 {
    var result = incremental_bridge.PrefixColumnsV3{
        .preprocessed = native.core.nPreprocessedColumns(),
        .main = native.core.nMainColumns(),
        .interaction = @intCast(
            try authenticated.totalInteractionColumns(&native.core, manifest),
        ),
    };
    for (extension.components) |descriptor| {
        result.preprocessed = try add(
            result.preprocessed,
            descriptor.preprocessed_columns,
        );
        result.main = try add(result.main, descriptor.main_columns);
        result.interaction = try add(
            result.interaction,
            descriptor.interaction_columns,
        );
    }
    try result.validate();
    return result;
}

fn verifyPreprocessedRoot(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    columns: []prover_pcs.ColumnEvaluation,
    expected: Engine.Hasher.Hash,
) !void {
    var moved = false;
    errdefer if (!moved) freeColumns(allocator, columns);
    var scheme = try Engine.init(allocator, pcs_config);
    defer Engine.deinit(&scheme, allocator);
    scheme.setCoefficientRetentionPolicy(.never);
    var channel = Engine.Channel{};
    moved = true;
    try Engine.commit(&scheme, allocator, columns, null, &channel);
    var roots = try scheme.roots(allocator);
    defer roots.deinit(allocator);
    if (roots.items.len != 1 or !std.meta.eql(roots.items[0], expected))
        return error.InvalidIncrementalEthereumPreprocessedRoot;
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

fn incrementalRoots(
    native: *const statement_v2.RiscVStatementV2,
) !struct { entry: u32, exit: u32 } {
    return .{
        .entry = native.core.public_data.initial_rw_root orelse
            return error.InvalidIncrementalEthereumStatement,
        .exit = native.core.public_data.final_rw_root orelse
            return error.InvalidIncrementalEthereumStatement,
    };
}

fn transcriptIdentity(
    native: *const statement_v2.RiscVStatementV2,
    profile: anytype,
    base_claim: *const statement.RiscVInteractionClaim,
    extension_claim: *const ethereum_types.ExtensionClaim,
    bridge_claim: QM31,
    relations: *const ethereum_transcript.Relations,
    ethereum_air: *const ethereum_context.ContextV1,
) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(TRANSCRIPT_DOMAIN);
    hashU32Digest(&hash, native.authority_id);
    hashU32Digest(&hash, native.public_data.wireId());
    hash.update(&profile.identity_sha256);
    hash.update(&profile.bridge_geometry.identity_sha256);
    hash.update(&ethereum_air.statement_sha256);
    hash.update(&ethereum_air.claim_sha256);
    hashInt(&hash, u64, base_claim.interaction_pow);
    hashQm31(&hash, extension_claim.componentSum());
    hashQm31(&hash, bridge_claim);
    var base_draws: [@import("../air/relation_challenges.zig").DRAW_COUNT]QM31 =
        undefined;
    relations.base.writeDraws(&base_draws) catch unreachable;
    for (base_draws) |draw| hashQm31(&hash, draw);
    return hash.finalResult();
}

fn captureIdentity(
    comptime Engine: type,
    comptime Profile: type,
    capture: *const FreshVerifiedCaptureV4(Engine, Profile),
) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(CAPTURE_DOMAIN);
    hashInt(&hash, u16, capture.format_version);
    hash.update(&capture.proof_capture_sha256);
    hash.update(&capture.transcript_identity_sha256);
    hash.update(&capture.profile.identity_sha256);
    hash.update(&capture.role_aware_public.public_boundary_identity_sha256);
    hash.update(&capture.public_sums.identity_sha256);
    hash.update(&capture.ethereum_air.identity_digest);
    hashU32Digest(&hash, capture.receipt.identity);
    hashU32Digest(&hash, capture.transcript_final_digest);
    hashInt(&hash, u32, capture.transcript_final_draw_count);
    return hash.finalResult();
}

fn validateTranscriptCheckpoint(
    digest: [8]u32,
    draw_count: u32,
) !void {
    if (draw_count >= m31.Modulus)
        return error.InvalidIncrementalEthereumFreshCapture;
    var aggregate: u32 = 0;
    for (digest) |word| {
        if (word >= m31.Modulus)
            return error.InvalidIncrementalEthereumFreshCapture;
        aggregate |= word;
    }
    if (aggregate == 0)
        return error.InvalidIncrementalEthereumFreshCapture;
}

fn add(left: u32, right: u32) !u32 {
    return std.math.add(u32, left, right) catch
        error.IncrementalEthereumLeafGeometryOverflow;
}

fn freeColumns(
    allocator: std.mem.Allocator,
    columns: []prover_pcs.ColumnEvaluation,
) void {
    for (columns) |column| allocator.free(@constCast(column.values));
    allocator.free(columns);
}

fn hashQm31(hash: *std.crypto.hash.sha2.Sha256, value: QM31) void {
    for (value.toM31Array()) |limb| hashInt(hash, u32, limb.toU32());
}

fn hashU32Digest(hash: *std.crypto.hash.sha2.Sha256, value: [8]u32) void {
    for (value) |word| hashInt(hash, u32, word);
}

fn hashInt(
    hash: *std.crypto.hash.sha2.Sha256,
    comptime T: type,
    value: anytype,
) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

comptime {
    if (PRODUCTION_ACTIVE or FORMAT_VERSION != 4 or
        COMMITMENT_TREE_COUNT != 4)
    {
        @compileError("incremental Ethereum verifier V4 activated");
    }
}
