//! Cold verifier and fresh-capture boundary for incremental native V3 proofs.
//!
//! Proof bytes, claims, and profile values are all untrusted inputs. The
//! verifier reconstructs every tree shape, selector column, relation draw,
//! component handle, and public cancellation before publishing the owned PCS
//! capture. A SHA-256 identity is retained only as custody metadata; it never
//! substitutes for this verification transaction or mints a live capability.

const std = @import("std");
const core_verifier = @import("stwo_core").verifier;
const pcs_core = @import("stwo_core").pcs;
const pcs_verifier = @import("stwo_core").pcs.verifier;
const prover_pcs = @import("stwo_prover_engine").pcs;
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;

const logup = @import("../air/logup.zig");
const lookup_physical_v2 =
    @import("../air/lang/lookup_physical_manifest_v2.zig");
const relation_challenges = @import("../air/relation_challenges.zig");
const statement_mod = @import("../air/statement.zig");
const statement_v2 = @import("../air/statement_v2.zig");
const transcript = @import("../air/transcript/mod.zig");
const base_component_assembly = @import("base_component_assembly.zig");
const external_tree = @import("guest_precompile/external_profile_tree.zig");
const incremental_bridge = @import("incremental_bridge_external_v3.zig");
const orchestration_v3 = @import("incremental_native_orchestration_v3.zig");
const preprocessed = @import("preprocessed.zig");
const proof_capture_sha256 = @import("proof_capture_sha256.zig");
const proof_workspace = @import("proof_workspace.zig");
const types = @import("types.zig");

pub const PRODUCTION_ACTIVE = false;
pub const FORMAT_VERSION: u16 = 3;
pub const COMMITMENT_TREE_COUNT: usize = 4;
pub const CaptureIdentity = [32]u8;
const CAPTURE_DOMAIN =
    "stwo.riscv.incremental-native-fresh-capture.v3\x00";
const TRANSCRIPT_DOMAIN =
    "stwo.riscv.incremental-native-transcript.v3\x00";

/// Owned verifier result. `proof` is the actual verifier-expanded PCS/FRI
/// capture, not a digest. `statement` borrows only `public_data`, which is
/// owned by this same object. The integration profile is copied by value and
/// must remain pointer-free under its own compile-time contract.
pub fn FreshVerifiedCaptureV3(
    comptime Engine: type,
    comptime Profile: type,
) type {
    return struct {
        format_version: u16 = FORMAT_VERSION,
        proof: core_verifier.ProofCapture(types.HasherForEngine(Engine)),
        public_data: statement_v2.OwnedPublicDataV2,
        statement: statement_v2.RiscVStatementV2,
        profile: Profile,
        profile_identity_sha256: orchestration_v3.ProfileIdentity,
        bridge_geometry: incremental_bridge.GeometryV3,
        base_claim: *statement_mod.RiscVInteractionClaim,
        bridge_claim: QM31,
        relations: relation_challenges.Relations,
        manifest: lookup_physical_v2.Manifest,
        authenticated: lookup_physical_v2.AuthenticatedStatement,
        receipt: statement_v2.VerifiedReceipt,
        native_public_sums: statement_v2.NativePublicSums,
        proof_capture_sha256: [32]u8,
        transcript_identity_sha256: [32]u8,
        identity_sha256: CaptureIdentity,

        const Self = @This();

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            allocator.destroy(self.base_claim);
            self.public_data.deinit();
            self.proof.deinit(allocator);
            self.* = undefined;
        }

        /// Rechecks all mutable custody plus the caller-reconstructed profile
        /// hook. This does not rerun FRI; only the verifier entrypoint below may
        /// mint `Self` after fresh proof verification.
        pub fn validateWithProfileHook(
            self: *const Self,
            pcs_config: pcs_core.PcsConfig,
            hook: orchestration_v3.ProfileHookV3(Engine),
        ) !void {
            if (self.format_version != FORMAT_VERSION)
                return error.InvalidIncrementalNativeFreshCapture;
            try self.public_data.validate();
            const expected_statement = try statement_v2.RiscVStatementV2.init(
                self.statement.core,
                self.public_data.data,
            );
            if (!std.meta.eql(expected_statement, self.statement))
                return error.InvalidIncrementalNativeFreshCapture;
            try self.receipt.validateAgainst(&self.public_data.data);
            try self.native_public_sums.validateAgainst(
                &self.public_data.data,
                &self.relations,
            );
            try self.authenticated.validateAgainst(
                &self.statement.core,
                &self.manifest,
            );
            const base_interaction = try self.authenticated
                .totalInteractionColumns(&self.statement.core, &self.manifest);
            try self.bridge_geometry.validate(
                &self.statement.core,
                std.math.cast(u32, base_interaction) orelse
                    return error.InvalidIncrementalNativeFreshCapture,
            );
            try hook.validate(
                @ptrCast(&self.profile),
                pcs_config,
                &self.statement,
                &self.bridge_geometry,
                &self.manifest,
                &self.authenticated,
            );
            const expected_proof_capture_sha256 =
                proof_capture_sha256.compute(&self.proof);
            if (!std.mem.eql(
                u8,
                &hook.profile_identity_sha256,
                &self.profile_identity_sha256,
            ) or !std.mem.eql(
                u8,
                &expected_proof_capture_sha256,
                &self.proof_capture_sha256,
            )) return error.InvalidIncrementalNativeFreshCapture;
            const canonical = try self.authenticated.canonicalInteractionClaim(
                &self.statement.core,
                &self.manifest,
                self.base_claim,
            );
            try logup.verifyGlobalCancellation(
                &.{canonical.view().total().add(self.bridge_claim)},
                self.native_public_sums.total,
            );
            const expected_transcript = transcriptIdentity(
                &self.statement,
                &self.authenticated,
                &self.bridge_geometry,
                self.profile_identity_sha256,
                self.base_claim,
                self.bridge_claim,
                &self.relations,
            );
            const expected_capture_identity =
                captureIdentity(Engine, Profile, self);
            if (!std.mem.eql(
                u8,
                &expected_transcript,
                &self.transcript_identity_sha256,
            ) or !std.mem.eql(
                u8,
                &expected_capture_identity,
                &self.identity_sha256,
            )) return error.InvalidIncrementalNativeFreshCapture;
        }
    };
}

/// Consumes `proof_in` on every path. `capture_out` is assigned only after the
/// complete AIR/PCS/FRI verifier and all post-verification custody checks pass.
pub fn verifyWithEngineUsingChannelAndCapture(
    comptime Engine: type,
    comptime Profile: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    statement: *const statement_v2.RiscVStatementV2,
    bridge_geometry: *const incremental_bridge.GeometryV3,
    profile: *const Profile,
    profile_hook: orchestration_v3.ProfileHookV3(Engine),
    proof_in: types.ProofForEngine(Engine),
    base_claim: *const statement_mod.RiscVInteractionClaim,
    bridge_claim: QM31,
    channel: *Engine.Channel,
    capture_out: *FreshVerifiedCaptureV3(Engine, Profile),
) !void {
    var proof = proof_in;
    var proof_moved = false;
    defer if (!proof_moved) proof.deinit(allocator);
    if (proof.commitment_scheme_proof.commitments.items.len !=
        COMMITMENT_TREE_COUNT)
    {
        return error.InvalidIncrementalNativeProofShape;
    }
    try statement.validate();
    var manifest = lookup_physical_v2.Manifest.native();
    var authenticated = try lookup_physical_v2.AuthenticatedStatement.init(
        &statement.core,
        &manifest,
    );
    const base_interaction_columns = try authenticated.totalInteractionColumns(
        &statement.core,
        &manifest,
    );
    try bridge_geometry.validate(
        &statement.core,
        std.math.cast(u32, base_interaction_columns) orelse
            return error.InvalidIncrementalNativeProofShape,
    );
    try profile_hook.validate(
        @ptrCast(profile),
        pcs_config,
        statement,
        bridge_geometry,
        &manifest,
        &authenticated,
    );

    var bridge_tree0 = try incremental_bridge.PreprocessedTraceV3.init(
        allocator,
        bridge_geometry,
    );
    defer bridge_tree0.deinit();
    const tree0_blocks = [_]external_tree.BorrowedBlock{bridge_tree0.block()};
    const tree0_columns = try external_tree.generatePreprocessed(
        allocator,
        &statement.core,
        &tree0_blocks,
    );
    try verifyPreprocessedRoot(
        Engine,
        allocator,
        pcs_config,
        tree0_columns,
        proof.commitment_scheme_proof.commitments.items[0],
    );

    const tree0_base_logs = try preprocessed.logSizes(
        allocator,
        statement.core,
    );
    defer allocator.free(tree0_base_logs);
    const tree0_logs = try external_tree.appendLogSizes(
        allocator,
        tree0_base_logs,
        &tree0_blocks,
    );
    defer allocator.free(tree0_logs);
    const tree1_base_logs = try mainLogSizes(allocator, &statement.core);
    defer allocator.free(tree1_base_logs);
    const empty_main_columns =
        [_][]const M31{&.{}} ** incremental_bridge.MAIN_COLUMNS;
    const bridge_shape_block = external_tree.BorrowedBlock{
        .log_size = bridge_geometry.log_size,
        .columns = &empty_main_columns,
    };
    const tree1_logs = try external_tree.appendLogSizes(
        allocator,
        tree1_base_logs,
        &.{bridge_shape_block},
    );
    defer allocator.free(tree1_logs);

    const canonical = try authenticated.canonicalInteractionClaim(
        &statement.core,
        &manifest,
        base_claim,
    );
    const empty_interaction_columns =
        [_][]const M31{&.{}} ** incremental_bridge.INTERACTION_COLUMNS;
    const tree2_shape_block = external_tree.BorrowedBlock{
        .log_size = bridge_geometry.log_size,
        .columns = &empty_interaction_columns,
    };
    const tree2_logs = try external_tree.appendLogSizes(
        allocator,
        canonical.view().log_sizes,
        &.{tree2_shape_block},
    );
    defer allocator.free(tree2_logs);

    try profile_hook.mixPreTree0(statement, channel);
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

    try profile_hook.mixPostTree1(statement, channel);
    if (!channel.verifyPowNonce(
        transcript.INTERACTION_POW_BITS,
        base_claim.interaction_pow,
    )) return error.InvalidIncrementalNativeInteractionProofOfWork;
    channel.mixU64(base_claim.interaction_pow);
    const relations = try relation_challenges.Relations.draw(allocator, channel);
    try authenticated.mixInteractionClaim(
        channel,
        &statement.core,
        &manifest,
        base_claim,
    );
    incremental_bridge.mixClaim(channel, bridge_claim);
    try scheme.commit(
        allocator,
        proof.commitment_scheme_proof.commitments.items[2],
        tree2_logs,
        channel,
    );

    const native_sums = try statement_v2.NativePublicSums.init(
        &statement.public_data,
        &relations,
    );
    try logup.verifyGlobalCancellation(
        &.{canonical.view().total().add(bridge_claim)},
        native_sums.total,
    );

    const workspace = try proof_workspace.VerificationWorkspace.create(allocator);
    defer workspace.destroy(allocator);
    workspace.canonical = canonical;
    try base_component_assembly
        .assembleIntoAuthenticatedLookupV2WithIncrementalBoundaryV3(
        .verifier,
        workspace,
        &statement.core,
        base_claim,
        &relations,
        statement.core.nMainColumns(),
        base_interaction_columns,
        &manifest,
        &authenticated,
    );
    const roots = try incrementalRoots(statement);
    const assembly = try incremental_bridge.Assembly(.verifier).create(
        allocator,
        workspace.components.active(),
        bridge_geometry,
        roots.entry,
        roots.exit,
        &relations,
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
    try validateCaptureLogs(&proof_capture, tree0_logs, tree1_logs, tree2_logs);

    var owned_public = try statement_v2.OwnedPublicDataV2.initVerified(
        allocator,
        &statement.public_data,
    );
    var owned_public_moved = false;
    defer if (!owned_public_moved) owned_public.deinit();
    const owned_statement = try statement_v2.RiscVStatementV2.init(
        statement.core,
        owned_public.data,
    );
    const receipt = try owned_statement.verifiedReceipt();
    const owned_sums = try statement_v2.NativePublicSums.init(
        &owned_public.data,
        &relations,
    );
    const owned_claim = try allocator.create(statement_mod.RiscVInteractionClaim);
    var owned_claim_moved = false;
    defer if (!owned_claim_moved) allocator.destroy(owned_claim);
    owned_claim.* = base_claim.*;
    const proof_sha = proof_capture_sha256.compute(&proof_capture);
    const transcript_sha = transcriptIdentity(
        &owned_statement,
        &authenticated,
        bridge_geometry,
        profile_hook.profile_identity_sha256,
        owned_claim,
        bridge_claim,
        &relations,
    );
    var result = FreshVerifiedCaptureV3(Engine, Profile){
        .proof = proof_capture,
        .public_data = owned_public,
        .statement = owned_statement,
        .profile = profile.*,
        .profile_identity_sha256 = profile_hook.profile_identity_sha256,
        .bridge_geometry = bridge_geometry.*,
        .base_claim = owned_claim,
        .bridge_claim = bridge_claim,
        .relations = relations,
        .manifest = manifest,
        .authenticated = authenticated,
        .receipt = receipt,
        .native_public_sums = owned_sums,
        .proof_capture_sha256 = proof_sha,
        .transcript_identity_sha256 = transcript_sha,
        .identity_sha256 = undefined,
    };
    result.identity_sha256 = captureIdentity(Engine, Profile, &result);
    capture_out.* = result;
    proof_capture_owned = false;
    owned_public_moved = true;
    owned_claim_moved = true;
}

fn mainLogSizes(
    allocator: std.mem.Allocator,
    statement: *const statement_mod.RiscVStatement,
) ![]u32 {
    const result = try allocator.alloc(u32, statement.nMainColumns());
    var offset: usize = 0;
    for (statement.component_descs[0..statement.n_components]) |descriptor| {
        @memset(result[offset..][0..descriptor.n_columns], descriptor.log_size);
        offset += descriptor.n_columns;
    }
    for (statement.infra_descs[0..statement.n_infra]) |descriptor| {
        @memset(result[offset..][0..descriptor.n_columns], descriptor.log_size);
        offset += descriptor.n_columns;
    }
    if (offset != result.len) return error.InvalidIncrementalNativeProofShape;
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
        return error.InvalidIncrementalNativePreprocessedRoot;
}

fn validateCaptureLogs(
    capture: anytype,
    tree0: []const u32,
    tree1: []const u32,
    tree2: []const u32,
) !void {
    if (capture.commitments.len != COMMITMENT_TREE_COUNT or
        capture.column_log_sizes.len != COMMITMENT_TREE_COUNT or
        !std.mem.eql(u32, capture.column_log_sizes[0], tree0) or
        !std.mem.eql(u32, capture.column_log_sizes[1], tree1) or
        !std.mem.eql(u32, capture.column_log_sizes[2], tree2) or
        capture.column_log_sizes[3].len == 0)
    {
        return error.InvalidIncrementalNativeProofShape;
    }
}

fn incrementalRoots(
    statement: *const statement_v2.RiscVStatementV2,
) !struct { entry: u32, exit: u32 } {
    const public = statement.core.public_data;
    return .{
        .entry = public.initial_rw_root orelse
            return error.InvalidIncrementalNativeStatement,
        .exit = public.final_rw_root orelse
            return error.InvalidIncrementalNativeStatement,
    };
}

fn transcriptIdentity(
    statement: *const statement_v2.RiscVStatementV2,
    authenticated: *const lookup_physical_v2.AuthenticatedStatement,
    geometry: *const incremental_bridge.GeometryV3,
    profile_identity: orchestration_v3.ProfileIdentity,
    base_claim: *const statement_mod.RiscVInteractionClaim,
    bridge_claim: QM31,
    relations: *const relation_challenges.Relations,
) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(TRANSCRIPT_DOMAIN);
    hashU32Digest(&hash, statement.authority_id);
    hashU32Digest(&hash, statement.public_data.wireId());
    hash.update(&authenticated.activation_identity);
    hash.update(&geometry.identity_sha256);
    hash.update(&profile_identity);
    hashInt(&hash, u64, base_claim.interaction_pow);
    var manifest = lookup_physical_v2.Manifest.native();
    const canonical = authenticated.canonicalInteractionClaim(
        &statement.core,
        &manifest,
        base_claim,
    ) catch unreachable;
    for (canonical.claimed_sums) |sum| hashQm31(&hash, sum);
    hashQm31(&hash, bridge_claim);
    var draws: [relation_challenges.DRAW_COUNT]QM31 = undefined;
    relations.writeDraws(&draws) catch unreachable;
    for (draws) |draw| hashQm31(&hash, draw);
    return hash.finalResult();
}

fn captureIdentity(
    comptime Engine: type,
    comptime Profile: type,
    capture: *const FreshVerifiedCaptureV3(Engine, Profile),
) CaptureIdentity {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(CAPTURE_DOMAIN);
    hashInt(&hash, u16, capture.format_version);
    hash.update(&capture.transcript_identity_sha256);
    hash.update(&capture.proof_capture_sha256);
    hash.update(&capture.profile_identity_sha256);
    hash.update(&capture.bridge_geometry.identity_sha256);
    hashU32Digest(&hash, capture.receipt.identity);
    hashU32Digest(&hash, capture.native_public_sums.identity);
    return hash.finalResult();
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
    if (PRODUCTION_ACTIVE or FORMAT_VERSION != 3 or
        COMMITMENT_TREE_COUNT != 4)
    {
        @compileError("incremental native verifier V3 activation drifted");
    }
}
