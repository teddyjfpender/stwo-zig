//! RISC-V proof transcript reconstruction and verification.
//!
//! Verifier component values and the canonical interaction claim live in a
//! heap `VerificationWorkspace`: `core_verifier.verify` borrows a
//! `[]const Component` of fat pointers into the component values, and the
//! canonical claim carries a fixed-capacity log-size table that must not sit in
//! a stack frame. The workspace is one allocation per verification, released by
//! `defer`. See `proof_workspace.zig`.

const std = @import("std");
const core_air_components = @import("stwo_core").air.components;
const pcs_core = @import("stwo_core").pcs;
const pcs_verifier = @import("stwo_core").pcs.verifier;
const core_verifier = @import("stwo_core").verifier;
const prover_engine = @import("stwo_prover_engine").engine;
const diagnostic_hints = @import("../air/diagnostic_hints.zig");

/// Owner-exported source used by the root regression test to pin diagnostic
/// reporting without reaching across the frontend package boundary.
pub const diagnostic_wiring_source = @embedFile("verifier.zig");
const opcode_interaction = @import("../air/lookups/opcode_interaction.zig");
const lookup_physical_v2 = @import("../air/lang/lookup_physical_manifest_v2.zig");
const logup = @import("../air/logup.zig");
const statement_v2 = @import("../air/statement_v2.zig");
const relation_challenges = @import("../air/relation_challenges.zig");
const statement_mod = @import("../air/statement.zig");
const proof_transcript = @import("../proof_transcript.zig");
const preprocessed_trace = @import("preprocessed.zig");
const base_component_assembly = @import("base_component_assembly.zig");
const proof_workspace = @import("proof_workspace.zig");
const vm_leaf_context = @import("../recursion/vm_leaf_context.zig");
const vm_leaf_context_v2 = @import("../recursion/vm_leaf_context_v2.zig");
const statement_validation = @import("statement_validation.zig");
const types = @import("types.zig");
const verifier_protocol = @import("verifier_protocol.zig");

const VerificationWorkspace = proof_workspace.VerificationWorkspace;

pub const LookupLayoutV2 = enum {
    compatibility,
    authenticated_physical_v2,
};

pub const QueryCapture = core_verifier.QueryCapture;

pub fn ProofCaptureForEngine(comptime Engine: type) type {
    return core_verifier.ProofCapture(types.HasherForEngine(Engine));
}

/// Native proof material plus the exact verifier-derived inputs needed to
/// replay this VM's AIR composition in recursive row 18. Both members are
/// published as one transaction after complete AIR, PCS, Merkle, and FRI
/// verification.
pub fn RecursiveLeafCaptureForEngine(comptime Engine: type) type {
    return struct {
        proof: ProofCaptureForEngine(Engine),
        vm_air: vm_leaf_context.Context,

        const Self = @This();

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            self.vm_air.deinit();
            self.proof.deinit(allocator);
            self.* = undefined;
        }
    };
}

/// Transactionally published proof capture plus pointer-free V2 statement
/// receipt.  Neither member is assigned to the caller until native AIR, PCS,
/// Merkle and FRI verification has succeeded.
pub fn VerifiedSegmentV2CaptureForEngine(comptime Engine: type) type {
    return struct {
        proof: ProofCaptureForEngine(Engine),
        vm_air: vm_leaf_context_v2.ContextV2,
        public_data: statement_v2.OwnedPublicDataV2,
        native_public_sums: statement_v2.NativePublicSums,
        receipt: statement_v2.VerifiedReceipt,

        const Self = @This();

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            self.public_data.deinit();
            self.vm_air.deinit();
            self.proof.deinit(allocator);
            self.* = undefined;
        }

        /// Revalidates every mutable, verifier-owned sidecar before recursive
        /// witness construction, including an independent recomputation of the
        /// statement authority from the authenticated wire and VM geometry.
        /// The proof capture is independently resealed by the engine-generic
        /// ContextV2 authority before downstream consumption.
        pub fn validate(self: *const Self) !void {
            try self.vm_air.validateCaptureAuthorities(
                &self.public_data,
                &self.receipt,
                &self.native_public_sums,
                &self.proof,
            );
        }
    };
}

pub const V1Protocol = verifier_protocol.V1Protocol;
pub const V2Protocol = verifier_protocol.V2Protocol;

/// Verify a RISC-V STARK proof with per-opcode-family components.
/// Consumes `proof_in` on both success and failure.
pub fn verifyRiscVWithEngine(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    statement: types.RiscVStatement,
    proof_in: types.ProofForEngine(Engine),
    claim: *const types.RiscVInteractionClaim,
) !void {
    var channel = Engine.Channel{};
    return verifyRiscVWithEngineUsingChannel(
        Engine,
        allocator,
        pcs_config,
        statement,
        proof_in,
        claim,
        &channel,
    );
}

/// Verifies through the production path using a caller-owned transcript channel.
/// The default entrypoint above remains monomorphic and has no tracing branch.
pub fn verifyRiscVWithEngineUsingChannel(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    statement: types.RiscVStatement,
    proof_in: types.ProofForEngine(Engine),
    claim: *const types.RiscVInteractionClaim,
    channel: *Engine.Channel,
) !void {
    return verifyRiscVWithEngineUsingChannelImpl(
        V1Protocol,
        Engine,
        .compatibility,
        allocator,
        pcs_config,
        statement,
        proof_in,
        claim,
        channel,
        @as(void, {}),
        null,
        null,
        null,
        null,
    );
}

/// Production RISC-V verification with transactional capture of the raw and
/// unique FRI query positions. The capture is published only after every AIR,
/// PCS, Merkle, and FRI check succeeds.
pub fn verifyRiscVWithEngineUsingChannelAndQueryCapture(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    statement: types.RiscVStatement,
    proof_in: types.ProofForEngine(Engine),
    claim: *const types.RiscVInteractionClaim,
    channel: *Engine.Channel,
    capture: *QueryCapture,
) !void {
    return verifyRiscVWithEngineUsingChannelImpl(
        V1Protocol,
        Engine,
        .compatibility,
        allocator,
        pcs_config,
        statement,
        proof_in,
        claim,
        channel,
        @as(void, {}),
        capture,
        null,
        null,
        null,
    );
}

/// Production RISC-V verification with a transactionally published, fully
/// expanded proof capture for fixed-width recursive witness construction.
pub fn verifyRiscVWithEngineUsingChannelAndProofCapture(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    statement: types.RiscVStatement,
    proof_in: types.ProofForEngine(Engine),
    claim: *const types.RiscVInteractionClaim,
    channel: *Engine.Channel,
    capture: *ProofCaptureForEngine(Engine),
) !void {
    return verifyRiscVWithEngineUsingChannelImpl(
        V1Protocol,
        Engine,
        .compatibility,
        allocator,
        pcs_config,
        statement,
        proof_in,
        claim,
        channel,
        @as(void, {}),
        null,
        capture,
        null,
        null,
    );
}

/// Production verification with failure-atomic publication of both the core
/// recursive proof witness and its Zig-native VM AIR composition authority.
pub fn verifyRiscVWithEngineUsingChannelAndRecursiveLeafCapture(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    statement: types.RiscVStatement,
    proof_in: types.ProofForEngine(Engine),
    claim: *const types.RiscVInteractionClaim,
    channel: *Engine.Channel,
    capture: *RecursiveLeafCaptureForEngine(Engine),
) !void {
    return verifyRiscVWithEngineUsingChannelImpl(
        V1Protocol,
        Engine,
        .compatibility,
        allocator,
        pcs_config,
        statement,
        proof_in,
        claim,
        channel,
        @as(void, {}),
        null,
        null,
        capture,
        null,
    );
}

/// Independently verifies one native resumed-segment proof.  The proof is
/// consumed on success and failure, exactly like the frozen V1 API.
pub fn verifyRiscVSegmentV2WithEngine(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    statement: statement_v2.RiscVStatementV2,
    proof_in: types.ProofForEngine(Engine),
    claim: *const types.RiscVInteractionClaim,
) !void {
    var transcript_channel = Engine.Channel{};
    return verifyRiscVSegmentV2WithEngineUsingChannel(
        Engine,
        allocator,
        pcs_config,
        statement,
        proof_in,
        claim,
        &transcript_channel,
    );
}

pub fn verifyRiscVSegmentV2WithEngineUsingChannel(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    statement: statement_v2.RiscVStatementV2,
    proof_in: types.ProofForEngine(Engine),
    claim: *const types.RiscVInteractionClaim,
    transcript_channel: *Engine.Channel,
) !void {
    return verifyRiscVWithEngineUsingChannelImpl(
        V2Protocol,
        Engine,
        .authenticated_physical_v2,
        allocator,
        pcs_config,
        statement,
        proof_in,
        claim,
        transcript_channel,
        @as(void, {}),
        null,
        null,
        null,
        null,
    );
}

/// Additive selected-lookup SegmentV2 verifier for an authenticated Stage-A
/// extension. Default SegmentV2 verification continues to pass `void` and
/// reconstructs its frozen transcript byte-for-byte.
pub fn verifyRiscVSegmentV2WithEngineUsingChannelAndTranscriptExtension(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    statement: statement_v2.RiscVStatementV2,
    proof_in: types.ProofForEngine(Engine),
    claim: *const types.RiscVInteractionClaim,
    transcript_channel: *Engine.Channel,
    transcript_extension: anytype,
) !void {
    return verifyRiscVWithEngineUsingChannelImpl(
        V2Protocol,
        Engine,
        .authenticated_physical_v2,
        allocator,
        pcs_config,
        statement,
        proof_in,
        claim,
        transcript_channel,
        transcript_extension,
        null,
        null,
        null,
        null,
    );
}

pub fn verifyRiscVSegmentV2WithEngineUsingChannelAndCapture(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    statement: statement_v2.RiscVStatementV2,
    proof_in: types.ProofForEngine(Engine),
    claim: *const types.RiscVInteractionClaim,
    transcript_channel: *Engine.Channel,
    capture: *VerifiedSegmentV2CaptureForEngine(Engine),
) !void {
    return verifyRiscVWithEngineUsingChannelImpl(
        V2Protocol,
        Engine,
        .authenticated_physical_v2,
        allocator,
        pcs_config,
        statement,
        proof_in,
        claim,
        transcript_channel,
        @as(void, {}),
        null,
        null,
        null,
        capture,
    );
}

/// Explicit spelling of the default selected physical lookup verifier.
pub fn verifyRiscVSegmentLookupV2WithEngine(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    statement: statement_v2.RiscVStatementV2,
    proof_in: types.ProofForEngine(Engine),
    claim: *const types.RiscVInteractionClaim,
) !void {
    var transcript_channel = Engine.Channel{};
    return verifyRiscVSegmentLookupV2WithEngineUsingChannel(
        Engine,
        allocator,
        pcs_config,
        statement,
        proof_in,
        claim,
        &transcript_channel,
    );
}

pub fn verifyRiscVSegmentLookupV2WithEngineUsingChannel(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    statement: statement_v2.RiscVStatementV2,
    proof_in: types.ProofForEngine(Engine),
    claim: *const types.RiscVInteractionClaim,
    transcript_channel: *Engine.Channel,
) !void {
    return verifyRiscVWithEngineUsingChannelImpl(
        V2Protocol,
        Engine,
        .authenticated_physical_v2,
        allocator,
        pcs_config,
        statement,
        proof_in,
        claim,
        transcript_channel,
        @as(void, {}),
        null,
        null,
        null,
        null,
    );
}

pub fn verifyRiscVWithEngineUsingChannelImpl(
    comptime Protocol: type,
    comptime Engine: type,
    comptime lookup_layout: LookupLayoutV2,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    statement: Protocol.Statement,
    proof_in: types.ProofForEngine(Engine),
    claim: *const types.RiscVInteractionClaim,
    channel: *Engine.Channel,
    transcript_extension: anytype,
    capture_out: ?*QueryCapture,
    proof_capture_out: ?*ProofCaptureForEngine(Engine),
    recursive_capture_out: ?*RecursiveLeafCaptureForEngine(Engine),
    v2_capture_out: ?*VerifiedSegmentV2CaptureForEngine(Engine),
) !void {
    comptime @import("stwo_prover_api").assertProverEngine(Engine);
    var proof = proof_in;
    var proof_moved = false;
    defer if (!proof_moved) proof.deinit(allocator);

    const capture_count = @intFromBool(capture_out != null) +
        @intFromBool(proof_capture_out != null) +
        @intFromBool(recursive_capture_out != null) +
        @intFromBool(v2_capture_out != null);
    if (capture_count > 1) return core_verifier.VerificationError.InvalidStructure;

    try Protocol.validate(&statement);
    const core_statement = Protocol.core(&statement);
    if (comptime lookup_layout == .authenticated_physical_v2 and
        !Protocol.is_v2)
    {
        @compileError("authenticated lookup V2 requires statement V2");
    }
    if (claim.n_components != core_statement.n_components or
        claim.n_infra != core_statement.n_infra)
    {
        return types.ProverError.InvalidInteractionClaim;
    }
    if (proof.commitment_scheme_proof.commitments.items.len != 4) {
        return core_verifier.VerificationError.InvalidStructure;
    }
    try statement_validation.verifyPreprocessedRoot(
        Engine,
        allocator,
        pcs_config,
        core_statement.*,
        proof.commitment_scheme_proof.commitments.items[0],
    );

    try Protocol.bind(Engine, pcs_config, &statement, channel);
    var lookup_manifest: lookup_physical_v2.Manifest = undefined;
    var authenticated_lookup: lookup_physical_v2.AuthenticatedStatement =
        undefined;
    if (comptime lookup_layout == .authenticated_physical_v2) {
        lookup_manifest = lookup_physical_v2.Manifest.native();
        authenticated_lookup = try lookup_physical_v2.AuthenticatedStatement.init(
            core_statement,
            &lookup_manifest,
        );
        authenticated_lookup.mixInto(channel);
    }

    var commitment_scheme = try pcs_verifier.CommitmentSchemeVerifier(
        types.HasherForEngine(Engine),
        Engine.MerkleChannel,
    ).init(allocator, pcs_config);
    defer commitment_scheme.deinit(allocator);

    // Tree 0: selector pairs plus exact lookup-table tuple columns.
    const preproc_log_sizes = try preprocessed_trace.logSizes(
        allocator,
        core_statement.*,
    );
    defer allocator.free(preproc_log_sizes);
    try commitment_scheme.commit(
        allocator,
        proof.commitment_scheme_proof.commitments.items[0],
        preproc_log_sizes,
        channel,
    );

    // Tree 1: opcode and infrastructure main columns.
    const n_main = core_statement.nMainColumns();
    const main_log_sizes = try allocator.alloc(u32, n_main);
    defer allocator.free(main_log_sizes);
    var col_offset: usize = 0;
    for (0..core_statement.n_components) |i| {
        const desc = core_statement.component_descs[i];
        for (0..desc.n_columns) |c| main_log_sizes[col_offset + c] = desc.log_size;
        col_offset += desc.n_columns;
    }
    for (0..core_statement.n_infra) |i| {
        const desc = core_statement.infra_descs[i];
        for (0..desc.n_columns) |c| main_log_sizes[col_offset + c] = desc.log_size;
        col_offset += desc.n_columns;
    }
    try commitment_scheme.commit(
        allocator,
        proof.commitment_scheme_proof.commitments.items[1],
        main_log_sizes,
        channel,
    );

    const relations = if (comptime @TypeOf(transcript_extension) == void)
        try proof_transcript.verifyToRelations(
            allocator,
            channel,
            core_statement,
            claim.interaction_pow,
        )
    else
        try proof_transcript.verifyToRelationsWithExtension(
            allocator,
            channel,
            core_statement,
            claim.interaction_pow,
            transcript_extension,
        );

    const n_interaction = if (comptime lookup_layout == .authenticated_physical_v2)
        try authenticated_lookup.totalInteractionColumns(
            core_statement,
            &lookup_manifest,
        )
    else
        core_statement.nInteractionColumns();
    const interaction_log_sizes = try allocator.alloc(u32, n_interaction);
    defer allocator.free(interaction_log_sizes);
    var inter_col_offset: usize = 0;
    for (0..core_statement.n_components) |i| {
        const n_cols = if (comptime lookup_layout == .authenticated_physical_v2)
            lookup_manifest.entryForFamily(
                core_statement.component_descs[i].family,
            ).interaction_column_count
        else
            opcode_interaction.nColumns(
                core_statement.component_descs[i].family,
            );
        for (0..n_cols) |c| {
            interaction_log_sizes[inter_col_offset + c] =
                core_statement.component_descs[i].log_size;
        }
        inter_col_offset += n_cols;
    }
    for (0..core_statement.n_infra) |i| {
        const n_cols = statement_mod.nInteractionColsForInfra(
            core_statement.infra_descs[i].kind,
        );
        for (0..n_cols) |c| {
            interaction_log_sizes[inter_col_offset + c] =
                core_statement.infra_descs[i].log_size;
        }
        inter_col_offset += n_cols;
    }
    std.debug.assert(inter_col_offset == n_interaction);
    if (comptime lookup_layout == .authenticated_physical_v2) {
        try authenticated_lookup.mixInteractionClaim(
            channel,
            core_statement,
            &lookup_manifest,
            claim,
        );
    } else {
        try proof_transcript.mixInteractionClaim(channel, core_statement, claim);
    }
    try commitment_scheme.commit(
        allocator,
        proof.commitment_scheme_proof.commitments.items[2],
        interaction_log_sizes,
        channel,
    );

    const workspace = try VerificationWorkspace.create(allocator);
    defer workspace.destroy(allocator);

    if (comptime lookup_layout == .authenticated_physical_v2) {
        workspace.canonical = try authenticated_lookup.canonicalInteractionClaim(
            core_statement,
            &lookup_manifest,
            claim,
        );
    } else {
        try workspace.canonicalize(claim, core_statement);
    }
    const canonical_view = workspace.canonical.view();
    const component_total = canonical_view.total();
    const public_boundary = try Protocol.publicBoundary(&statement, &relations);
    logup.verifyGlobalCancellation(&.{component_total}, public_boundary) catch |err| {
        // `LogupSumNonZero` names the symptom and stops. Which relation is
        // unbalanced is not derivable here -- a component's claimed sum is a
        // single field element over every relation that component touches --
        // but it *is* derivable by `riscv-trace-dump --relation-sums`, which
        // ships next to this binary. Say so at the point of failure rather than
        // leaving the reader to rediscover the tooling.
        diagnostic_hints.reportLogupImbalance(
            component_total.add(public_boundary),
            Protocol.declaresPublicIo(&statement),
        );
        return err;
    };

    const active_components = if (comptime lookup_layout == .authenticated_physical_v2)
        try assembleComponentsAuthenticatedLookupV2(
            workspace,
            core_statement,
            claim,
            &relations,
            n_main,
            n_interaction,
            &lookup_manifest,
            &authenticated_lookup,
        )
    else
        try assembleComponents(
            workspace,
            core_statement,
            claim,
            &relations,
            n_main,
            n_interaction,
        );

    const v2_receipt = if (comptime Protocol.is_v2)
        try statement.verifiedReceipt()
    else {};
    proof_moved = true;
    if (comptime Protocol.is_v2) {
        if (v2_capture_out) |capture| {
            var native_capture: ProofCaptureForEngine(Engine) = undefined;
            var native_capture_owned = false;
            defer if (native_capture_owned) native_capture.deinit(allocator);
            try core_verifier.verifyWithProofCapture(
                types.HasherForEngine(Engine),
                Engine.MerkleChannel,
                allocator,
                active_components,
                channel,
                &commitment_scheme,
                proof,
                &native_capture,
            );
            native_capture_owned = true;
            var owned_public_data = try statement_v2.OwnedPublicDataV2.initVerified(
                allocator,
                &statement.public_data,
            );
            errdefer owned_public_data.deinit();
            const native_public_sums = try statement_v2.NativePublicSums.init(
                &owned_public_data.data,
                &relations,
            );
            var context = try vm_leaf_context_v2.ContextV2.initVerified(
                allocator,
                &statement,
                claim,
                &relations,
                &lookup_manifest,
                &authenticated_lookup,
                active_components,
                &native_capture,
                &v2_receipt,
                &native_public_sums,
            );
            errdefer context.deinit();
            capture.* = .{
                .proof = native_capture,
                .vm_air = context,
                .public_data = owned_public_data,
                .native_public_sums = native_public_sums,
                .receipt = v2_receipt,
            };
            native_capture_owned = false;
        } else {
            try core_verifier.verify(
                types.HasherForEngine(Engine),
                Engine.MerkleChannel,
                allocator,
                active_components,
                channel,
                &commitment_scheme,
                proof,
            );
        }
    } else {
        if (recursive_capture_out) |capture| {
            var native_capture: ProofCaptureForEngine(Engine) = undefined;
            var native_capture_owned = false;
            defer if (native_capture_owned) native_capture.deinit(allocator);
            try core_verifier.verifyWithProofCapture(
                types.HasherForEngine(Engine),
                Engine.MerkleChannel,
                allocator,
                active_components,
                channel,
                &commitment_scheme,
                proof,
                &native_capture,
            );
            native_capture_owned = true;
            var context = try vm_leaf_context.Context.initVerified(
                allocator,
                core_statement,
                claim,
                &relations,
                active_components,
            );
            errdefer context.deinit();
            capture.* = .{ .proof = native_capture, .vm_air = context };
            native_capture_owned = false;
        } else if (proof_capture_out) |capture| {
            try core_verifier.verifyWithProofCapture(
                types.HasherForEngine(Engine),
                Engine.MerkleChannel,
                allocator,
                active_components,
                channel,
                &commitment_scheme,
                proof,
                capture,
            );
        } else if (capture_out) |capture| {
            try core_verifier.verifyWithQueryCapture(
                types.HasherForEngine(Engine),
                Engine.MerkleChannel,
                allocator,
                active_components,
                channel,
                &commitment_scheme,
                proof,
                capture,
            );
        } else {
            try core_verifier.verify(
                types.HasherForEngine(Engine),
                Engine.MerkleChannel,
                allocator,
                active_components,
                channel,
                &commitment_scheme,
                proof,
            );
        }
        if (comptime @hasDecl(Engine.Channel, "completeRiscVTranscript"))
            try channel.completeRiscVTranscript();
    }
}

/// Builds the unchanged base verifier-component prefix without consuming the
/// proof. Profile verifiers append their authenticated components to this
/// borrowed slice and then invoke the shared core verifier once.
pub fn assembleComponents(
    workspace: *VerificationWorkspace,
    statement: *const types.RiscVStatement,
    claim: *const types.RiscVInteractionClaim,
    relations: *const relation_challenges.Relations,
    n_main: usize,
    n_interaction: usize,
) ![]const core_air_components.Component {
    try base_component_assembly.assembleInto(
        .verifier,
        workspace,
        statement,
        claim,
        relations,
        n_main,
        n_interaction,
    );
    return workspace.components.active();
}

/// Verifier-side twin of the dormant authenticated V2 prover registry. Both
/// directions cross the same statement/manifest admission boundary and share
/// the exact assembly walk.
pub fn assembleComponentsAuthenticatedLookupV2(
    workspace: *VerificationWorkspace,
    statement: *const types.RiscVStatement,
    claim: *const types.RiscVInteractionClaim,
    relations: *const relation_challenges.Relations,
    n_main: usize,
    n_interaction: usize,
    manifest: *const lookup_physical_v2.Manifest,
    authenticated_statement: *const lookup_physical_v2.AuthenticatedStatement,
) ![]const core_air_components.Component {
    try base_component_assembly.assembleIntoAuthenticatedLookupV2(
        .verifier,
        workspace,
        statement,
        claim,
        relations,
        n_main,
        n_interaction,
        manifest,
        authenticated_statement,
    );
    return workspace.components.active();
}

/// Verifier twin of the full-state incremental V3 boundary assembly. This
/// preserves the authenticated V2 roster while selecting ternary split memory
/// multiplicities for the memory infrastructure component only.
pub fn assembleComponentsAuthenticatedLookupV2WithIncrementalBoundaryV3(
    workspace: *VerificationWorkspace,
    statement: *const types.RiscVStatement,
    claim: *const types.RiscVInteractionClaim,
    relations: *const relation_challenges.Relations,
    n_main: usize,
    n_interaction: usize,
    manifest: *const lookup_physical_v2.Manifest,
    authenticated_statement: *const lookup_physical_v2.AuthenticatedStatement,
) ![]const core_air_components.Component {
    try base_component_assembly
        .assembleIntoAuthenticatedLookupV2WithIncrementalBoundaryV3(
        .verifier,
        workspace,
        statement,
        claim,
        relations,
        n_main,
        n_interaction,
        manifest,
        authenticated_statement,
    );
    return workspace.components.active();
}
