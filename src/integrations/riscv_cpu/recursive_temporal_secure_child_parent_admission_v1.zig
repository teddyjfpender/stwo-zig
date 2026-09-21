//! Cold q193 admission for a verified temporal-parent child.
//!
//! The capability is minted only by canonical artifact decode/reserialize plus
//! `Kernel.verifyCold`.  It then binds the exact scheduled task, node profile,
//! session, statement, proof, PCS capture, transcript, reconstruction, and
//! evaluated composition graph.  It is not a production/publication flag.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const artifact_mod =
    @import("recursive_temporal_secure_parent_artifact_v1.zig");
const engine_mod =
    @import("recursive_temporal_secure_parent_native_engine_v1.zig");
const node_profile = @import("recursive_temporal_node_profile_v1.zig");
const statement_plan = @import("recursive_temporal_statement_plan_v1.zig");
const secure_tail = @import("recursive_temporal_secure_tree_tail_v1.zig");

const channel = frontend.recursion.poseidon2_channel;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 1;
pub const PRODUCTION_ACTIVATION = false;
pub const PROOF_BEARING_EMPTY_H1_ADMISSION_AVAILABLE = false;
pub const CANDIDATE_44_ADMISSION_AVAILABLE = false;

const ADMISSION_DOMAIN =
    "stwo-zig/typed-air/secure-temporal-child-admission/v1\x00";

/// Pointer-free summary of a live cold-verifier capability.  Callers must keep
/// the `FreshVerificationV1` beside it; this value alone cannot be readmitted.
pub const FreshSecureChildAdmissionV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    production_activation: bool = PRODUCTION_ACTIVATION,
    reserved: [3]u8 = .{ 0, 0, 0 },
    global_ordinal: u16,
    parent_height: u8,
    reserved_2: u8 = 0,
    parent_index: u32,
    tail_plan_identity_sha256: [32]u8,
    statement_plan_identity_sha256: [32]u8,
    task_identity_sha256: [32]u8,
    profile_identity_sha256: [32]u8,
    ingress_identity_sha256: [32]u8,
    session_identity_sha256: [32]u8,
    statement_identity_sha256: [32]u8,
    parent_statement_sha256: [32]u8,
    canonical_proof_sha256: [32]u8,
    proof_id: channel.Digest,
    pcs_capture_id: channel.Digest,
    transcript_id: channel.Digest,
    verification_key_id: channel.Digest,
    next_parent_vk_id: channel.Digest,
    air_program_id: channel.Digest,
    reconstruction_identity_sha256: [32]u8,
    composition_capture_identity_sha256: [32]u8,
    identity_sha256: [32]u8,

    pub fn mint(
        allocator: std.mem.Allocator,
        plan: *const secure_tail.TailPlanV1,
        source: *const statement_plan.MaterializedPlanV1,
        upper_local_ordinal: usize,
        session: *const artifact_mod.SessionV1,
        artifact: *const artifact_mod.OwnedArtifactV1,
        fresh: *engine_mod.FreshVerificationV1,
    ) !FreshSecureChildAdmissionV1 {
        const scheduled = try scheduledAuthority(
            allocator,
            plan,
            source,
            upper_local_ordinal,
        );
        const task = scheduled.task;
        const profile = scheduled.profile;
        try validateAuthority(task, profile, session, artifact, fresh);
        const reconstruction = &fresh.temporal_parent_reconstruction.?;
        const composition_capture =
            &fresh.temporal_parent_composition_capture.?;
        var result = FreshSecureChildAdmissionV1{
            .global_ordinal = task.global_ordinal,
            .parent_height = task.parent_height,
            .parent_index = task.parent_index,
            .tail_plan_identity_sha256 = plan.identity_sha256,
            .statement_plan_identity_sha256 = source.identity,
            .task_identity_sha256 = task.identity_sha256,
            .profile_identity_sha256 = profile.identity,
            .ingress_identity_sha256 = session.ingress_identity_sha256,
            .session_identity_sha256 = session.identity_sha256,
            .statement_identity_sha256 = fresh.statement.identity_sha256,
            .parent_statement_sha256 = fresh.statement.parent_statement_sha256,
            .canonical_proof_sha256 = fresh.statement.canonical_proof_sha256,
            .proof_id = fresh.statement.proof_id,
            .pcs_capture_id = fresh.statement.capture_id,
            .transcript_id = fresh.statement.transcript_id,
            .verification_key_id = profile.verification_key_id,
            .next_parent_vk_id = profile.next_parent_vk_id,
            .air_program_id = profile.air_program_id,
            .reconstruction_identity_sha256 = reconstruction.identity_sha256,
            .composition_capture_identity_sha256 = composition_capture.identity_sha256,
            .identity_sha256 = undefined,
        };
        result.identity_sha256 = admissionIdentity(&result);
        try result.validateAgainst(
            allocator,
            plan,
            source,
            upper_local_ordinal,
            session,
            artifact,
            fresh,
        );
        return result;
    }

    pub fn validateAgainst(
        self: *const FreshSecureChildAdmissionV1,
        allocator: std.mem.Allocator,
        plan: *const secure_tail.TailPlanV1,
        source: *const statement_plan.MaterializedPlanV1,
        upper_local_ordinal: usize,
        session: *const artifact_mod.SessionV1,
        artifact: *const artifact_mod.OwnedArtifactV1,
        fresh: *engine_mod.FreshVerificationV1,
    ) !void {
        const scheduled = try scheduledAuthority(
            allocator,
            plan,
            source,
            upper_local_ordinal,
        );
        const task = scheduled.task;
        const profile = scheduled.profile;
        try validateAuthority(task, profile, session, artifact, fresh);
        const reconstruction = &fresh.temporal_parent_reconstruction.?;
        const composition_capture =
            &fresh.temporal_parent_composition_capture.?;
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.production_activation or
            !std.mem.allEqual(u8, &self.reserved, 0) or
            self.reserved_2 != 0 or self.global_ordinal != task.global_ordinal or
            self.parent_height != task.parent_height or
            self.parent_index != task.parent_index or
            !std.mem.eql(
                u8,
                &self.tail_plan_identity_sha256,
                &plan.identity_sha256,
            ) or !std.mem.eql(
            u8,
            &self.statement_plan_identity_sha256,
            &source.identity,
        ) or
            !std.mem.eql(
                u8,
                &self.task_identity_sha256,
                &task.identity_sha256,
            ) or !std.mem.eql(
            u8,
            &self.profile_identity_sha256,
            &profile.identity,
        ) or !std.mem.eql(
            u8,
            &self.ingress_identity_sha256,
            &session.ingress_identity_sha256,
        ) or !std.mem.eql(
            u8,
            &self.session_identity_sha256,
            &session.identity_sha256,
        ) or !std.mem.eql(
            u8,
            &self.statement_identity_sha256,
            &fresh.statement.identity_sha256,
        ) or !std.mem.eql(
            u8,
            &self.parent_statement_sha256,
            &fresh.statement.parent_statement_sha256,
        ) or !std.mem.eql(
            u8,
            &self.canonical_proof_sha256,
            &fresh.statement.canonical_proof_sha256,
        ) or !std.meta.eql(self.proof_id, fresh.statement.proof_id) or
            !std.meta.eql(self.pcs_capture_id, fresh.statement.capture_id) or
            !std.meta.eql(self.transcript_id, fresh.statement.transcript_id) or
            !std.meta.eql(
                self.verification_key_id,
                profile.verification_key_id,
            ) or !std.meta.eql(
            self.next_parent_vk_id,
            profile.next_parent_vk_id,
        ) or !std.meta.eql(self.air_program_id, profile.air_program_id) or
            !std.mem.eql(
                u8,
                &self.reconstruction_identity_sha256,
                &reconstruction.identity_sha256,
            ) or !std.mem.eql(
            u8,
            &self.composition_capture_identity_sha256,
            &composition_capture.identity_sha256,
        ) or !std.mem.eql(
            u8,
            &self.identity_sha256,
            &admissionIdentity(self),
        )) {
            return error.InvalidFreshSecureTemporalChildAdmission;
        }
    }
};

/// Owns both the decoded artifact bytes and the non-serializable fresh result.
/// Destroying either invalidates the admission capability.
pub const ColdReadmissionV1 = struct {
    artifact: artifact_mod.OwnedArtifactV1,
    fresh: engine_mod.FreshVerificationV1,
    admission: FreshSecureChildAdmissionV1,

    pub fn deinit(self: *ColdReadmissionV1) void {
        self.fresh.deinit();
        self.artifact.deinit();
        self.* = undefined;
    }
};

/// The only public mint transaction. `decodeCanonical` performs a canonical
/// reserialization check; the explicit second comparison keeps that property
/// local to this admission boundary before `Kernel.verifyCold` runs.
pub fn coldReadmit(
    comptime Kernel: type,
    allocator: std.mem.Allocator,
    authority_inputs: anytype,
    plan: *const secure_tail.TailPlanV1,
    source: *const statement_plan.MaterializedPlanV1,
    upper_local_ordinal: usize,
    session: *const artifact_mod.SessionV1,
    encoded_artifact: []const u8,
) !ColdReadmissionV1 {
    var artifact = try artifact_mod.OwnedArtifactV1.decodeCanonical(
        allocator,
        encoded_artifact,
    );
    errdefer artifact.deinit();
    const canonical = try artifact.encodeCanonicalAlloc(allocator);
    defer allocator.free(canonical);
    if (!std.mem.eql(u8, encoded_artifact, canonical))
        return error.NonCanonicalSecureTemporalParentProof;

    var fresh = try Kernel.verifyCold(
        allocator,
        authority_inputs,
        session,
        &artifact,
    );
    errdefer fresh.deinit();
    const admission = try FreshSecureChildAdmissionV1.mint(
        allocator,
        plan,
        source,
        upper_local_ordinal,
        session,
        &artifact,
        &fresh,
    );
    return .{
        .artifact = artifact,
        .fresh = fresh,
        .admission = admission,
    };
}

const ScheduledAuthorityV1 = struct {
    task: *const secure_tail.ProductTaskV1,
    profile: *const node_profile.NodeProfileV1,
};

fn scheduledAuthority(
    allocator: std.mem.Allocator,
    plan: *const secure_tail.TailPlanV1,
    source: *const statement_plan.MaterializedPlanV1,
    upper_local_ordinal: usize,
) !ScheduledAuthorityV1 {
    try plan.validateAgainst(allocator, source);
    if (upper_local_ordinal >= secure_tail.UPPER_TASK_COUNT)
        return error.InvalidFreshSecureTemporalChildAdmission;
    const task = &plan.tasks[
        secure_tail.EMPTY_H1_TASK_COUNT + upper_local_ordinal
    ];
    return .{
        .task = task,
        .profile = try source.profiles.forNode(
            task.parent_height,
            task.parent_kind,
        ),
    };
}

fn validateAuthority(
    task: *const secure_tail.ProductTaskV1,
    profile: *const node_profile.NodeProfileV1,
    session: *const artifact_mod.SessionV1,
    artifact: *const artifact_mod.OwnedArtifactV1,
    fresh: *engine_mod.FreshVerificationV1,
) !void {
    try task.validate();
    try profile.requireProductionSecurity();
    try session.validate();
    try artifact.validateCustody();
    try artifact.statement.validateAgainstSession(session);
    try fresh.statement.validateAgainstSession(session);
    if (task.task_class != .upper or
        profile.kind != .recursive_parent or
        session.source_kind != .fresh_temporal_parent_v3 or
        !std.meta.eql(artifact.statement, fresh.statement) or
        !std.mem.eql(
            u8,
            &task.profile_identity_sha256,
            &profile.identity,
        ) or !std.mem.eql(
        u8,
        &task.parent_statement_sha256,
        &session.parent_statement_sha256,
    ) or !std.mem.eql(
        u8,
        &session.profile_identity_sha256,
        &profile.identity,
    ) or !std.mem.eql(
        u8,
        &session.child_composition_manifest_sha256,
        &profile.child_composition_manifest_sha_id,
    ) or !std.mem.eql(
        u8,
        &session.parent_outer_manifest_sha256,
        &profile.manifest_sha_id,
    ) or !std.meta.eql(
        session.verification_key_id,
        profile.verification_key_id,
    ) or !std.meta.eql(
        session.next_parent_vk_id,
        profile.next_parent_vk_id,
    ) or !std.meta.eql(session.air_program_id, profile.air_program_id) or
        fresh.h1_reconstruction != null or
        fresh.h1_composition_capture != null or
        fresh.temporal_parent_reconstruction == null or
        fresh.temporal_parent_composition_capture == null)
    {
        return error.InvalidFreshSecureTemporalChildAdmission;
    }
    const reconstruction = &fresh.temporal_parent_reconstruction.?;
    const capture = &fresh.temporal_parent_composition_capture.?;
    try reconstruction.validateAgainstCapture(&fresh.capture);
    try capture.validateRetained();
    if (!std.mem.eql(
        u8,
        &reconstruction.session.identity_sha256,
        &session.identity_sha256,
    ) or !std.mem.eql(
        u8,
        &capture.reconstruction_identity_sha256,
        &reconstruction.identity_sha256,
    )) return error.InvalidFreshSecureTemporalChildAdmission;
}

fn admissionIdentity(value: *const FreshSecureChildAdmissionV1) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(ADMISSION_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hashInt(&hash, u16, value.global_ordinal);
    hashInt(&hash, u8, value.parent_height);
    hashInt(&hash, u32, value.parent_index);
    hash.update(&value.tail_plan_identity_sha256);
    hash.update(&value.statement_plan_identity_sha256);
    hash.update(&value.task_identity_sha256);
    hash.update(&value.profile_identity_sha256);
    hash.update(&value.ingress_identity_sha256);
    hash.update(&value.session_identity_sha256);
    hash.update(&value.statement_identity_sha256);
    hash.update(&value.parent_statement_sha256);
    hash.update(&value.canonical_proof_sha256);
    hashDigest(&hash, value.proof_id);
    hashDigest(&hash, value.pcs_capture_id);
    hashDigest(&hash, value.transcript_id);
    hashDigest(&hash, value.verification_key_id);
    hashDigest(&hash, value.next_parent_vk_id);
    hashDigest(&hash, value.air_program_id);
    hash.update(&value.reconstruction_identity_sha256);
    hash.update(&value.composition_capture_identity_sha256);
    return hash.finalResult();
}

fn hashDigest(hash: *Sha256, value: channel.Digest) void {
    for (value) |word| hashInt(hash, u32, word);
}

fn hashInt(hash: *Sha256, comptime T: type, value: anytype) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}

comptime {
    if (PRODUCTION_ACTIVATION or PROOF_BEARING_EMPTY_H1_ADMISSION_AVAILABLE or
        CANDIDATE_44_ADMISSION_AVAILABLE)
        @compileError("secure temporal child admission activated prematurely");
}
