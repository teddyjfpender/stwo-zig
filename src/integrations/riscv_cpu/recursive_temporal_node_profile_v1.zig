//! Pointer-free verification-profile authority for one recursive tree level.
//!
//! A profile separates the VK which verified this node from the VK selected
//! for its parent.  Legacy real parents happen to use the same value; the
//! empty height-one cohort deliberately does not.  The exact manifest,
//! program/profile and transcript descriptor travel with both values so a
//! later heterogeneous pair cannot infer authority from dimensions alone.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const artifact_mod = @import("recursive_temporal_parent_verified_artifact_v1.zig");
const publication_mod = @import("recursive_temporal_parent_publication_v3.zig");
const security_mod = @import("recursive_temporal_proof_security_v1.zig");
const transcript_mod = @import("recursive_temporal_child_transcript_authority_v1.zig");

const channel = frontend.recursion.poseidon2_channel;
const m31 = @import("stwo_core").fields.m31;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 3;
const AUTHORITY_DOMAIN =
    "stwo-zig/typed-air/recursive-temporal-node-profile/v1\x00";

pub const KindV1 = enum(u8) {
    real_parent_h1 = 1,
    empty_parent_h1 = 2,
    recursive_parent = 3,
};

pub const NodeProfileV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    kind: KindV1,
    parent_height: u8,
    padding: [2]u8 = .{ 0, 0 },
    verification_key_id: channel.Digest,
    next_parent_vk_id: channel.Digest,
    /// Manifest for the native child AIR replayed by row 18. An Ethereum h1
    /// profile seals the verifier-derived dynamic physical roster
    /// (`2 * n_components + n_infra + 14`); the measured 4M-cycle leaves use
    /// 163--181 entries. This is distinct from the parent outer STARK's
    /// fixed 39-component roster and must never be replaced by a fixed 53.
    child_composition_manifest_sha_id: [32]u8,
    /// Manifest for this node proof's outer STARK component roster.
    manifest_sha_id: [32]u8,
    air_program_id: channel.Digest,
    profile_id: channel.Digest,
    admitted_child_security: security_mod.ProofSecurityV1,
    parent_proof_security: security_mod.ProofSecurityV1,
    transcript: transcript_mod.DescriptorV1,
    identity: [32]u8,

    pub fn init(
        kind: KindV1,
        parent_height: u8,
        verification_key_id: channel.Digest,
        next_parent_vk_id: channel.Digest,
        manifest_sha_id: [32]u8,
        air_program_id: channel.Digest,
        profile_id: channel.Digest,
        admitted_child_security: security_mod.ProofSecurityV1,
        parent_proof_security: security_mod.ProofSecurityV1,
        transcript: transcript_mod.DescriptorV1,
    ) !NodeProfileV1 {
        return initWithManifests(
            kind,
            parent_height,
            verification_key_id,
            next_parent_vk_id,
            manifest_sha_id,
            manifest_sha_id,
            air_program_id,
            profile_id,
            admitted_child_security,
            parent_proof_security,
            transcript,
        );
    }

    /// Append-only constructor for a profile whose child AIR composition and
    /// parent outer-STARK rosters are intentionally distinct.
    pub fn initWithManifests(
        kind: KindV1,
        parent_height: u8,
        verification_key_id: channel.Digest,
        next_parent_vk_id: channel.Digest,
        child_composition_manifest_sha_id: [32]u8,
        parent_outer_manifest_sha_id: [32]u8,
        air_program_id: channel.Digest,
        profile_id: channel.Digest,
        admitted_child_security: security_mod.ProofSecurityV1,
        parent_proof_security: security_mod.ProofSecurityV1,
        transcript: transcript_mod.DescriptorV1,
    ) !NodeProfileV1 {
        var result = NodeProfileV1{
            .kind = kind,
            .parent_height = parent_height,
            .verification_key_id = verification_key_id,
            .next_parent_vk_id = next_parent_vk_id,
            .child_composition_manifest_sha_id = child_composition_manifest_sha_id,
            .manifest_sha_id = parent_outer_manifest_sha_id,
            .air_program_id = air_program_id,
            .profile_id = profile_id,
            .admitted_child_security = admitted_child_security,
            .parent_proof_security = parent_proof_security,
            .transcript = transcript,
            .identity = undefined,
        };
        result.identity = authorityIdentity(&result);
        try result.validate();
        return result;
    }

    pub fn validate(self: *const NodeProfileV1) !void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or self.parent_height == 0 or
            !std.mem.allEqual(u8, &self.padding, 0))
        {
            return error.InvalidNodeProfile;
        }
        try requireDigest(self.verification_key_id);
        try requireDigest(self.next_parent_vk_id);
        try requireDigest(self.air_program_id);
        try requireDigest(self.profile_id);
        try self.admitted_child_security.validate();
        try self.parent_proof_security.validate();
        if (std.mem.allEqual(
            u8,
            &self.child_composition_manifest_sha_id,
            0,
        ) or std.mem.allEqual(u8, &self.manifest_sha_id, 0))
            return error.InvalidNodeProfile;
        try self.transcript.validateForChildHeight(self.parent_height);
        switch (self.kind) {
            .real_parent_h1 => if (self.parent_height != 1 or
                self.transcript.kind != .temporal_parent_v3 or
                self.admitted_child_security.kind == .proofless_empty)
                return error.InvalidNodeProfile,
            .empty_parent_h1 => if (self.parent_height != 1 or
                self.transcript.kind != .empty_parent_v1 or
                self.admitted_child_security.kind != .proofless_empty)
                return error.InvalidNodeProfile,
            .recursive_parent => if (self.parent_height < 2 or
                self.transcript.kind != .recursive_node_v1 or
                (self.admitted_child_security.kind !=
                    .recursive_parent_functional and
                    self.admitted_child_security.kind !=
                        .recursive_parent_secure))
                return error.InvalidNodeProfile,
        }
        if (self.parent_proof_security.kind != .recursive_parent_functional and
            self.parent_proof_security.kind != .recursive_parent_secure)
        {
            return error.InvalidNodeProfile;
        }
        if (!std.mem.eql(u8, &self.identity, &authorityIdentity(self)))
            return error.NodeProfileIdentityMismatch;
    }

    /// Re-admission check for a verifier-minted proof artifact.  This is the
    /// content/VK gate: matching row dimensions without these exact fields is
    /// insufficient.
    pub fn validateArtifact(
        self: *const NodeProfileV1,
        publication: *const publication_mod.VerifiedPublicationV1,
        artifact: *const artifact_mod.VerifiedTemporalParentArtifactV1,
    ) !void {
        try self.validate();
        try artifact.validateAgainst(publication);
        const statement = try artifact.child.statement();
        if (statement.slots.height != self.parent_height or
            !std.meta.eql(
                artifact.child.verification_key_id,
                self.verification_key_id,
            ) or !std.meta.eql(
            artifact.child.recursive_parent_vk_id,
            self.next_parent_vk_id,
        ) or !std.mem.eql(
            u8,
            &publication.manifest_sha_id,
            &self.manifest_sha_id,
        ) or !std.meta.eql(
            artifact.child.air_program_id,
            self.air_program_id,
        ) or !std.meta.eql(artifact.child.profile_id, self.profile_id) or
            !std.meta.eql(artifact.transcript_authority, self.transcript))
        {
            return error.NodeProfileArtifactMismatch;
        }
    }

    /// Strict selected-path security check. Availability/activation is a
    /// separate gate; this method proves only that the sealed profile names
    /// the production PCS schedule rather than the functional q=3 schedule.
    pub fn requireProductionSecurity(self: *const NodeProfileV1) !void {
        try self.validate();
        switch (self.kind) {
            .real_parent_h1 => if (self.admitted_child_security.kind !=
                .ethereum_segment_v3_poseidon2)
            {
                return error.ProductionSecurityProfileRequired;
            },
            .empty_parent_h1 => {},
            .recursive_parent => if (self.admitted_child_security.kind !=
                .recursive_parent_secure)
            {
                return error.ProductionSecurityProfileRequired;
            },
        }
        if (self.parent_proof_security.kind != .recursive_parent_secure)
            return error.ProductionSecurityProfileRequired;
    }
};

fn authorityIdentity(value: *const NodeProfileV1) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(AUTHORITY_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hashInt(&hash, u8, @intFromEnum(value.kind));
    hashInt(&hash, u8, value.parent_height);
    hashDigest(&hash, value.verification_key_id);
    hashDigest(&hash, value.next_parent_vk_id);
    hash.update(&value.child_composition_manifest_sha_id);
    hash.update(&value.manifest_sha_id);
    hashDigest(&hash, value.air_program_id);
    hashDigest(&hash, value.profile_id);
    hash.update(&value.admitted_child_security.identity);
    hash.update(&value.parent_proof_security.identity);
    hashInt(&hash, u16, value.transcript.format_version);
    hashInt(&hash, u16, value.transcript.schema_version);
    hashInt(&hash, u8, @intFromEnum(value.transcript.kind));
    hashInt(&hash, u32, value.transcript.domain);
    hashInt(&hash, u16, value.transcript.cohort_format_version);
    hashInt(&hash, u16, value.transcript.cohort_schema_version);
    hashInt(&hash, u16, value.transcript.component_count);
    return hash.finalResult();
}

fn requireDigest(value: channel.Digest) !void {
    var nonzero = false;
    for (value) |word| {
        if (word >= m31.Modulus) return error.InvalidNodeProfile;
        nonzero = nonzero or word != 0;
    }
    if (!nonzero) return error.InvalidNodeProfile;
}

fn hashDigest(hash: *Sha256, value: channel.Digest) void {
    for (value) |word| hashInt(hash, u32, word);
}

fn hashInt(hash: *Sha256, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

comptime {
    if (FORMAT_VERSION != 1 or SCHEMA_VERSION != 3)
        @compileError("temporal node profile contract drifted");
}
