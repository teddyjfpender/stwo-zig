//! Fixed relation-replay authority for one verified SegmentV2 temporal child.
//!
//! A successful SegmentV2 verifier transaction mints `RecursiveWitnessV1`.
//! After that witness has passed its artifact preflight, this module copies
//! its exact 94 transcript draws into a pointer-free temporal-child profile.
//! No proof bytes, caller-selected relation values, or allocator enter this
//! boundary.  The witness relation seal remains the transitive draw identity;
//! the profile identity binds that seal to the publication and witness without
//! hashing the 94 draws a second time.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const segment_artifact =
    @import("recursive_segment_v2_verified_artifact.zig");
const segment_publication =
    @import("recursive_segment_v2_verified_publication.zig");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const m31 = stwo_core.fields.m31;
const recursion = frontend.recursion;
const channel = recursion.poseidon2_channel;
const universal = recursion.air.universal_challenges;

pub const Digest = segment_publication.Digest;
pub const Publication = segment_artifact.Publication;
pub const RecursiveWitnessV1 = segment_artifact.RecursiveWitnessV1;
pub const UniversalRelations = universal.UniversalRelations;

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 1;
pub const RELATION_DRAW_COUNT: usize = segment_artifact.RELATION_DRAW_COUNT;
pub const RELATION_COUNT: usize = universal.RELATION_COUNT;
pub const PROFILE_ID_DOMAIN: u32 = 0x5452_5031; // "TRP1"

pub const POINTER_FREE = true;
pub const HEAP_ALLOCATIONS_PER_DERIVE: usize = 0;
pub const HEAP_ALLOCATIONS_PER_VALIDATE: usize = 0;
pub const HEAP_ALLOCATIONS_PER_RECONSTRUCT: usize = 0;
pub const UNIVERSAL_RECONSTRUCTIONS_PER_DERIVE: usize = 0;
pub const UNIVERSAL_RECONSTRUCTIONS_PER_RECONSTRUCT: usize = 1;
pub const RAW_DRAW_REHASHES_PER_DERIVE: usize = 0;

pub const Error = universal.Error || error{
    NonCanonicalField,
    PublicationLinkMismatch,
    RelationDrawsIdentityMismatch,
    RelationDrawsMismatch,
    RelationProfileIdentityMismatch,
    UnsupportedFormat,
};

/// Ordered, fixed-width input to temporal relation replay.  The array order is
/// exactly `universal_challenges`: `(z, alpha)` for each of the 47 registry
/// relations.  This value is a derived view, never a second draw authority.
pub const TemporalChildRelationProfileV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    relation_draw_count: u8 = RELATION_DRAW_COUNT,
    padding: [3]u8 = .{ 0, 0, 0 },

    publication_id: Digest,
    witness_id: Digest,
    relation_draws_id: Digest,
    relation_draws: [RELATION_DRAW_COUNT]QM31,
    profile_id: Digest,

    /// Requires the caller to have completed SegmentV2 artifact preflight for
    /// this exact publication/witness pair.  Derivation only copies that
    /// verifier-owned source and deliberately does not reconstruct alpha
    /// powers; the consumer can derive the profile and reconstruct once.
    pub fn deriveFromValidatedWitness(
        publication: *const Publication,
        witness: *const RecursiveWitnessV1,
    ) Error!TemporalChildRelationProfileV1 {
        var result = TemporalChildRelationProfileV1{
            .publication_id = publication.publication_id,
            .witness_id = witness.witness_id,
            .relation_draws_id = witness.relation_draws_id,
            .relation_draws = witness.relation_draws,
            .profile_id = undefined,
        };
        result.profile_id = profileId(&result);
        try result.validateFixedAgainstValidatedWitness(
            publication,
            witness,
        );
        return result;
    }

    /// Allocation-free exact-source validation plus one reconstruction of the
    /// 47 relation elements.  Returning the value lets the caller validate and
    /// consume replay authority without constructing alpha powers twice.
    pub fn reconstructAgainstValidatedWitness(
        self: *const TemporalChildRelationProfileV1,
        publication: *const Publication,
        witness: *const RecursiveWitnessV1,
    ) Error!UniversalRelations {
        try self.validateFixedAgainstValidatedWitness(publication, witness);
        const relations = UniversalRelations.fromDraws(&self.relation_draws);
        try relations.validate();
        return relations;
    }

    pub fn validateAgainstValidatedWitness(
        self: *const TemporalChildRelationProfileV1,
        publication: *const Publication,
        witness: *const RecursiveWitnessV1,
    ) Error!void {
        _ = try self.reconstructAgainstValidatedWitness(
            publication,
            witness,
        );
    }

    fn validateFixedAgainstValidatedWitness(
        self: *const TemporalChildRelationProfileV1,
        publication: *const Publication,
        witness: *const RecursiveWitnessV1,
    ) Error!void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.relation_draw_count != RELATION_DRAW_COUNT or
            !std.mem.allEqual(u8, &self.padding, 0))
        {
            return error.UnsupportedFormat;
        }

        try requireCanonicalDigest(self.publication_id);
        try requireCanonicalDigest(self.witness_id);
        try requireCanonicalDigest(self.relation_draws_id);
        try requireCanonicalDigest(self.profile_id);
        for (self.relation_draws) |value| try requireCanonical(value);

        if (!std.meta.eql(self.publication_id, publication.publication_id) or
            !std.meta.eql(self.witness_id, witness.witness_id) or
            !std.meta.eql(self.witness_id, publication.recursive_witness_id))
        {
            return error.PublicationLinkMismatch;
        }
        if (!std.meta.eql(
            self.relation_draws_id,
            witness.relation_draws_id,
        )) return error.RelationDrawsIdentityMismatch;
        if (!std.meta.eql(self.relation_draws, witness.relation_draws))
            return error.RelationDrawsMismatch;
        if (!std.meta.eql(self.profile_id, profileId(self)))
            return error.RelationProfileIdentityMismatch;
    }
};

/// The raw draws are transitively committed by `relation_draws_id`, which was
/// minted and checked by SegmentV2 artifact preflight.  Reabsorbing all 376
/// field limbs here would add cold-path work without adding authority.
pub fn profileId(profile: *const TemporalChildRelationProfileV1) Digest {
    var hash = ProfileHasher.init();
    hash.addU32(profile.format_version);
    hash.addU32(profile.schema_version);
    hash.addU32(profile.relation_draw_count);
    hash.addU32(RELATION_COUNT);
    hash.digest(profile.publication_id);
    hash.digest(profile.witness_id);
    hash.digest(profile.relation_draws_id);
    return hash.inner.finalize();
}

fn requireCanonical(value: QM31) Error!void {
    for (value.toM31Array()) |word|
        if (word.toU32() >= m31.Modulus) return error.NonCanonicalField;
}

fn requireCanonicalDigest(value: Digest) Error!void {
    for (value) |word|
        if (word >= m31.Modulus) return error.NonCanonicalField;
}

const ProfileHasher = struct {
    inner: channel.CanonicalWordHasher,

    fn init() ProfileHasher {
        return .{
            .inner = channel.CanonicalWordHasher.init(PROFILE_ID_DOMAIN),
        };
    }

    fn addU32(self: *ProfileHasher, value: anytype) void {
        const exact: u32 = @intCast(value);
        std.debug.assert(exact < m31.Modulus);
        self.inner.update(&.{M31.fromCanonical(exact)});
    }

    fn digest(self: *ProfileHasher, value: Digest) void {
        for (value) |word| self.addU32(word);
    }
};

fn assertPointerFree(comptime T: type) void {
    switch (@typeInfo(T)) {
        .pointer, .optional => @compileError("relation profile retains a pointer"),
        .array => |array| assertPointerFree(array.child),
        .@"struct" => |info| inline for (info.fields) |field|
            assertPointerFree(field.type),
        .@"union" => |info| inline for (info.fields) |field|
            assertPointerFree(field.type),
        else => {},
    }
}

comptime {
    if (RELATION_DRAW_COUNT != 94 or RELATION_COUNT != 47 or
        !POINTER_FREE or HEAP_ALLOCATIONS_PER_DERIVE != 0 or
        HEAP_ALLOCATIONS_PER_VALIDATE != 0 or
        HEAP_ALLOCATIONS_PER_RECONSTRUCT != 0 or
        UNIVERSAL_RECONSTRUCTIONS_PER_DERIVE != 0 or
        UNIVERSAL_RECONSTRUCTIONS_PER_RECONSTRUCT != 1 or
        RAW_DRAW_REHASHES_PER_DERIVE != 0)
    {
        @compileError("temporal-child relation-profile ABI drifted");
    }
    assertPointerFree(TemporalChildRelationProfileV1);
}
