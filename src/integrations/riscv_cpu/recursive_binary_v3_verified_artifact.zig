//! Append-only recursive sidecar for one successfully verified binary proof.
//!
//! The frozen V2 publication binds canonical proof bytes, the authenticated
//! pair, cohort authority, and exact global closure, but predates recursive
//! capture custody.  This V3 value is minted beside it while the successful
//! verifier still owns the capture, reconstructed claims, transcript draws,
//! and provider partials.  It is pointer-free and exposes no detached mint
//! constructor.  Consumers must re-admit it with the capture, V2 publication,
//! trusted universal manifest, and selected V3 binary program descriptor.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const publication_mod = @import("recursive_binary_verified_publication.zig");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const m31 = stwo_core.fields.m31;
const recursion = frontend.recursion;
const channel = recursion.poseidon2_channel;
const protocol = recursion.protocol;
const manifest_mod = recursion.air.universal_adapter_manifest;
const roster = recursion.air.universal_roster;
const universal = recursion.air.universal_challenges;
const composition_v3 = recursion.recursion_air_composition_circuit_v3;

pub const Digest = channel.Digest;
pub const Sha256Digest = [32]u8;
pub const Publication = publication_mod.VerifiedBinaryClosurePublicationV2;
pub const OuterProofCapture = stwo_core.pcs.verifier.VerifiedProofCapture(
    recursion.engine.Hasher,
);

pub const FORMAT_VERSION: u16 = 3;
pub const SCHEMA_VERSION: u16 = 1;
pub const CLAIM_COUNT: usize = roster.COMPONENT_COUNT;
pub const RELATION_DRAW_COUNT: usize = universal.DRAW_COUNT;
pub const POSEIDON2_PARTIAL_COUNT: usize = 2;
pub const POSEIDON2_ROSTER_ROW: usize =
    @intFromEnum(roster.Component.poseidon2);

pub const CAPTURE_ID_DOMAIN: u32 = 0x4256_4341; // "BVCA"
pub const CLAIMS_ID_DOMAIN: u32 = 0x4256_434c; // "BVCL"
pub const RELATIONS_ID_DOMAIN: u32 = 0x4256_524c; // "BVRL"
pub const PARTIALS_ID_DOMAIN: u32 = 0x4256_5032; // "BVP2"
pub const ARTIFACT_ID_DOMAIN: u32 = 0x4256_4152; // "BVAR"

pub const POINTER_FREE = true;
pub const PUBLIC_MINT_CONSTRUCTOR_AVAILABLE = false;
pub const HEAP_ALLOCATIONS_PER_PREFLIGHT: usize = 0;
pub const CAPTURE_ID_HASHES_PER_PREFLIGHT: usize = 1;

pub const Error = publication_mod.Error || manifest_mod.Error ||
    universal.Error || composition_v3.Error || error{
    ArtifactIdentityMismatch,
    CaptureIdentityMismatch,
    ClaimIdentityMismatch,
    CohortAuthorityMismatch,
    InvalidCount,
    ManifestMismatch,
    NonCanonicalField,
    PartialIdentityMismatch,
    Poseidon2PartialMismatch,
    ProgramDescriptorMismatch,
    PublicationLinkMismatch,
    RelationIdentityMismatch,
    StatementIdentityMismatch,
    UnsupportedFormat,
};

/// Fixed verifier-local material required by the V3 binary composition lane.
/// Dynamic capture storage stays in the surrounding transaction output.
pub const VerifiedBinaryArtifactV3 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    claim_count: u8 = CLAIM_COUNT,
    relation_draw_count: u8 = RELATION_DRAW_COUNT,
    poseidon2_partial_count: u8 = POSEIDON2_PARTIAL_COUNT,
    padding: [3]u8 = .{ 0, 0, 0 },

    proof_id: Digest,
    publication_id: Digest,
    capture_id: Digest,
    statement_id: Digest,
    verification_key_id: Digest,
    cohort_id: Digest,
    air_program_id: Digest,

    cohort_authority_sha_id: Sha256Digest,
    manifest_seal: Sha256Digest,
    program_descriptor_identity: Sha256Digest,

    statement_words: recursion.span_statement.StatementWords,
    claimed_sums: [CLAIM_COUNT]QM31,
    relation_draws: [RELATION_DRAW_COUNT]QM31,
    poseidon2_partials: [POSEIDON2_PARTIAL_COUNT]QM31,

    claimed_sums_id: Digest,
    relation_draws_id: Digest,
    poseidon2_partials_id: Digest,
    artifact_id: Digest,

    pub fn validateSelfConsistency(
        self: *const VerifiedBinaryArtifactV3,
    ) Error!void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.claim_count != CLAIM_COUNT or
            self.relation_draw_count != RELATION_DRAW_COUNT or
            self.poseidon2_partial_count != POSEIDON2_PARTIAL_COUNT or
            !std.mem.allEqual(u8, &self.padding, 0))
        {
            return error.UnsupportedFormat;
        }
        inline for (.{
            self.proof_id,
            self.publication_id,
            self.capture_id,
            self.statement_id,
            self.verification_key_id,
            self.cohort_id,
            self.air_program_id,
            self.claimed_sums_id,
            self.relation_draws_id,
            self.poseidon2_partials_id,
            self.artifact_id,
        }) |value| try requireDigest(value);
        try requireSha(self.cohort_authority_sha_id);
        try requireSha(self.manifest_seal);
        try requireSha(self.program_descriptor_identity);
        for (self.statement_words) |word|
            if (word.toU32() >= m31.Modulus) return error.NonCanonicalField;
        for (self.claimed_sums) |value| try requireCanonical(value);
        for (self.relation_draws) |value| try requireCanonical(value);
        for (self.poseidon2_partials) |value| try requireCanonical(value);
        if (!self.poseidon2_partials[0].add(self.poseidon2_partials[1]).eql(
            self.claimed_sums[POSEIDON2_ROSTER_ROW],
        )) return error.Poseidon2PartialMismatch;

        const relations = universal.UniversalRelations.fromDraws(
            &self.relation_draws,
        );
        try relations.validate();
        if (!std.meta.eql(statementId(&self.statement_words), self.statement_id))
            return error.StatementIdentityMismatch;
        if (!std.meta.eql(claimedSumsId(self), self.claimed_sums_id))
            return error.ClaimIdentityMismatch;
        if (!std.meta.eql(relationDrawsId(self), self.relation_draws_id))
            return error.RelationIdentityMismatch;
        if (!std.meta.eql(poseidon2PartialsId(self), self.poseidon2_partials_id))
            return error.PartialIdentityMismatch;
        if (!std.meta.eql(artifactId(self), self.artifact_id))
            return error.ArtifactIdentityMismatch;
    }

    pub fn validateAgainst(
        self: *const VerifiedBinaryArtifactV3,
        capture: *const OuterProofCapture,
        publication: *const Publication,
        manifest: *const manifest_mod.Manifest,
        descriptor: composition_v3.ProgramDescriptorV3,
    ) Error!void {
        try publication.validate();
        try manifest.validate();
        try validateBinaryDescriptor(descriptor, manifest);
        try self.validateSelfConsistency();
        if (!std.meta.eql(captureIdentity(capture), self.capture_id))
            return error.CaptureIdentityMismatch;
        if (!std.meta.eql(self.proof_id, publication.proof_id) or
            !std.meta.eql(self.publication_id, publication.publication_id) or
            !std.meta.eql(self.statement_id, publication.statement_id) or
            !std.meta.eql(
                self.verification_key_id,
                publication.recursive_parent_vk_id,
            ) or !std.meta.eql(self.cohort_id, publication.cohort_id) or
            !std.mem.eql(
                u8,
                &self.cohort_authority_sha_id,
                &publication.cohort_authority_sha_id,
            ))
        {
            return error.PublicationLinkMismatch;
        }
        if (!std.mem.eql(u8, &self.manifest_seal, &manifest.seal))
            return error.ManifestMismatch;
        if (!std.meta.eql(self.air_program_id, descriptor.air_program_id) or
            !std.mem.eql(
                u8,
                &self.program_descriptor_identity,
                &descriptor.identity,
            ))
        {
            return error.ProgramDescriptorMismatch;
        }
    }
};

pub fn validateBinaryDescriptor(
    descriptor: composition_v3.ProgramDescriptorV3,
    manifest: *const manifest_mod.Manifest,
) Error!void {
    try manifest.validate();
    try descriptor.validate();
    if (descriptor.proof_kind != .binary_node or
        descriptor.manifest_family != .universal_v1 or
        descriptor.claim_policy != .universal_with_zero_tail or
        descriptor.source_claim_count != CLAIM_COUNT or
        descriptor.program_roster_count != CLAIM_COUNT or
        descriptor.poseidon_partial_count != POSEIDON2_PARTIAL_COUNT or
        descriptor.composition_claim_count !=
            composition_v3.COMPOSITION_CLAIM_INPUT_COUNT or
        descriptor.poseidon_roster_row != POSEIDON2_ROSTER_ROW or
        descriptor.manifest_format_version != manifest.format_version or
        !std.mem.eql(u8, &descriptor.manifest_seal, &manifest.seal) or
        !std.mem.allEqual(u8, &descriptor.catalog_identity, 0))
    {
        return error.ProgramDescriptorMismatch;
    }
}

/// Semantic identity of every dynamic verifier-capture field.  This is
/// separate from the canonical proof-byte identity retained by V2.
pub fn captureIdentity(capture: *const OuterProofCapture) Digest {
    var hash = IdentityHasher.init(CAPTURE_ID_DOMAIN);
    hash.addU32(FORMAT_VERSION);
    hash.addUsize(capture.commitments.len);
    for (capture.commitments) |value| hash.digest(value);
    hash.addUsize(capture.column_log_sizes.len);
    for (capture.column_log_sizes) |logs| {
        hash.addUsize(logs.len);
        for (logs) |value| hash.addU32(value);
    }
    hash.addUsize(capture.sampled_points.len);
    for (capture.sampled_points) |columns| {
        hash.addUsize(columns.len);
        for (columns) |points| {
            hash.addUsize(points.len);
            for (points) |point| {
                hash.qm31(point.x);
                hash.qm31(point.y);
            }
        }
    }
    hash.addUsize(capture.sampled_values.len);
    for (capture.sampled_values) |value| hash.qm31(value);
    hash.addUsize(capture.queried_values.len);
    for (capture.queried_values) |value| hash.addU32(value.toU32());
    hash.addUsize(capture.deep_answers.len);
    for (capture.deep_answers) |value| hash.qm31(value);
    hash.addUsize(capture.trace_paths.len);
    for (capture.trace_paths) |paths| {
        hash.addU32(paths.path_depth);
        hash.addUsize(paths.positions.len);
        for (paths.positions) |position| hash.addUsize(position);
        hash.addUsize(paths.siblings.len);
        for (paths.siblings) |value| hash.digest(value);
    }
    hash.addUsize(capture.fri.layers.len);
    for (capture.fri.layers) |layer| {
        hash.digest(layer.commitment);
        hash.qm31(layer.folding_alpha);
        hash.addU32(layer.fold_step);
        hash.addU32(layer.fold_width);
        hash.addU32(layer.path_depth);
        hash.addUsize(layer.query_count);
        hash.addUsize(layer.positions.len);
        for (layer.positions) |position| hash.addUsize(position);
        hash.addUsize(layer.values.len);
        for (layer.values) |value| hash.qm31(value);
        hash.addUsize(layer.siblings.len);
        for (layer.siblings) |value| hash.digest(value);
    }
    hash.addUsize(capture.last_layer_coefficients.len);
    for (capture.last_layer_coefficients) |value| hash.qm31(value);
    hash.addU64(capture.proof_of_work);
    hash.qm31(capture.composition_randomness);
    hash.qm31(capture.oods_seed);
    hash.qm31(capture.deep_randomness);
    hash.addUsize(capture.queries.raw.len);
    for (capture.queries.raw) |position| hash.addUsize(position);
    hash.addUsize(capture.queries.unique.len);
    for (capture.queries.unique) |position| hash.addUsize(position);
    return hash.finalize();
}

pub fn claimedSumsId(value: *const VerifiedBinaryArtifactV3) Digest {
    var hash = IdentityHasher.init(CLAIMS_ID_DOMAIN);
    hash.addU32(FORMAT_VERSION);
    hash.digest(value.publication_id);
    hash.digest(value.capture_id);
    hash.addU32(CLAIM_COUNT);
    for (value.claimed_sums) |claim| hash.qm31(claim);
    return hash.finalize();
}

pub fn relationDrawsId(value: *const VerifiedBinaryArtifactV3) Digest {
    var hash = IdentityHasher.init(RELATIONS_ID_DOMAIN);
    hash.addU32(FORMAT_VERSION);
    hash.digest(value.publication_id);
    hash.digest(value.capture_id);
    hash.addU32(RELATION_DRAW_COUNT);
    for (value.relation_draws) |draw| hash.qm31(draw);
    return hash.finalize();
}

pub fn poseidon2PartialsId(value: *const VerifiedBinaryArtifactV3) Digest {
    var hash = IdentityHasher.init(PARTIALS_ID_DOMAIN);
    hash.addU32(FORMAT_VERSION);
    hash.digest(value.publication_id);
    hash.digest(value.capture_id);
    hash.addU32(POSEIDON2_PARTIAL_COUNT);
    for (value.poseidon2_partials) |partial| hash.qm31(partial);
    return hash.finalize();
}

pub fn artifactId(value: *const VerifiedBinaryArtifactV3) Digest {
    var hash = IdentityHasher.init(ARTIFACT_ID_DOMAIN);
    hash.addU32(value.format_version);
    hash.addU32(value.schema_version);
    hash.addU32(value.claim_count);
    hash.addU32(value.relation_draw_count);
    hash.addU32(value.poseidon2_partial_count);
    hash.digest(value.proof_id);
    hash.digest(value.publication_id);
    hash.digest(value.capture_id);
    hash.digest(value.statement_id);
    hash.digest(value.verification_key_id);
    hash.digest(value.cohort_id);
    hash.digest(value.air_program_id);
    hash.sha(value.cohort_authority_sha_id);
    hash.sha(value.manifest_seal);
    hash.sha(value.program_descriptor_identity);
    hash.digest(value.claimed_sums_id);
    hash.digest(value.relation_draws_id);
    hash.digest(value.poseidon2_partials_id);
    return hash.finalize();
}

pub fn statementId(
    words: *const recursion.span_statement.StatementWords,
) Digest {
    var canonical: [recursion.span_statement.SPAN_STATEMENT_CANONICAL_WORDS]u32 =
        undefined;
    for (words, &canonical) |word, *destination|
        destination.* = word.toU32();
    return protocol.statementId(&canonical);
}

pub fn relationDraws(
    relations: *const universal.UniversalRelations,
) [RELATION_DRAW_COUNT]QM31 {
    var result: [RELATION_DRAW_COUNT]QM31 = undefined;
    for (relations.elements, 0..) |element, index| {
        result[2 * index] = element.z;
        result[2 * index + 1] = element.alpha;
    }
    return result;
}

fn requireDigest(value: Digest) Error!void {
    var aggregate: u32 = 0;
    for (value) |word| {
        if (word >= m31.Modulus) return error.NonCanonicalField;
        aggregate |= word;
    }
    if (aggregate == 0) return error.ArtifactIdentityMismatch;
}

fn requireSha(value: Sha256Digest) Error!void {
    if (std.mem.allEqual(u8, &value, 0))
        return error.ArtifactIdentityMismatch;
}

fn requireCanonical(value: QM31) Error!void {
    for (value.toM31Array()) |word|
        if (word.toU32() >= m31.Modulus) return error.NonCanonicalField;
}

const IdentityHasher = struct {
    inner: channel.CanonicalWordHasher,

    fn init(domain: u32) IdentityHasher {
        return .{ .inner = channel.CanonicalWordHasher.init(domain) };
    }

    fn addU32(self: *IdentityHasher, value: anytype) void {
        const exact: u32 = @intCast(value);
        std.debug.assert(exact < m31.Modulus);
        const words = [_]M31{M31.fromCanonical(exact)};
        self.inner.update(&words);
    }

    fn addU64(self: *IdentityHasher, value: u64) void {
        self.addU32(@as(u32, @truncate(value & 0xffff)));
        self.addU32(@as(u32, @truncate((value >> 16) & 0xffff)));
        self.addU32(@as(u32, @truncate((value >> 32) & 0xffff)));
        self.addU32(@as(u32, @truncate(value >> 48)));
    }

    fn addUsize(self: *IdentityHasher, value: usize) void {
        self.addU64(@intCast(value));
    }

    fn digest(self: *IdentityHasher, value: Digest) void {
        for (value) |word| self.addU32(word);
    }

    fn sha(self: *IdentityHasher, value: Sha256Digest) void {
        var at: usize = 0;
        while (at < value.len) : (at += 3) {
            const remaining = value.len - at;
            var word: u32 = value[at];
            if (remaining > 1) word |= @as(u32, value[at + 1]) << 8;
            if (remaining > 2) word |= @as(u32, value[at + 2]) << 16;
            self.addU32(word);
        }
    }

    fn qm31(self: *IdentityHasher, value: QM31) void {
        for (value.toM31Array()) |word| self.addU32(word.toU32());
    }

    fn finalize(self: *IdentityHasher) Digest {
        return self.inner.finalize();
    }
};

fn assertPointerFree(comptime T: type) void {
    switch (@typeInfo(T)) {
        .pointer, .optional => @compileError("binary V3 artifact retains a pointer"),
        .array => |array| assertPointerFree(array.child),
        .@"struct" => |info| inline for (info.fields) |field|
            assertPointerFree(field.type),
        .@"union" => |info| inline for (info.fields) |field|
            assertPointerFree(field.type),
        else => {},
    }
}

comptime {
    if (FORMAT_VERSION != 3 or SCHEMA_VERSION != 1 or CLAIM_COUNT != 36 or
        RELATION_DRAW_COUNT != 94 or POSEIDON2_PARTIAL_COUNT != 2 or
        POSEIDON2_ROSTER_ROW != 34 or !POINTER_FREE or
        PUBLIC_MINT_CONSTRUCTOR_AVAILABLE or
        HEAP_ALLOCATIONS_PER_PREFLIGHT != 0 or
        CAPTURE_ID_HASHES_PER_PREFLIGHT != 1)
    {
        @compileError("binary V3 verifier-artifact ABI drifted");
    }
    assertPointerFree(VerifiedBinaryArtifactV3);
}

test "binary V3 artifact exposes no detached mint constructor" {
    try std.testing.expect(!@hasDecl(VerifiedBinaryArtifactV3, "init"));
    try std.testing.expect(!@hasDecl(@This(), "mint"));
}
