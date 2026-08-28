//! Pointer-free transcript-prefix custody for a verified temporal parent.
//!
//! The next recursion level must replay the parent verifier from the zero
//! Poseidon state.  A pre-core checkpoint alone is not sufficient: accepting
//! it as an unconstrained initial state would skip the commitments, manifest,
//! relation challenges, claims, and public wire boundary which produced it.
//! This receipt retains the exact manifest projection and relation draws used
//! by the successful verifier.  Commitments and claims remain in the verifier
//! capture/admission and are deliberately not duplicated here.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const manifest_mod = @import("recursive_temporal_parent_manifest_v3.zig");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const m31 = stwo_core.fields.m31;
const recursion = frontend.recursion;
const channel = recursion.poseidon2_channel;
const global_closure = recursion.binary_global_closure_outer_source;
const universal = recursion.air.universal_challenges;

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 3;
pub const RELATION_DRAW_COUNT: usize = universal.DRAW_COUNT;
pub const CLAIM_COUNT: usize = manifest_mod.COMPONENT_COUNT;
pub const WIRE_BOUNDARY_TRANSCRIPT_DOMAIN: u32 = 0x5457_4231; // "TWB1"

const ID_DOMAIN =
    "stwo-zig/typed-air/recursive-temporal-parent-transcript-prefix/v1\x00";

pub const Error = manifest_mod.Error || universal.Error || error{
    InvalidTranscriptPrefix,
    NonCanonicalField,
};

pub const PrefixV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    roster_count: u8 = CLAIM_COUNT,
    padding: [3]u8 = .{ 0, 0, 0 },
    total_preprocessed_columns: u32,
    total_main_columns: u32,
    total_interaction_columns: u32,
    total_constraints: u32,
    manifest_sha_id: [32]u8,
    prefix_layout_sha_id: [32]u8,
    suffix_source_authority_sha_id: [32]u8,
    registry_order_sha_id: [32]u8,
    interaction_columns: [CLAIM_COUNT]u16,
    relation_draws: [RELATION_DRAW_COUNT]QM31,
    poseidon2_partials: [2]QM31,
    wire_boundary: global_closure.BoundaryEvidenceV2,
    verifier_input_boundary: global_closure.BoundaryEvidenceV2,
    identity: [32]u8,

    pub fn init(
        manifest: *const manifest_mod.Manifest,
        relations: *const universal.UniversalRelations,
        poseidon2_partials: [2]QM31,
        wire_boundary: global_closure.BoundaryEvidenceV2,
        verifier_input_boundary: global_closure.BoundaryEvidenceV2,
    ) Error!PrefixV1 {
        try manifest.validate();
        try relations.validate();
        for (poseidon2_partials) |value| try requireCanonical(value);
        try validateBoundary(wire_boundary);
        try validateBoundary(verifier_input_boundary);
        var interaction_columns: [CLAIM_COUNT]u16 = undefined;
        for (&interaction_columns, 0..) |*destination, row| {
            destination.* = manifest.placements[row].?.geometry.interaction_columns;
        }
        var relation_draws: [RELATION_DRAW_COUNT]QM31 = undefined;
        for (relations.elements, 0..) |element, index| {
            relation_draws[2 * index] = element.z;
            relation_draws[2 * index + 1] = element.alpha;
        }
        var result = PrefixV1{
            .total_preprocessed_columns = manifest.total_preprocessed_columns,
            .total_main_columns = manifest.total_main_columns,
            .total_interaction_columns = manifest.total_interaction_columns,
            .total_constraints = manifest.total_constraints,
            .manifest_sha_id = manifest.seal,
            .prefix_layout_sha_id = manifest.prefix_layout.layout_sha_id,
            .suffix_source_authority_sha_id = manifest.suffix_source_authority_sha_id,
            .registry_order_sha_id = universal.registryOrderDigest(),
            .interaction_columns = interaction_columns,
            .relation_draws = relation_draws,
            .poseidon2_partials = poseidon2_partials,
            .wire_boundary = wire_boundary,
            .verifier_input_boundary = verifier_input_boundary,
            .identity = undefined,
        };
        result.identity = prefixIdentity(&result);
        try result.validate();
        return result;
    }

    pub fn validate(self: *const PrefixV1) Error!void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.roster_count != CLAIM_COUNT or
            !std.mem.allEqual(u8, &self.padding, 0) or
            self.total_preprocessed_columns == 0 or
            self.total_main_columns == 0 or
            self.total_interaction_columns == 0 or
            self.total_constraints == 0 or
            std.mem.allEqual(u8, &self.manifest_sha_id, 0) or
            std.mem.allEqual(u8, &self.prefix_layout_sha_id, 0) or
            std.mem.allEqual(u8, &self.suffix_source_authority_sha_id, 0) or
            !std.mem.eql(
                u8,
                &self.registry_order_sha_id,
                &universal.registryOrderDigest(),
            ))
        {
            return error.InvalidTranscriptPrefix;
        }
        for (self.interaction_columns) |count|
            if (count == 0) return error.InvalidTranscriptPrefix;
        for (self.relation_draws) |value| try requireCanonical(value);
        for (self.poseidon2_partials) |value| try requireCanonical(value);
        const relations = universal.UniversalRelations.fromDraws(
            &self.relation_draws,
        );
        try relations.validate();
        try validateBoundary(self.wire_boundary);
        try validateBoundary(self.verifier_input_boundary);
        if (!std.mem.eql(u8, &self.identity, &prefixIdentity(self)))
            return error.InvalidTranscriptPrefix;
    }

    pub fn validateAgainst(
        self: *const PrefixV1,
        manifest: *const manifest_mod.Manifest,
        relations: *const universal.UniversalRelations,
        poseidon2_partials: [2]QM31,
        wire_boundary: global_closure.BoundaryEvidenceV2,
        verifier_input_boundary: global_closure.BoundaryEvidenceV2,
    ) Error!void {
        const expected = try PrefixV1.init(
            manifest,
            relations,
            poseidon2_partials,
            wire_boundary,
            verifier_input_boundary,
        );
        if (!std.meta.eql(self.*, expected))
            return error.InvalidTranscriptPrefix;
    }

    /// Exact `Manifest.mixStatementPrefix` projection retained without the
    /// large placement table.
    pub fn mixManifestPrefix(self: *const PrefixV1, transcript: anytype) Error!void {
        try self.validate();
        transcript.mixU32s(&.{
            manifest_mod.TRANSCRIPT_DOMAIN,
            manifest_mod.TRANSCRIPT_FORMAT_VERSION,
            self.roster_count,
            self.total_preprocessed_columns,
            self.total_main_columns,
            self.total_interaction_columns,
            self.total_constraints,
        });
        transcript.mixU32s(&digestWords(self.manifest_sha_id));
        transcript.mixU32s(&digestWords(self.prefix_layout_sha_id));
        transcript.mixU32s(&digestWords(self.suffix_source_authority_sha_id));
        transcript.mixU32s(&digestWords(self.registry_order_sha_id));
    }

    pub fn mixWireBoundary(self: *const PrefixV1, transcript: anytype) Error!void {
        try self.validate();
        try mixWireBoundaryEvidence(transcript, self.wire_boundary);
    }
};

/// Parent-specific transcript binding for the independently audited public
/// wire boundary.  It deliberately mirrors the SegmentV2 boundary position:
/// after interaction claims and before the interaction-tree commitment.
pub fn mixWireBoundaryEvidence(
    transcript: anytype,
    evidence: global_closure.BoundaryEvidenceV2,
) Error!void {
    try validateBoundary(evidence);
    transcript.mixU32s(&.{
        WIRE_BOUNDARY_TRANSCRIPT_DOMAIN,
        FORMAT_VERSION,
        evidence.tuple_count,
    });
    transcript.mixU32s(&digestWords(evidence.source_authority_id));
    transcript.mixU32s(&digestWords(evidence.snapshot_id));
    transcript.mixU32s(&digestWords(evidence.tuple_provenance_id));
    transcript.mixFelts(&.{evidence.claimed_sum});
}

fn validateBoundary(evidence: global_closure.BoundaryEvidenceV2) Error!void {
    if (evidence.tuple_count == 0 or
        std.mem.allEqual(u8, &evidence.source_authority_id, 0) or
        std.mem.allEqual(u8, &evidence.snapshot_id, 0) or
        std.mem.allEqual(u8, &evidence.tuple_provenance_id, 0))
    {
        return error.InvalidTranscriptPrefix;
    }
    try requireCanonical(evidence.claimed_sum);
}

fn prefixIdentity(value: *const PrefixV1) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(ID_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hashInt(&hash, u8, value.roster_count);
    hash.update(&value.padding);
    hashInt(&hash, u32, value.total_preprocessed_columns);
    hashInt(&hash, u32, value.total_main_columns);
    hashInt(&hash, u32, value.total_interaction_columns);
    hashInt(&hash, u32, value.total_constraints);
    hash.update(&value.manifest_sha_id);
    hash.update(&value.prefix_layout_sha_id);
    hash.update(&value.suffix_source_authority_sha_id);
    hash.update(&value.registry_order_sha_id);
    for (value.interaction_columns) |count| hashInt(&hash, u16, count);
    for (value.relation_draws) |item| hashQm31(&hash, item);
    for (value.poseidon2_partials) |item| hashQm31(&hash, item);
    hash.update(&value.wire_boundary.source_authority_id);
    hash.update(&value.wire_boundary.snapshot_id);
    hash.update(&value.wire_boundary.tuple_provenance_id);
    hashInt(&hash, u32, value.wire_boundary.tuple_count);
    hashQm31(&hash, value.wire_boundary.claimed_sum);
    hash.update(&value.verifier_input_boundary.source_authority_id);
    hash.update(&value.verifier_input_boundary.snapshot_id);
    hash.update(&value.verifier_input_boundary.tuple_provenance_id);
    hashInt(&hash, u32, value.verifier_input_boundary.tuple_count);
    hashQm31(&hash, value.verifier_input_boundary.claimed_sum);
    return hash.finalResult();
}

pub fn digestWords(value: [32]u8) [8]u32 {
    var result: [8]u32 = undefined;
    for (&result, 0..) |*word, index| word.* = std.mem.readInt(
        u32,
        value[index * 4 ..][0..4],
        .little,
    );
    return result;
}

fn requireCanonical(value: QM31) Error!void {
    for (value.toM31Array()) |word|
        if (word.toU32() >= m31.Modulus) return error.NonCanonicalField;
}

fn hashQm31(hash: anytype, value: QM31) void {
    for (value.toM31Array()) |word| hashInt(hash, u32, word.toU32());
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

comptime {
    if (CLAIM_COUNT != 36 or RELATION_DRAW_COUNT != 94)
        @compileError("temporal parent transcript prefix geometry drifted");
}
