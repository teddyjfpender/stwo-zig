//! Admission manifest for a verified *local V2* outer proof of a V3 leaf.
//!
//! This host bridge does not prove the 64-bit global position. It may stage a
//! genuinely verified 39-row V2 outer proof for a future V3 wrapper, but can
//! never publish a V3 recursive root or parent-ready child.
const std = @import("std");
const channel = @import("poseidon2_channel.zig");
const metadata_mod = @import("segment_leaf_local_authority_v3.zig");
const link_mod = @import("segment_leaf_local_verified_link_v3.zig");
const projection = @import("segment_leaf_local_projection_v3.zig");
const publication_mod = @import("segment_verified_publication_v2.zig");
const public_data = @import("../air/public_data_v2.zig");
const receipt_mod = @import("../air/statement_v2.zig");
const M31 = @import("stwo_core").fields.m31.M31;

pub const FORMAT_VERSION: u16 = 3;
pub const SCHEMA_VERSION: u16 = 1;
pub const ID_DOMAIN: u32 = 0x5354_4733; // "STG3"
pub const LOCAL_V2_OUTER_COMPONENT_COUNT: u8 =
    @intCast(@import("air/segment_outer_adapter_manifest_v2.zig").COMPONENT_COUNT);
pub const GLOBAL_POSITION_RECURSIVELY_PROVEN = false;
pub const V3_RECURSIVE_PUBLICATION_AVAILABLE = false;

comptime {
    if (LOCAL_V2_OUTER_COMPONENT_COUNT != 39)
        @compileError("V3 staged outer manifest must be reviewed after V2 roster changes");
}

pub const StageManifestV3 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    local_outer_component_count: u8 = LOCAL_V2_OUTER_COMPONENT_COUNT,
    global_position_recursively_proven: bool = false,
    metadata_id: channel.Digest,
    link_id: channel.Digest,
    local_wire_id: channel.Digest,
    local_receipt_id: channel.Digest,
    outer_publication_id: channel.Digest,
    outer_proof_id: channel.Digest,
    segment_index: u32,
    segment_count: u32,
    global_cycle_start: u64,
    global_cycle_end: u64,
    local_cycle_count: u32,
    identity: channel.Digest,

    pub fn init(
        metadata: *const metadata_mod.MetadataV3,
        link: *const link_mod.VerifiedLinkV3,
        local: *const public_data.PublicDataV2,
        receipt: *const receipt_mod.VerifiedReceipt,
        outer: *const publication_mod.VerifiedSegmentV2PublicationV1,
    ) !StageManifestV3 {
        try metadata.validate();
        try link.validateAgainst(metadata, local, receipt);
        try outer.validate();
        const projected = try projection.localStatementFromMetadata(metadata);
        const projected_words = try projected.canonicalWords();
        if (!std.meta.eql(outer.statement_words, projected_words) or
            !std.meta.eql(outer.segment_wire_id, receipt.wire_id) or
            !std.meta.eql(outer.session_id, receipt.session_id) or
            !std.meta.eql(outer.job_id, receipt.job_id) or
            !std.meta.eql(outer.position_id, receipt.position_id) or
            !std.meta.eql(outer.lineage_id, receipt.lineage_id) or
            outer.segment_index != metadata.segment_index or
            outer.segment_count != metadata.segment_count or
            outer.global_cycle_start != 0 or
            outer.global_cycle_end != metadata.local_cycle_count or
            outer.entry_continuation_root != metadata.entry.continuation_root or
            outer.exit_continuation_root != metadata.exit.continuation_root)
        {
            return error.LocalOuterPublicationMismatch;
        }
        var result = StageManifestV3{
            .metadata_id = link.global_metadata_id,
            .link_id = link.identity,
            .local_wire_id = receipt.wire_id,
            .local_receipt_id = receipt.identity,
            .outer_publication_id = outer.publication_id,
            .outer_proof_id = outer.proof_id,
            .segment_index = metadata.segment_index,
            .segment_count = metadata.segment_count,
            .global_cycle_start = metadata.global_cycle_start,
            .global_cycle_end = metadata.global_cycle_end,
            .local_cycle_count = metadata.local_cycle_count,
            .identity = undefined,
        };
        result.identity = stageIdentity(&result);
        return result;
    }

    pub fn validateAgainst(
        self: *const StageManifestV3,
        metadata: *const metadata_mod.MetadataV3,
        link: *const link_mod.VerifiedLinkV3,
        local: *const public_data.PublicDataV2,
        receipt: *const receipt_mod.VerifiedReceipt,
        outer: *const publication_mod.VerifiedSegmentV2PublicationV1,
    ) !void {
        const expected = try StageManifestV3.init(metadata, link, local, receipt, outer);
        if (!std.meta.eql(self.*, expected)) return error.InvalidV3StageManifest;
    }

    pub fn requireRecursiveV3Publication(_: *const StageManifestV3) error{V3WrapperProofUnavailable}!void {
        return error.V3WrapperProofUnavailable;
    }
};

fn stageIdentity(value: *const StageManifestV3) channel.Digest {
    var words: [66]M31 = undefined;
    var at: usize = 0;
    put(&words, &at, value.format_version);
    put(&words, &at, value.schema_version);
    put(&words, &at, value.local_outer_component_count);
    put(&words, &at, @intFromBool(value.global_position_recursively_proven));
    inline for (.{
        value.metadata_id,
        value.link_id,
        value.local_wire_id,
        value.local_receipt_id,
        value.outer_publication_id,
        value.outer_proof_id,
    }) |digest| for (digest) |word| put(&words, &at, word);
    putU32(&words, &at, value.segment_index);
    putU32(&words, &at, value.segment_count);
    putU64(&words, &at, value.global_cycle_start);
    putU64(&words, &at, value.global_cycle_end);
    putU32(&words, &at, value.local_cycle_count);
    std.debug.assert(at == words.len);
    return channel.hashCanonicalWords(&words, ID_DOMAIN);
}

fn put(words: []M31, at: *usize, value: u32) void {
    words[at.*] = M31.fromCanonical(value);
    at.* += 1;
}
fn putU32(words: []M31, at: *usize, value: u32) void {
    put(words, at, value & 0xffff);
    put(words, at, value >> 16);
}
fn putU64(words: []M31, at: *usize, value: u64) void {
    inline for (0..4) |i| put(words, at, @intCast((value >> (16 * i)) & 0xffff));
}

test "V3 stage identity is domain separated and cannot be promoted" {
    const zero: channel.Digest = .{0} ** channel.RATE;
    var stage = StageManifestV3{
        .metadata_id = zero,
        .link_id = zero,
        .local_wire_id = zero,
        .local_receipt_id = zero,
        .outer_publication_id = zero,
        .outer_proof_id = zero,
        .segment_index = 1,
        .segment_count = 2,
        .global_cycle_start = 0x1_0000_0000,
        .global_cycle_end = 0x1_0000_0001,
        .local_cycle_count = 1,
        .identity = undefined,
    };
    stage.identity = stageIdentity(&stage);
    var shifted = stage;
    shifted.global_cycle_start += 1;
    try std.testing.expect(!std.meta.eql(stage.identity, stageIdentity(&shifted)));
    try std.testing.expectError(error.V3WrapperProofUnavailable, stage.requireRecursiveV3Publication());
}
