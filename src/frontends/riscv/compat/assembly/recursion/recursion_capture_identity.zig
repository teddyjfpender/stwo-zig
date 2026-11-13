//! Canonical capture-layout and sample-input authority seals; public records remain in the facade.

const Root = @import("recursion_air_composition_capture_layout.zig");
const std = @import("std");
const stwo_core = @import("stwo_core");
const QM31 = stwo_core.fields.qm31.QM31;
const m31 = stwo_core.fields.m31;
const Sha256 = std.crypto.hash.sha2.Sha256;
const LAYOUT_DOMAIN = Root.LAYOUT_DOMAIN;
const INPUT_AUTHORITY_DOMAIN = Root.INPUT_AUTHORITY_DOMAIN;
const CANONICAL_EMPTY_LAYOUT_DOMAIN = Root.CANONICAL_EMPTY_LAYOUT_DOMAIN;
const ProofKind = Root.ProofKind;
const Error = Root.Error;
const CaptureLayoutV3 = Root.CaptureLayoutV3;
const CanonicalEmptyCaptureLayoutV3 = Root.CanonicalEmptyCaptureLayoutV3;
const SampleInputAuthorityV3 = Root.SampleInputAuthorityV3;

pub fn layoutIdentity(layout: *const CaptureLayoutV3) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(LAYOUT_DOMAIN);
    hashInt(&hash, u16, layout.format_version);
    hashInt(&hash, u16, layout.schema_version);
    hashInt(&hash, u8, proofKindCode(layout.proof_kind));
    hashInt(&hash, u8, @intFromEnum(layout.manifest_family));
    hash.update(&layout.manifest_seal);
    hash.update(&layout.catalog_identity);
    hashInt(&hash, u8, layout.component_count);
    hashInt(&hash, u32, layout.sampled_value_count);
    for (layout.tree_column_counts) |count| hashInt(&hash, u32, count);
    for (layout.offsets) |tree| {
        hashInt(&hash, u32, @intCast(tree.len));
        for (tree) |offset| hashInt(&hash, u64, @intCast(offset));
    }
    hashInt(&hash, u32, layout.composition_log_size);
    hashInt(&hash, u32, layout.composition_log_split);
    hashInt(&hash, u32, layout.quotient_max_log_degree_bound);
    hashInt(&hash, u32, layout.fri_log_blowup);
    return hash.finalResult();
}

pub fn canonicalEmptyLayoutIdentity(
    layout: *const CanonicalEmptyCaptureLayoutV3,
) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(CANONICAL_EMPTY_LAYOUT_DOMAIN);
    hashInt(&hash, u16, layout.format_version);
    hashInt(&hash, u16, layout.schema_version);
    hash.update(&layout.manifest_seal);
    hash.update(&layout.binary_geometry_identity);
    hashInt(&hash, u32, layout.source_sample_count);
    hashInt(&hash, u32, layout.internal_sample_count);
    hash.update(&layout.geometry.identity);
    return hash.finalResult();
}

pub fn sampleInputAuthorityIdentity(value: SampleInputAuthorityV3) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(INPUT_AUTHORITY_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hashInt(&hash, u32, value.segment_sample_count);
    hashInt(&hash, u32, value.binary_sample_count);
    hashInt(&hash, u32, value.empty_sample_count);
    hashInt(&hash, u32, value.max_sample_count);
    hash.update(&value.segment_layout_identity);
    hash.update(&value.binary_layout_identity);
    return hash.finalResult();
}

pub fn proofKindCode(kind: ProofKind) u8 {
    return switch (kind) {
        .segment_leaf => 0,
        .binary_node => 1,
        .empty_leaf => 2,
    };
}

pub fn requireCanonical(value: QM31) Error!void {
    for (value.toM31Array()) |word|
        if (word.toU32() >= m31.Modulus) return error.NonCanonicalField;
}

pub fn overlap(left: []const u8, right: []const u8) bool {
    if (left.len == 0 or right.len == 0) return false;
    const left_start = @intFromPtr(left.ptr);
    const right_start = @intFromPtr(right.ptr);
    const left_end = std.math.add(usize, left_start, left.len) catch return true;
    const right_end = std.math.add(usize, right_start, right.len) catch return true;
    return left_start < right_end and right_start < left_end;
}

pub fn hashInt(hash: *Sha256, comptime T: type, value: T) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, value, .little);
    hash.update(&encoded);
}

pub fn allZero(value: []const u8) bool {
    var aggregate: u8 = 0;
    for (value) |byte| aggregate |= byte;
    return aggregate == 0;
}
