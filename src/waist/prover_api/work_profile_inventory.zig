//! Versioned typed inventory for exact logical-work producer sites.
//!
//! Runtime expected/completed arrays catch early exits, duplication, and site
//! substitution. The independent Python lexical gate closes source deletion;
//! comments and strings are never an executable authority.

const std = @import("std");

pub const SCHEMA_VERSION: u16 = 9;

pub const Boundary = enum(u3) {
    field_operations = 0,
    column_preparation_fft = 1,
    polynomial_commit_fft = 2,
    secure_composition_fft = 3,
    commitment_tree_merkle = 4,
    streaming_commitment_merkle = 5,
    fri_protocol = 6,
};

pub const Site = enum(u8) {
    column_passthrough_fft = 0,
    column_interpolate_only_fft = 1,
    column_interpolate_for_extension_fft = 2,
    column_extension_fft = 3,
    column_combined_fft = 4,
    polynomial_commit_forward_fft = 5,
    secure_composition_interpolation_fft = 6,
    commitment_tree_merkle = 7,
    streaming_commitment_merkle = 8,
    fri_protocol = 9,
    main_witness_field = 10,
    cold_twiddle_construction = 11,
    sampled_value_coefficient_evaluation = 12,
    sampled_value_barycentric_evaluation = 13,
    oods_seed_to_point = 14,
    oods_mask_points = 15,
    oods_constraint_evaluation = 16,
    sparse_memory_and_guest_poseidon_witness = 17,
    relation_challenges_and_interaction_traces = 18,
    quotient_sample_preparation = 19,
    quotient_row_execution = 20,
    air_composition_on_domain = 21,
    pcs_transcript_shell = 22,
};

pub const SITE_COUNT: usize = @typeInfo(Site).@"enum".fields.len;
pub const SiteCounts = [SITE_COUNT]u64;

pub const Spec = struct {
    site: Site,
    id: []const u8,
    boundary: Boundary,
};

pub const SITES = [_]Spec{
    .{ .site = .column_passthrough_fft, .id = "column-passthrough-fft", .boundary = .column_preparation_fft },
    .{ .site = .column_interpolate_only_fft, .id = "column-interpolate-only-fft", .boundary = .column_preparation_fft },
    .{ .site = .column_interpolate_for_extension_fft, .id = "column-interpolate-for-extension-fft", .boundary = .column_preparation_fft },
    .{ .site = .column_extension_fft, .id = "column-extension-fft", .boundary = .column_preparation_fft },
    .{ .site = .column_combined_fft, .id = "column-combined-fft", .boundary = .column_preparation_fft },
    .{ .site = .polynomial_commit_forward_fft, .id = "polynomial-commit-forward-fft", .boundary = .polynomial_commit_fft },
    .{ .site = .secure_composition_interpolation_fft, .id = "secure-composition-interpolation-fft", .boundary = .secure_composition_fft },
    .{ .site = .commitment_tree_merkle, .id = "commitment-tree-merkle", .boundary = .commitment_tree_merkle },
    .{ .site = .streaming_commitment_merkle, .id = "streaming-commitment-merkle", .boundary = .streaming_commitment_merkle },
    .{ .site = .fri_protocol, .id = "fri-protocol", .boundary = .fri_protocol },
    .{ .site = .main_witness_field, .id = "main-witness-field", .boundary = .field_operations },
    .{ .site = .cold_twiddle_construction, .id = "cold-twiddle-construction", .boundary = .field_operations },
    .{ .site = .sampled_value_coefficient_evaluation, .id = "sampled-value-coefficient-evaluation", .boundary = .field_operations },
    .{ .site = .sampled_value_barycentric_evaluation, .id = "sampled-value-barycentric-evaluation", .boundary = .field_operations },
    .{ .site = .oods_seed_to_point, .id = "oods-seed-to-point", .boundary = .field_operations },
    .{ .site = .oods_mask_points, .id = "oods-mask-points", .boundary = .field_operations },
    .{ .site = .oods_constraint_evaluation, .id = "oods-constraint-evaluation", .boundary = .field_operations },
    .{ .site = .sparse_memory_and_guest_poseidon_witness, .id = "sparse-memory-and-guest-poseidon-witness", .boundary = .field_operations },
    .{ .site = .relation_challenges_and_interaction_traces, .id = "relation-challenges-and-interaction-traces", .boundary = .field_operations },
    .{ .site = .quotient_sample_preparation, .id = "quotient-sample-preparation", .boundary = .field_operations },
    .{ .site = .quotient_row_execution, .id = "quotient-row-execution", .boundary = .field_operations },
    .{ .site = .air_composition_on_domain, .id = "air-composition-on-domain", .boundary = .field_operations },
    .{ .site = .pcs_transcript_shell, .id = "pcs-transcript-shell", .boundary = .field_operations },
};

comptime {
    std.debug.assert(SITES.len == SITE_COUNT);
    for (SITES, 0..) |spec, index|
        std.debug.assert(@intFromEnum(spec.site) == index);
}

/// Compile-time total mapping from executable sites to the stable V2 boundary
/// ABI. The transport remains boundary-aggregated while runtime admission is
/// exact per site.
pub inline fn boundary(site: Site) Boundary {
    return SITES[@intFromEnum(site)].boundary;
}

pub fn zeroSiteCounts() SiteCounts {
    return .{0} ** SITE_COUNT;
}

test "logical work producer site mapping is total and injectively indexed" {
    var seen: u32 = 0;
    for (SITES) |spec| {
        const bit = @as(u32, 1) << @as(u5, @intCast(@intFromEnum(spec.site)));
        try std.testing.expectEqual(@as(u32, 0), seen & bit);
        seen |= bit;
        try std.testing.expectEqual(spec.boundary, boundary(spec.site));
        try std.testing.expect(spec.id.len != 0);
    }
    try std.testing.expectEqual(
        (@as(u32, 1) << @as(u5, @intCast(SITES.len))) - 1,
        seen,
    );
}
