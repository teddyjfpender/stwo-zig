//! Stable arena slot identities for one exact resident CUDA Blake proof.

const arena = @import("../../../../backends/cuda/runtime/arena.zig");

pub const SlotId = arena.SlotId;

pub const twiddles_forward: SlotId = 0x2100;
pub const twiddles_inverse: SlotId = 0x2101;
pub const transcript_state: SlotId = 0x2110;
pub const relation_elements: SlotId = 0x2111;
pub const statement1_claims: SlotId = 0x2112;
pub const composition_challenge: SlotId = 0x2113;
pub const interaction_denominators: SlotId = 0x2120;
pub const interaction_batch_prefix: SlotId = 0x2121;
pub const interaction_output_pointer_table: SlotId = 0x2122;
pub const interaction_output_tables: SlotId = 0x2123;
pub const interaction_denominator_tables: SlotId = 0x2124;
pub const interaction_claim_tables: SlotId = 0x2125;
pub const interaction_geometry: SlotId = 0x2126;
pub const interaction_reduction_partials: SlotId = 0x2127;
pub const interaction_scan_block_sums: SlotId = 0x2128;
/// Reused across the four trace-tree commits; 24 words per lifted leaf.
pub const commitment_states: SlotId = 0x2129;

pub const preprocessed_evaluations: SlotId = 0x2200;
pub const preprocessed_coefficients: SlotId = 0x2201;
pub const preprocessed_lde: SlotId = 0x2202;
pub const preprocessed_hashes: SlotId = 0x2203;
pub const preprocessed_layers: SlotId = 0x2204;

pub const main_evaluations: SlotId = 0x2210;
pub const main_coefficients: SlotId = 0x2211;
pub const main_lde: SlotId = 0x2212;
pub const main_hashes: SlotId = 0x2213;
pub const main_layers: SlotId = 0x2214;
/// Immutable preprocessed+main witness emitted by the exact witness AOT.
pub const relation_sources: SlotId = 0x2215;

pub const interaction_evaluations: SlotId = 0x2220;
pub const interaction_coefficients: SlotId = 0x2221;
pub const interaction_lde: SlotId = 0x2222;
pub const interaction_hashes: SlotId = 0x2223;
pub const interaction_layers: SlotId = 0x2224;

pub const composition_evaluations: SlotId = 0x2230;
pub const composition_coefficients: SlotId = 0x2231;
pub const composition_lde: SlotId = 0x2232;
pub const composition_hashes: SlotId = 0x2233;
pub const composition_layers: SlotId = 0x2234;

pub const constraint_random_powers: SlotId = 0x2300;
pub const constraint_denominator_inverses: SlotId = 0x2301;
pub const constraint_component_partials: SlotId = 0x2302;

pub const oods_parameter: SlotId = 0x2400;
pub const oods_points: SlotId = 0x2401;
pub const oods_fold_counts: SlotId = 0x2402;
pub const oods_output_indices: SlotId = 0x2403;
pub const oods_scratch_a: SlotId = 0x2404;
pub const oods_scratch_b: SlotId = 0x2405;
pub const sampled_values: SlotId = 0x2406;

pub const quotient_challenge: SlotId = 0x2500;
pub const quotient_descriptors: SlotId = 0x2501;
pub const quotient_term_points: SlotId = 0x2502;
pub const quotient_line_coefficients: SlotId = 0x2503;
pub const quotient_partials: SlotId = 0x2504;
pub const quotient_coordinates: SlotId = 0x2505;

pub const pow_nonce: SlotId = 0x2700;
pub const raw_queries: SlotId = 0x2800;
pub const decommit_scratch: SlotId = 0x2801;
pub const proof_bundle: SlotId = 0x28ff;

const fri_coordinates_base: SlotId = 0x3000;
const fri_hashes_base: SlotId = 0x3100;
const fri_layers_base: SlotId = 0x3200;
const max_fri_trees: usize = 64;

pub fn friCoordinates(index: usize) SlotId {
    std.debug.assert(index < max_fri_trees);
    return fri_coordinates_base + @as(SlotId, @intCast(index));
}

pub fn friHashes(index: usize) SlotId {
    std.debug.assert(index < max_fri_trees);
    return fri_hashes_base + @as(SlotId, @intCast(index));
}

pub fn friLayers(index: usize) SlotId {
    std.debug.assert(index < max_fri_trees);
    return fri_layers_base + @as(SlotId, @intCast(index));
}

const std = @import("std");

test "exact Blake dynamic FRI slot families are disjoint" {
    for (0..max_fri_trees) |index| {
        try std.testing.expect(friCoordinates(index) != friHashes(index));
        try std.testing.expect(friCoordinates(index) != friLayers(index));
        try std.testing.expect(friHashes(index) != friLayers(index));
        try std.testing.expect(friCoordinates(index) != proof_bundle);
    }
}
