//! Stable arena slot identities for one Native CUDA Native Poseidon proof.

const std = @import("std");
const arena = @import("stwo_cuda_backend").runtime.arena;
const geometry_mod = @import("geometry.zig");

pub const SlotId = arena.SlotId;

pub const twiddles_forward: SlotId = 0x0100;
pub const twiddles_inverse: SlotId = 0x0101;
pub const transcript_state: SlotId = 0x0110;
pub const transcript_input_snapshot: SlotId = 0x0112;
pub const transcript_output_snapshot: SlotId = 0x0113;
pub const transcript_boundary_snapshot: SlotId = 0x0114;
pub const transcript_static_inputs: SlotId = 0x0115;

pub const main_coefficients: SlotId = 0x0201;
pub const interaction_coefficients: SlotId = 0x0202;
pub const composition_coefficients: SlotId = 0x0203;
/// The 2N commitment-domain evaluations in canonical tree-column order.
pub const source_evaluations: SlotId = 0x0204;
/// The independent 4N source domain consumed by the exact AIR kernel.
pub const constraint_source_evaluations: SlotId = 0x0205;
pub const coefficient_log_sizes: SlotId = 0x0206;
pub const main_merkle_hashes: SlotId = 0x0220;
pub const interaction_merkle_hashes: SlotId = 0x0221;
pub const composition_merkle_hashes: SlotId = 0x0222;
pub const main_merkle_layers: SlotId = 0x0223;
pub const interaction_merkle_layers: SlotId = 0x0224;
pub const composition_merkle_layers: SlotId = 0x0225;

pub const composition_powers: SlotId = 0x0303;
pub const constraint_denominator_inverses: SlotId = 0x0304;
pub const composition_coordinates: SlotId = 0x0305;
pub const composition_challenge: SlotId = 0x0306;
pub const lookup_elements: SlotId = 0x0310;
pub const relation_alpha_powers: SlotId = 0x0311;
pub const relation_z: SlotId = 0x0312;
pub const relation_source_values: SlotId = 0x0313;
pub const relation_source_tables: SlotId = 0x0314;
pub const relation_descriptor_tables: SlotId = 0x0315;
pub const relation_output_tables: SlotId = 0x0316;
pub const relation_denominator_tables: SlotId = 0x0317;
pub const relation_geometry: SlotId = 0x0318;
pub const relation_claimed_sum_tables: SlotId = 0x0319;
pub const relation_source_pointer_table: SlotId = 0x031a;
pub const relation_descriptors: SlotId = 0x031b;
pub const relation_output_pointer_table: SlotId = 0x031c;
pub const relation_denominator_slab: SlotId = 0x031d;
pub const relation_claimed_sum: SlotId = 0x031e;
pub const relation_reduction_partials: SlotId = 0x031f;
pub const relation_scan_block_sums: SlotId = 0x0320;

pub const oods_parameter: SlotId = 0x0400;
pub const oods_offset_points: SlotId = 0x0401;
pub const oods_fold_counts: SlotId = 0x0402;
pub const oods_output_indices: SlotId = 0x0403;
pub const oods_sample_points: SlotId = 0x0404;
pub const oods_evaluation_points: SlotId = 0x0405;
pub const oods_folding_factors: SlotId = 0x0406;
pub const oods_reduce_a: SlotId = 0x0407;
pub const oods_reduce_b: SlotId = 0x0408;
pub const sampled_values: SlotId = 0x0409;

pub const quotient_challenge: SlotId = 0x0500;
pub const quotient_prepared_terms: SlotId = 0x0501;
pub const quotient_group_offsets: SlotId = 0x0502;
pub const quotient_group_term_indices: SlotId = 0x0503;
pub const quotient_batch_terms: SlotId = 0x0505;
pub const quotient_group_log_sizes: SlotId = 0x0506;
pub const quotient_partial_log_sizes: SlotId = 0x0507;
pub const quotient_term_points: SlotId = 0x0508;
pub const quotient_line_coefficients: SlotId = 0x0509;
pub const quotient_group_points: SlotId = 0x050a;
pub const quotient_first_linear_terms: SlotId = 0x050b;
pub const quotient_partial_coordinates: SlotId = 0x050c;
/// The quotient result is the first committed FRI coordinate slab.
pub const quotient_coordinates: SlotId = 0x1000;

pub const fri_alpha: SlotId = 0x0600;
pub const fri_last_coefficients: SlotId = 0x0601;
pub const fri_last_degree_error: SlotId = 0x0602;
pub const fri_last_transcript: SlotId = 0x0603;
pub const fri_last_evaluation: SlotId = 0x0604;

pub const pow_prefix_digest: SlotId = 0x0700;
pub const pow_best_nonce: SlotId = 0x0701;
pub const pow_completed_blocks: SlotId = 0x0702;
pub const pow_transcript_nonce: SlotId = 0x0703;

pub const raw_queries: SlotId = 0x0800;
pub const unique_queries: SlotId = 0x0801;
pub const decommit_mapped_queries: SlotId = 0x0802;
pub const decommit_walk_queries: SlotId = 0x0803;
pub const decommit_walk_scratch: SlotId = 0x0804;
pub const decommit_leaf_indices: SlotId = 0x0805;
pub const decommit_expanded_positions: SlotId = 0x0806;
pub const decommit_sparse_indices: SlotId = 0x0807;
pub const decommit_sparse_hashes: SlotId = 0x0808;
pub const decommit_counts: SlotId = 0x0809;
pub const decommit_sparse_level_offsets: SlotId = 0x080a;
pub const decommit_sparse_level_counts: SlotId = 0x080b;
pub const main_column_log_sizes: SlotId = 0x080c;
pub const interaction_column_log_sizes: SlotId = 0x080d;
pub const composition_column_log_sizes: SlotId = 0x080e;
pub const proof_bundle: SlotId = 0x08ff;

const fri_coordinates_base: SlotId = 0x1000;
const fri_hashes_base: SlotId = 0x1100;
const fri_layers_base: SlotId = 0x1200;

pub fn friCoordinates(index: usize) SlotId {
    std.debug.assert(index < geometry_mod.max_log_n_rows);
    return fri_coordinates_base + @as(SlotId, @intCast(index));
}

pub fn friMerkleHashes(index: usize) SlotId {
    std.debug.assert(index < geometry_mod.max_log_n_rows);
    return fri_hashes_base + @as(SlotId, @intCast(index));
}

pub fn friMerkleLayers(index: usize) SlotId {
    std.debug.assert(index < geometry_mod.max_log_n_rows);
    return fri_layers_base + @as(SlotId, @intCast(index));
}

test "stable slot families are disjoint across the maximum admitted FRI depth" {
    var seen: [geometry_mod.max_log_n_rows * 3]SlotId = undefined;
    for (0..geometry_mod.max_log_n_rows) |index| {
        seen[index] = friCoordinates(index);
        seen[geometry_mod.max_log_n_rows + index] = friMerkleHashes(index);
        seen[geometry_mod.max_log_n_rows * 2 + index] = friMerkleLayers(index);
    }
    for (seen, 0..) |id, index| {
        try std.testing.expect(id != proof_bundle);
        for (seen[0..index]) |previous| try std.testing.expect(id != previous);
    }
}
