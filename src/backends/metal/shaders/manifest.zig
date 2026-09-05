const std = @import("std");

pub const core_shader_abi: u32 = 22;
pub const witness_codegen_support_version: u64 = 6;

pub const CompileProfile = struct {
    sdk: []const u8,
    language_standard: []const u8,
    math_mode: []const u8,
    warnings_as_errors: bool,
};

pub const compile_profile: CompileProfile = .{
    .sdk = "macosx",
    .language_standard = "metal3.1",
    .math_mode = "safe",
    .warnings_as_errors = true,
};

pub const Unit = enum {
    transcript,
    commitments,
    cairo_trace,
    cairo_witness_feed,
    cairo_fixed_tables,
    cairo_ec_op,
    circle_transform,
    composition,
    relation,
    compaction,
    quotient,
    fri,
    decommit,
    polynomial_eval,
    riscv_polynomials,
    arena_ops,
    trace_generation,
};

pub const Export = struct {
    name: []const u8,
    owner: Unit,
};

/// The logical owner map is authoritative even while unmoved kernels remain in
/// the legacy translation unit during the staged migration.
pub const exports = [_]Export{
    .{ .name = "stwo_zig_quadratic_recurrence_trace", .owner = .trace_generation },
    .{ .name = "stwo_zig_transcript_init_resident", .owner = .transcript },
    .{ .name = "stwo_zig_transcript_mix_resident", .owner = .transcript },
    .{ .name = "stwo_zig_poseidon2_channel_pow_search", .owner = .transcript },
    .{ .name = "stwo_zig_transcript_draw_secure_resident", .owner = .transcript },
    .{ .name = "stwo_zig_transcript_draw_queries_resident", .owner = .transcript },
    .{ .name = "stwo_zig_blake2s_leaves", .owner = .commitments },
    .{ .name = "stwo_zig_blake2s_pow_search", .owner = .commitments },
    .{ .name = "stwo_zig_blake2s_leaf_absorb_resident", .owner = .commitments },
    .{ .name = "stwo_zig_blake2s_leaf_absorb_compact_resident", .owner = .commitments },
    .{ .name = "stwo_zig_blake2s_parents", .owner = .commitments },
    .{ .name = "stwo_zig_blake2s_parents_sparse", .owner = .commitments },
    .{ .name = "stwo_zig_blake2s_parent_tail_sparse", .owner = .commitments },
    .{ .name = "stwo_zig_blake2s_parents_plain_sparse", .owner = .commitments },
    .{ .name = "stwo_zig_poseidon2_m31_leaves", .owner = .commitments },
    .{ .name = "stwo_zig_poseidon2_m31_leaves_wide", .owner = .commitments },
    .{ .name = "stwo_zig_poseidon2_m31_leaf_absorb_resident", .owner = .commitments },
    .{ .name = "stwo_zig_poseidon2_m31_leaf_absorb_compact_resident", .owner = .commitments },
    .{ .name = "stwo_zig_poseidon2_m31_leaf_state_digest_resident_v1", .owner = .commitments },
    .{ .name = "stwo_zig_poseidon2_m31_parents", .owner = .commitments },
    .{ .name = "stwo_zig_poseidon2_m31_parents_sparse", .owner = .commitments },
    .{ .name = "stwo_zig_poseidon2_m31_parent_tail_sparse", .owner = .commitments },
    .{ .name = "stwo_zig_witness_input_gather_resident", .owner = .cairo_trace },
    .{ .name = "stwo_zig_execution_table_split_resident", .owner = .cairo_trace },
    .{ .name = "stwo_zig_memory_address_base_trace_resident", .owner = .cairo_trace },
    .{ .name = "stwo_zig_memory_value_base_trace_resident", .owner = .cairo_trace },
    .{ .name = "stwo_zig_memory_rc99_count_resident", .owner = .cairo_trace },
    .{ .name = "stwo_zig_public_memory_seed_resident", .owner = .cairo_trace },
    .{ .name = "stwo_zig_felt252_oracle", .owner = .cairo_ec_op },
    .{ .name = "stwo_zig_ec_op_lookup", .owner = .cairo_ec_op },
    .{ .name = "stwo_zig_ec_op_witness", .owner = .cairo_ec_op },
    .{ .name = "stwo_zig_ec_op_base_finalize", .owner = .cairo_ec_op },
    .{ .name = "stwo_zig_circle_ifft_first", .owner = .circle_transform },
    .{ .name = "stwo_zig_circle_ifft_layer", .owner = .circle_transform },
    .{ .name = "stwo_zig_circle_rfft_layer", .owner = .circle_transform },
    .{ .name = "stwo_zig_circle_rfft_last", .owner = .circle_transform },
    .{ .name = "stwo_zig_circle_rescale", .owner = .circle_transform },
    .{ .name = "stwo_zig_circle_expand_coefficients", .owner = .circle_transform },
    .{ .name = "stwo_zig_circle_expand_sparse", .owner = .circle_transform },
    .{ .name = "stwo_zig_composition_expand_sparse", .owner = .composition },
    .{ .name = "stwo_zig_circle_copy_sparse", .owner = .circle_transform },
    .{ .name = "stwo_zig_circle_ifft_first_sparse", .owner = .circle_transform },
    .{ .name = "stwo_zig_circle_ifft_layer_sparse", .owner = .circle_transform },
    .{ .name = "stwo_zig_circle_rescale_sparse", .owner = .circle_transform },
    .{ .name = "stwo_zig_fixed_table_lookup_sparse", .owner = .cairo_fixed_tables },
    .{ .name = "stwo_zig_circle_rfft_layer_sparse", .owner = .circle_transform },
    .{ .name = "stwo_zig_circle_rfft_radix4_sparse", .owner = .circle_transform },
    .{ .name = "stwo_zig_circle_rfft_last_sparse", .owner = .circle_transform },
    .{ .name = "stwo_zig_circle_rfft_layer_sparse_wide", .owner = .circle_transform },
    .{ .name = "stwo_zig_circle_rfft_last_sparse_wide", .owner = .circle_transform },
    .{ .name = "stwo_zig_composition_lift_accumulate", .owner = .composition },
    .{ .name = "stwo_zig_composition_split_coordinates", .owner = .composition },
    .{ .name = "stwo_zig_composition_random_powers", .owner = .composition },
    .{ .name = "stwo_zig_composition_ext_params", .owner = .composition },
    .{ .name = "stwo_zig_circle_ifft_fused_tail", .owner = .circle_transform },
    .{ .name = "stwo_zig_circle_ifft_fused_tail_wide", .owner = .circle_transform },
    .{ .name = "stwo_zig_quadratic_recurrence_ifft_fused_wide", .owner = .circle_transform },
    .{ .name = "stwo_zig_circle_rfft_fused_tail", .owner = .circle_transform },
    .{ .name = "stwo_zig_circle_rfft_fused_tail_sparse", .owner = .circle_transform },
    .{ .name = "stwo_zig_circle_rfft_fused_tail_sparse_wide", .owner = .circle_transform },
    .{ .name = "stwo_zig_relation_fused", .owner = .relation },
    .{ .name = "stwo_zig_relation_block_scan", .owner = .relation },
    .{ .name = "stwo_zig_relation_scan_blocks", .owner = .relation },
    .{ .name = "stwo_zig_relation_scan_finalize", .owner = .relation },
    .{ .name = "stwo_zig_witness_feed_counts", .owner = .cairo_witness_feed },
    .{ .name = "stwo_zig_clear_arena_spans", .owner = .arena_ops },
    .{ .name = "stwo_zig_compact_gather", .owner = .compaction },
    .{ .name = "stwo_zig_compact_radix_histogram", .owner = .compaction },
    .{ .name = "stwo_zig_compact_radix_prefix", .owner = .compaction },
    .{ .name = "stwo_zig_compact_radix_scatter", .owner = .compaction },
    .{ .name = "stwo_zig_compact_heads", .owner = .compaction },
    .{ .name = "stwo_zig_compact_scan_local", .owner = .compaction },
    .{ .name = "stwo_zig_compact_scan_blocks", .owner = .compaction },
    .{ .name = "stwo_zig_compact_scan_add", .owner = .compaction },
    .{ .name = "stwo_zig_compact_clear_outputs", .owner = .compaction },
    .{ .name = "stwo_zig_compact_scatter", .owner = .compaction },
    .{ .name = "stwo_zig_compact_finalize", .owner = .compaction },
    .{ .name = "stwo_zig_fri_fold_circle", .owner = .fri },
    .{ .name = "stwo_zig_fri_fold_line", .owner = .fri },
    .{ .name = "stwo_zig_qm31_to_coordinates", .owner = .quotient },
    .{ .name = "stwo_zig_quotient_rows", .owner = .quotient },
    .{ .name = "stwo_zig_quotient_rows_raw", .owner = .quotient },
    .{ .name = "stwo_zig_quotient_partials_raw", .owner = .quotient },
    .{ .name = "stwo_zig_quotient_combine_partials_raw", .owner = .quotient },
    .{ .name = "stwo_zig_quotient_numerator_raw", .owner = .quotient },
    .{ .name = "stwo_zig_quotient_finalize", .owner = .quotient },
    .{ .name = "stwo_zig_quotient_coefficients_resident", .owner = .quotient },
    .{ .name = "stwo_zig_quotient_domain_points_resident", .owner = .quotient },
    .{ .name = "stwo_zig_quotient_denominators_resident", .owner = .quotient },
    .{ .name = "stwo_zig_quotient_combine_resident", .owner = .quotient },
    .{ .name = "stwo_zig_fri_fold3_resident", .owner = .fri },
    .{ .name = "stwo_zig_fri_fold2_resident", .owner = .fri },
    .{ .name = "stwo_zig_fri_packed_leaves_resident", .owner = .fri },
    .{ .name = "stwo_zig_poseidon2_m31_fri_packed_leaves_resident", .owner = .fri },
    .{ .name = "stwo_zig_fri_final_line_resident", .owner = .fri },
    .{ .name = "stwo_zig_decommit_normalize_queries_resident", .owner = .decommit },
    .{ .name = "stwo_zig_decommit_prepare_fri_queries_resident", .owner = .decommit },
    .{ .name = "stwo_zig_decommit_prepare_trace_queries_resident", .owner = .decommit },
    .{ .name = "stwo_zig_decommit_gather_trace_values_resident", .owner = .decommit },
    .{ .name = "stwo_zig_decommit_gather_tree_values_resident", .owner = .decommit },
    .{ .name = "stwo_zig_decommit_gather_tree_values_resident_wide", .owner = .decommit },
    .{ .name = "stwo_zig_decommit_gather_fri_values_resident", .owner = .decommit },
    .{ .name = "stwo_zig_decommit_sparse_parent_resident", .owner = .decommit },
    .{ .name = "stwo_zig_decommit_sparse_leaves_resident", .owner = .decommit },
    .{ .name = "stwo_zig_decommit_sparse_leaf_group_resident", .owner = .decommit },
    .{ .name = "stwo_zig_decommit_assemble_trace_resident", .owner = .decommit },
    .{ .name = "stwo_zig_decommit_assemble_fri_resident", .owner = .decommit },
    .{ .name = "stwo_zig_eval_basis", .owner = .polynomial_eval },
    .{ .name = "stwo_zig_eval_polynomials", .owner = .polynomial_eval },
    .{ .name = "stwo_zig_sampled_barycentric_domain_v1", .owner = .polynomial_eval },
    .{ .name = "stwo_zig_sampled_barycentric_scale_v1", .owner = .polynomial_eval },
    .{ .name = "stwo_zig_sampled_barycentric_parts_v1", .owner = .polynomial_eval },
    .{ .name = "stwo_zig_sampled_barycentric_inverse_direct_v1", .owner = .polynomial_eval },
    .{ .name = "stwo_zig_sampled_barycentric_inverse_tree_v1", .owner = .polynomial_eval },
    .{ .name = "stwo_zig_sampled_barycentric_finish_v1", .owner = .polynomial_eval },
    .{ .name = "stwo_zig_sampled_barycentric_evaluate_many_v1", .owner = .polynomial_eval },
    .{ .name = "stwo_zig_sampled_barycentric_reduce_v1", .owner = .polynomial_eval },
    .{ .name = "stwo_zig_base_poly_e3d97ada62a6ad9f06872ffebf334097", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_base_poly_94bb6ee080d963f1a9b89ba8836e6cbf", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_base_poly_43fb3f4df23ca371514fbd130360efba", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_base_poly_c435f0a2ee25c59eec1ebd9f12b995cd", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_base_poly_116f3173573043d8dc56aa23e5c1fac4", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_base_poly_63ea0b65e576f67691cdb43d14a7590b", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_base_poly_782a4d5d838c828e4ae55bb81b63e389", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_base_poly_0b0c9beaa20a9460c6d8ecfdfe560eba", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_base_poly_766a542bb547c7b4eaf4c8a8fb9eef52", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_base_poly_a995060c2a616369140d09438c7dac67", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_base_poly_9228c4a31e483b8e787375ff1354be9a", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_base_poly_c20d068f8ff248590d22364c7c7d5649", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_base_poly_4a95ed38e5a6795e8a84b0817ddd37e1", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_base_poly_706ca0b14e34ec043cbf5f04e14fb315", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_base_poly_40d34cb41f90634e26f0b2bb88a77110", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_base_poly_5d744c2fbb612ce7e9954dfd6cc1b4b7", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_base_poly_903175038c36e2a6aad8376003874197", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_lookup_poly_a5980ef351d2fafc7a22e5aa40300954", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_lookup_poly_e5715747fc906de9684a84af2d392d1e", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_lookup_poly_8a132b1e9e82b54afcec47fe86f30324", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_lookup_poly_bed36219333c2c4ad3c08cfdfda0e8a2", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_lookup_poly_020adcddb227238a71dcd523f9c87a7f", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_lookup_poly_d6611c9189072c08839d56f6496f63ed", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_lookup_poly_94aa7ee9c1399f0ac1615227be890e54", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_lookup_poly_ff8f5638e589be25d994070f031c73f4", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_lookup_poly_04a5ee0118c370d4f4be88a43aa90c1b", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_lookup_poly_71a7dea9a6d87e457404d7286bf51e2b", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_lookup_poly_c98fc3b8440d536b2dd11e209cf33406", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_lookup_poly_c7ef2b87fccb92355969d231b02a1d52", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_lookup_poly_7187bd253b26502c413540ac56eccb23", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_lookup_poly_ae8631b5be628fa89a790444be02b7b1", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_lookup_poly_d7203c97e13213534f5bd98272130f81", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_lookup_poly_fe8c4b8e3259f973cd85613a2dd582bc", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_lookup_poly_43726bbe802a5a24b6c16a4bc093608b", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_lookup_poly_v2_6e35df3dbb1bb66f7c23e82cdf0f6705509c4f08e5719edab77049660d8e632d", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_lookup_poly_v2_253283e6dfe6bf332f2e466400c1f09394999e7935e86d6bb99a351d8d0b1f49", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_lookup_poly_v2_28bc2d54b9a33dccb35df8513dc35a810077488a2f4be0c88b5d36a55a9e8bf8", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_lookup_poly_v2_be13b51301211f686fd16c2f88309d8f847af74402b7d38c61ef79b645d99f79", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_lookup_poly_v2_275d7261fb64f5cf5fc049ceac6422a7d6e64f153e09f81ddcf3311c1e2ffaa6", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_lookup_poly_v2_c21e7087e658c83a4ea68ba0339efa466e9023c10538de1236d5e94f360cd70f", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_lookup_poly_v2_6e0f5b41382a11695ffc997f00f28eb2a1fd365fac56419e6a58bd35fcecaebc", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_lookup_poly_v2_330b38988296b847ce7943460949e4339ec66db537e4d03491747b2c39b920c0", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_lookup_poly_v2_77f9c3e7ba9b17eb361ff2af6220464a5777f3a52ef415c3524ac42ab6e32f2c", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_lookup_poly_v2_69a3e73ed85579645e6ee7eee831fcd273dc41967143d39561a8b07d44d4b8b7", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_lookup_poly_v2_17d893819094787c341d61e34fc145d907ae4f229fc5bdf675450f9cbfc783e7", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_lookup_poly_v2_c52d555f957bd0bb3a403a52ba9a00707ea38b95680598413ab0c999a4f2e212", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_lookup_poly_v2_1d2cb31b377e1584858df2e1571ab50af833573e09a8e92b509736d894751ff5", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_lookup_poly_v2_a58738eaf81c1bd3c20292b4d470433552c7c5bef4faf841e4da8e2a5a04681a", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_lookup_poly_v2_a5c335d39317cb0ece5d0ffe5dd536cba3b9c4c84da54f5c8876a3b6cd5520f4", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_lookup_poly_v2_23bb5dc1410c56ceab84080bd3239e6c9156f3761b93508f773dee7e448a70dc", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_lookup_poly_v2_64c076e4946245d3c0f988997bf90b10774d23a6344d856e147c744b2df6d98c", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_base_poly_8ae392ed1a7274608734b90ddc05e147", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_base_poly_7be9f94a181c86f487035579b75a3c09", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_base_poly_252a366d21097cfa39ddc55b4c8d3732", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_base_poly_3ff26f48f99514ff96f9e6242e02689c", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_lookup_poly_bfaf5e2aa44bc0bce57377b16d8362a7", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_base_poly_e13d2efe7ad236638a213d15673065f1", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_base_poly_e7e0dab59a4ca045df197c03e1cde944", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_base_poly_b0c8b0812b31ac11d0ed355fdffceaeb", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_base_poly_ba19de000ba4a34803e344cadd255681", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_lookup_poly_eadeb11637b6b8b330635af67876a763", .owner = .riscv_polynomials },
};

pub fn isDeferredOwner(owner: Unit) bool {
    return switch (owner) {
        .cairo_trace, .cairo_witness_feed, .cairo_fixed_tables, .cairo_ec_op => true,
        else => false,
    };
}

pub const native_export_count = count: {
    var result: usize = 0;
    for (exports) |entry| {
        if (!isDeferredOwner(entry.owner)) result += 1;
    }
    break :count result;
};

/// The exact Native Stwo kernel ABI. Deferred Cairo kernels never enter the
/// default source library or its eager pipeline set.
pub const native_exports: [native_export_count]Export = filtered: {
    var result: [native_export_count]Export = undefined;
    var index: usize = 0;
    for (exports) |entry| {
        if (isDeferredOwner(entry.owner)) continue;
        result[index] = entry;
        index += 1;
    }
    break :filtered result;
};

pub const TranslationUnit = struct {
    path: []const u8,
    source: []const u8,
};

const legacy_source = @embedFile("../kernels.metal");
const fri_resident_source = @embedFile("core/fri_resident.metal");
const base_source = @embedFile("include/base.metal");
const blake2s_source = @embedFile("include/blake2s.metal");
const merkle_source = @embedFile("include/merkle.metal");
const decommit_source = @embedFile("include/decommit.metal");
const m31_source = @embedFile("include/m31.metal");
const poseidon2_m31_source = @embedFile("include/poseidon2_m31.metal");
const extension_fields_source = @embedFile("include/extension_fields.metal");
const circle_source = @embedFile("include/circle.metal");
const abi_types_source = @embedFile("include/abi_types.metal");
const felt252_source = @embedFile("include/felt252.metal");
const ec_source = @embedFile("include/ec.metal");
const witness_abi_source = @embedFile("include/witness_abi.metal");
const witness_tables_source = @embedFile("include/witness_tables.metal");
const witness_deductions_source = @embedFile("include/witness_deductions.metal");
const commitments_source = @embedFile("core/commitments.metal");
const cairo_trace_source = @embedFile("cairo/trace.metal");
const cairo_witness_feed_source = @embedFile("cairo/witness_feed.metal");
const cairo_fixed_tables_source = @embedFile("cairo/fixed_tables.metal");
const cairo_ec_op_source = @embedFile("cairo/ec_op.metal");
const circle_transform_source = @embedFile("core/circle_transform.metal");
const circle_transform_wide_source = @embedFile("core/circle_transform_wide.metal");
const circle_transform_all_source = circle_transform_source ++ circle_transform_wide_source;
const arena_ops_source = @embedFile("core/arena_ops.metal");
const transcript_source = @embedFile("core/transcript.metal");
const composition_source = @embedFile("core/composition.metal");
const relation_source = @embedFile("core/relation.metal");
const decommit_kernels_source = @embedFile("core/decommit.metal");
const polynomial_eval_source = @embedFile("core/polynomial_eval.metal");
const riscv_polynomials_source = @embedFile("core/riscv_polynomials.metal");

pub const WitnessCodegenSupport = struct {
    base: []const u8,
    m31: []const u8,
    felt252: []const u8,
    ec: []const u8,
    witness_abi: []const u8,
    witness_tables: []const u8,
    witness_deductions: []const u8,
};

/// Backend-owned shader headers admitted to Cairo witness code generation.
/// Consumers receive immutable bytes rather than filesystem access to this
/// package's private shader tree.
pub const witness_codegen_support = WitnessCodegenSupport{
    .base = base_source,
    .m31 = m31_source,
    .felt252 = felt252_source,
    .ec = ec_source,
    .witness_abi = witness_abi_source,
    .witness_tables = witness_tables_source,
    .witness_deductions = witness_deductions_source,
};

pub const support_headers = [_]TranslationUnit{
    .{ .path = "src/backends/metal/shaders/include/base.metal", .source = base_source },
    .{ .path = "src/backends/metal/shaders/include/blake2s.metal", .source = blake2s_source },
    .{ .path = "src/backends/metal/shaders/include/merkle.metal", .source = merkle_source },
    .{ .path = "src/backends/metal/shaders/include/decommit.metal", .source = decommit_source },
    .{ .path = "src/backends/metal/shaders/include/m31.metal", .source = m31_source },
    .{ .path = "src/backends/metal/shaders/include/poseidon2_m31.metal", .source = poseidon2_m31_source },
    .{ .path = "src/backends/metal/shaders/include/extension_fields.metal", .source = extension_fields_source },
    .{ .path = "src/backends/metal/shaders/include/circle.metal", .source = circle_source },
    .{ .path = "src/backends/metal/shaders/include/abi_types.metal", .source = abi_types_source },
    .{ .path = "src/backends/metal/shaders/include/felt252.metal", .source = felt252_source },
    .{ .path = "src/backends/metal/shaders/include/ec.metal", .source = ec_source },
    .{ .path = "src/backends/metal/shaders/include/witness_abi.metal", .source = witness_abi_source },
    .{ .path = "src/backends/metal/shaders/include/witness_tables.metal", .source = witness_tables_source },
    .{ .path = "src/backends/metal/shaders/include/witness_deductions.metal", .source = witness_deductions_source },
};

pub const native_support_headers = support_headers[0..9];

pub const translation_units = [_]TranslationUnit{
    .{ .path = "src/backends/metal/shaders/core/commitments.metal", .source = commitments_source },
    .{ .path = "src/backends/metal/kernels.metal", .source = legacy_source },
    .{ .path = "src/backends/metal/shaders/core/fri_resident.metal", .source = fri_resident_source },
    .{ .path = "src/backends/metal/shaders/core/circle_transform.metal", .source = circle_transform_source },
    .{ .path = "src/backends/metal/shaders/core/circle_transform_wide.metal", .source = circle_transform_wide_source },
    .{ .path = "src/backends/metal/shaders/cairo/trace.metal", .source = cairo_trace_source },
    .{ .path = "src/backends/metal/shaders/cairo/witness_feed.metal", .source = cairo_witness_feed_source },
    .{ .path = "src/backends/metal/shaders/cairo/fixed_tables.metal", .source = cairo_fixed_tables_source },
    .{ .path = "src/backends/metal/shaders/cairo/ec_op.metal", .source = cairo_ec_op_source },
    .{ .path = "src/backends/metal/shaders/core/arena_ops.metal", .source = arena_ops_source },
    .{ .path = "src/backends/metal/shaders/core/transcript.metal", .source = transcript_source },
    .{ .path = "src/backends/metal/shaders/core/composition.metal", .source = composition_source },
    .{ .path = "src/backends/metal/shaders/core/relation.metal", .source = relation_source },
    .{ .path = "src/backends/metal/shaders/core/decommit.metal", .source = decommit_kernels_source },
    .{ .path = "src/backends/metal/shaders/core/polynomial_eval.metal", .source = polynomial_eval_source },
    .{ .path = "src/backends/metal/shaders/core/riscv_polynomials.metal", .source = riscv_polynomials_source },
};

pub const native_translation_units = [_]TranslationUnit{
    .{ .path = "src/backends/metal/shaders/core/commitments.metal", .source = commitments_source },
    .{ .path = "src/backends/metal/kernels.metal", .source = legacy_source },
    .{ .path = "src/backends/metal/shaders/core/fri_resident.metal", .source = fri_resident_source },
    .{ .path = "src/backends/metal/shaders/core/circle_transform.metal", .source = circle_transform_source },
    .{ .path = "src/backends/metal/shaders/core/circle_transform_wide.metal", .source = circle_transform_wide_source },
    .{ .path = "src/backends/metal/shaders/core/arena_ops.metal", .source = arena_ops_source },
    .{ .path = "src/backends/metal/shaders/core/transcript.metal", .source = transcript_source },
    .{ .path = "src/backends/metal/shaders/core/composition.metal", .source = composition_source },
    .{ .path = "src/backends/metal/shaders/core/relation.metal", .source = relation_source },
    .{ .path = "src/backends/metal/shaders/core/decommit.metal", .source = decommit_kernels_source },
    .{ .path = "src/backends/metal/shaders/core/polynomial_eval.metal", .source = polynomial_eval_source },
    .{ .path = "src/backends/metal/shaders/core/riscv_polynomials.metal", .source = riscv_polynomials_source },
};

pub const native_amalgamated_source: [:0]const u8 = "#define STWO_ZIG_AMALGAMATED 1\n" ++
    "#line 1 \"src/backends/metal/shaders/include/base.metal\"\n" ++ base_source ++
    "\n#line 1 \"src/backends/metal/shaders/include/blake2s.metal\"\n" ++ blake2s_source ++
    "\n#line 1 \"src/backends/metal/shaders/include/merkle.metal\"\n" ++ merkle_source ++
    "\n#line 1 \"src/backends/metal/shaders/include/decommit.metal\"\n" ++ decommit_source ++
    "\n#line 1 \"src/backends/metal/shaders/include/m31.metal\"\n" ++ m31_source ++
    "\n#line 1 \"src/backends/metal/shaders/include/poseidon2_m31.metal\"\n" ++ poseidon2_m31_source ++
    "\n#line 1 \"src/backends/metal/shaders/include/extension_fields.metal\"\n" ++ extension_fields_source ++
    "\n#line 1 \"src/backends/metal/shaders/include/circle.metal\"\n" ++ circle_source ++
    "\n#line 1 \"src/backends/metal/shaders/include/abi_types.metal\"\n" ++ abi_types_source ++
    "\n#line 1 \"src/backends/metal/shaders/core/commitments.metal\"\n" ++ commitments_source ++
    "\n#line 1 \"src/backends/metal/kernels.metal\"\n" ++ legacy_source ++
    "\n#line 1 \"src/backends/metal/shaders/core/fri_resident.metal\"\n" ++ fri_resident_source ++
    "\n#line 1 \"src/backends/metal/shaders/core/circle_transform.metal\"\n" ++ circle_transform_source ++
    "\n#line 1 \"src/backends/metal/shaders/core/circle_transform_wide.metal\"\n" ++ circle_transform_wide_source ++
    "\n#line 1 \"src/backends/metal/shaders/core/arena_ops.metal\"\n" ++ arena_ops_source ++
    "\n#line 1 \"src/backends/metal/shaders/core/transcript.metal\"\n" ++ transcript_source ++
    "\n#line 1 \"src/backends/metal/shaders/core/composition.metal\"\n" ++ composition_source ++
    "\n#line 1 \"src/backends/metal/shaders/core/relation.metal\"\n" ++ relation_source ++
    "\n#line 1 \"src/backends/metal/shaders/core/decommit.metal\"\n" ++ decommit_kernels_source ++
    "\n#line 1 \"src/backends/metal/shaders/core/polynomial_eval.metal\"\n" ++ polynomial_eval_source ++
    "\n#line 1 \"src/backends/metal/shaders/core/riscv_polynomials.metal\"\n" ++ riscv_polynomials_source ++ "\x00";

/// Hash at runtime. The generated RISC-V polynomial kernels are large enough
/// that evaluating SHA-256 at comptime exhausts the compiler's branch quota
/// and creates avoidable multi-gigabyte compiler memory pressure.
pub fn nativeAmalgamatedSourceDigest() [32]u8 {
    var result: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(
        native_amalgamated_source[0 .. native_amalgamated_source.len - 1],
        &result,
        .{},
    );
    return result;
}

/// The runtime still compiles one library. Translation-unit boundaries are
/// explicit here so AOT compilation can consume the same ordered manifest.
pub const amalgamated_source: [:0]const u8 = "#define STWO_ZIG_AMALGAMATED 1\n" ++
    "#line 1 \"src/backends/metal/shaders/include/base.metal\"\n" ++
    base_source ++
    "\n#line 1 \"src/backends/metal/shaders/include/blake2s.metal\"\n" ++
    blake2s_source ++
    "\n#line 1 \"src/backends/metal/shaders/include/merkle.metal\"\n" ++
    merkle_source ++
    "\n#line 1 \"src/backends/metal/shaders/include/decommit.metal\"\n" ++
    decommit_source ++
    "\n#line 1 \"src/backends/metal/shaders/include/m31.metal\"\n" ++
    m31_source ++
    "\n#line 1 \"src/backends/metal/shaders/include/poseidon2_m31.metal\"\n" ++
    poseidon2_m31_source ++
    "\n#line 1 \"src/backends/metal/shaders/include/extension_fields.metal\"\n" ++
    extension_fields_source ++
    "\n#line 1 \"src/backends/metal/shaders/include/circle.metal\"\n" ++
    circle_source ++
    "\n#line 1 \"src/backends/metal/shaders/include/abi_types.metal\"\n" ++
    abi_types_source ++
    "\n#line 1 \"src/backends/metal/shaders/include/felt252.metal\"\n" ++
    felt252_source ++
    "\n#line 1 \"src/backends/metal/shaders/include/ec.metal\"\n" ++
    ec_source ++
    "\n#line 1 \"src/backends/metal/shaders/include/witness_abi.metal\"\n" ++
    witness_abi_source ++
    "\n#line 1 \"src/backends/metal/shaders/include/witness_tables.metal\"\n" ++
    witness_tables_source ++
    "\n#line 1 \"src/backends/metal/shaders/include/witness_deductions.metal\"\n" ++
    witness_deductions_source ++
    "\n#line 1 \"src/backends/metal/shaders/core/commitments.metal\"\n" ++
    commitments_source ++
    "\n#line 1 \"src/backends/metal/kernels.metal\"\n" ++
    legacy_source ++
    "\n#line 1 \"src/backends/metal/shaders/core/fri_resident.metal\"\n" ++
    fri_resident_source ++
    "\n#line 1 \"src/backends/metal/shaders/core/circle_transform.metal\"\n" ++
    circle_transform_source ++
    "\n#line 1 \"src/backends/metal/shaders/core/circle_transform_wide.metal\"\n" ++
    circle_transform_wide_source ++
    "\n#line 1 \"src/backends/metal/shaders/cairo/trace.metal\"\n" ++
    cairo_trace_source ++
    "\n#line 1 \"src/backends/metal/shaders/cairo/witness_feed.metal\"\n" ++
    cairo_witness_feed_source ++
    "\n#line 1 \"src/backends/metal/shaders/cairo/fixed_tables.metal\"\n" ++
    cairo_fixed_tables_source ++
    "\n#line 1 \"src/backends/metal/shaders/cairo/ec_op.metal\"\n" ++
    cairo_ec_op_source ++
    "\n#line 1 \"src/backends/metal/shaders/core/arena_ops.metal\"\n" ++
    arena_ops_source ++
    "\n#line 1 \"src/backends/metal/shaders/core/transcript.metal\"\n" ++
    transcript_source ++
    "\n#line 1 \"src/backends/metal/shaders/core/composition.metal\"\n" ++
    composition_source ++
    "\n#line 1 \"src/backends/metal/shaders/core/relation.metal\"\n" ++
    relation_source ++
    "\n#line 1 \"src/backends/metal/shaders/core/decommit.metal\"\n" ++
    decommit_kernels_source ++
    "\n#line 1 \"src/backends/metal/shaders/core/polynomial_eval.metal\"\n" ++
    polynomial_eval_source ++
    "\n#line 1 \"src/backends/metal/shaders/core/riscv_polynomials.metal\"\n" ++
    riscv_polynomials_source ++ "\x00";

pub fn amalgamatedSourceDigest() [32]u8 {
    var result: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(
        amalgamated_source[0 .. amalgamated_source.len - 1],
        &result,
        .{},
    );
    return result;
}

fn manifestContains(name: []const u8) bool {
    for (exports) |entry| {
        if (std.mem.eql(u8, entry.name, name)) return true;
    }
    return false;
}

fn countKernelDeclarations(source: []const u8, name: []const u8) usize {
    var pattern_buffer: [160]u8 = undefined;
    const pattern = std.fmt.bufPrint(&pattern_buffer, "kernel void {s}(", .{name}) catch unreachable;
    return std.mem.count(u8, source, pattern);
}

fn kernelDeclaration(source: []const u8, name: []const u8) ![]const u8 {
    var pattern_buffer: [160]u8 = undefined;
    const pattern = try std.fmt.bufPrint(&pattern_buffer, "kernel void {s}(", .{name});
    const start = std.mem.indexOf(u8, source, pattern) orelse return error.MissingMetalKernelDeclaration;
    const end = std.mem.indexOfPos(u8, source, start, ") {") orelse
        return error.MalformedMetalKernelDeclaration;
    return source[start .. end + 3];
}

const Root = @This();

pub const testing = struct {
    pub const legacy_source = Root.legacy_source;
    pub const fri_resident_source = Root.fri_resident_source;
    pub const base_source = Root.base_source;
    pub const blake2s_source = Root.blake2s_source;
    pub const merkle_source = Root.merkle_source;
    pub const decommit_source = Root.decommit_source;
    pub const m31_source = Root.m31_source;
    pub const poseidon2_m31_source = Root.poseidon2_m31_source;
    pub const extension_fields_source = Root.extension_fields_source;
    pub const circle_source = Root.circle_source;
    pub const abi_types_source = Root.abi_types_source;
    pub const felt252_source = Root.felt252_source;
    pub const ec_source = Root.ec_source;
    pub const witness_abi_source = Root.witness_abi_source;
    pub const witness_tables_source = Root.witness_tables_source;
    pub const witness_deductions_source = Root.witness_deductions_source;
    pub const commitments_source = Root.commitments_source;
    pub const cairo_trace_source = Root.cairo_trace_source;
    pub const cairo_witness_feed_source = Root.cairo_witness_feed_source;
    pub const cairo_fixed_tables_source = Root.cairo_fixed_tables_source;
    pub const cairo_ec_op_source = Root.cairo_ec_op_source;
    pub const circle_transform_source = Root.circle_transform_source;
    pub const circle_transform_wide_source = Root.circle_transform_wide_source;
    pub const circle_transform_all_source = Root.circle_transform_all_source;
    pub const arena_ops_source = Root.arena_ops_source;
    pub const transcript_source = Root.transcript_source;
    pub const composition_source = Root.composition_source;
    pub const relation_source = Root.relation_source;
    pub const decommit_kernels_source = Root.decommit_kernels_source;
    pub const polynomial_eval_source = Root.polynomial_eval_source;
    pub const riscv_polynomials_source = Root.riscv_polynomials_source;
    pub const manifestContains = Root.manifestContains;
    pub const countKernelDeclarations = Root.countKernelDeclarations;
    pub const kernelDeclaration = Root.kernelDeclaration;
};
