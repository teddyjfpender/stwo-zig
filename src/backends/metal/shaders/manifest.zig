const std = @import("std");

pub const core_shader_abi: u32 = 14;
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
    .{ .name = "stwo_zig_fri_final_line_resident", .owner = .fri },
    .{ .name = "stwo_zig_decommit_normalize_queries_resident", .owner = .decommit },
    .{ .name = "stwo_zig_decommit_prepare_fri_queries_resident", .owner = .decommit },
    .{ .name = "stwo_zig_decommit_prepare_trace_queries_resident", .owner = .decommit },
    .{ .name = "stwo_zig_decommit_gather_trace_values_resident", .owner = .decommit },
    .{ .name = "stwo_zig_decommit_gather_fri_values_resident", .owner = .decommit },
    .{ .name = "stwo_zig_decommit_sparse_parent_resident", .owner = .decommit },
    .{ .name = "stwo_zig_decommit_sparse_leaves_resident", .owner = .decommit },
    .{ .name = "stwo_zig_decommit_sparse_leaf_group_resident", .owner = .decommit },
    .{ .name = "stwo_zig_decommit_assemble_trace_resident", .owner = .decommit },
    .{ .name = "stwo_zig_decommit_assemble_fri_resident", .owner = .decommit },
    .{ .name = "stwo_zig_eval_basis", .owner = .polynomial_eval },
    .{ .name = "stwo_zig_eval_polynomials", .owner = .polynomial_eval },
    .{ .name = "stwo_zig_base_poly_450551d90acd324ebbd24fcf112b6e2a", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_base_poly_c14a50f654a9c7e71379b41a108194ff", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_base_poly_f3458c84073cbe0a1a0cc8d255a028f0", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_base_poly_a2a6593402647f120c2a259a1710c6e3", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_base_poly_a972dafabb2bf5eee1d1cdb560f3572e", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_base_poly_09e5f90f9696d165cc36093de2564888", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_base_poly_a74fd0125263cc1e887ee5d726ac99a0", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_base_poly_3b018614b76f63e7a28e127029c18704", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_base_poly_aa55ec34af78d3f2b74d4b3d06c708a8", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_base_poly_0ade2040c246f9cad3919da46161d2fd", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_base_poly_6301135c98c38c29971098b60b459397", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_base_poly_95bca92bf8e5c8c0cd1438e06c6c8963", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_base_poly_373e28e4ebf898ce291ed734807dfa00", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_base_poly_1d58ef609255595a37488e277d52585c", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_base_poly_208adea2af3accc5bd53faa7807024bb", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_base_poly_9b9a12367c3aeb8830ac01bf757fa64a", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_base_poly_ebe47c5c0304bddea66f3a2b7c9cd55c", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_lookup_poly_6bd1123655f7e5fc662f4e397524645b", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_lookup_poly_60369e534e1e31666bb1684e6745500b", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_lookup_poly_cae77cf99f2127b1108dc5c1609cc16b", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_lookup_poly_d1b44ec0cc8a532f04e4e39fd0bb648e", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_lookup_poly_88bafd2b2b2bb614f3a37e2e93f88f8f", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_lookup_poly_f0435e9fbbd4a7a98c7c5162bee7d7a9", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_lookup_poly_cc2c95d2bff4c999fee2f44e08222252", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_lookup_poly_b52a532ad3c7e42bdece0624fb56b8aa", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_lookup_poly_b15f9ad4a9abfc83a7cdec6c46ee4ade", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_lookup_poly_fcc84457fa16172e164408c12324b2c2", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_lookup_poly_ff9bf971cfa80d96e0aa0e50e4b1b89d", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_lookup_poly_b63d26046143c546183c7769fee7803a", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_lookup_poly_60da0a81177c1f7c118d91080a104856", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_lookup_poly_d71f7ff4122659b75334f16e7282cd1e", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_lookup_poly_2933fad233d8d72eaaaac264f1f08e46", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_lookup_poly_55f49d22b3eefd58176c82e98f534eb1", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_lookup_poly_34a73d9627a19782b2486c6dcd96f1fe", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_lookup_poly_v2_4495e1dc5d58d71f640d011e5e267fc06fe6adfe54e6405fa20aab1ab4a4f496", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_lookup_poly_v2_faadbe548bfa104ae056599d5e4910f9812fc7ddf9179da65d5d5e6fba234d35", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_lookup_poly_v2_9ed05c9eac769627c64b0e915e2630d0a51bb6325410ea144d9669b85c480514", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_lookup_poly_v2_198678cb3ba8974d902c91452544c7f63c81fc0d10de3a87f612c1e9cb9437a8", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_lookup_poly_v2_ec1cb673e29351c380eb472b19293e7ea97ab2030393f54c7bcbb1426ae83aa2", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_lookup_poly_v2_edade529adf1f7eb6b09313aad8cc71ff739a71d11e2b40cb6101daf378d8489", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_lookup_poly_v2_c95e5383b34ea4ad55aaff5bc8ca9054b9fb9abe15db39e6409374e0dd3b5617", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_lookup_poly_v2_b64e1478588595c7a3f7c71371ef1e6f1ceae3dd055c9eb56aa4081cf93e97d1", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_lookup_poly_v2_b9e7c8afba03add7dd116b67fd791e19256bc093b6eb47e41ca9ee411608c58a", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_lookup_poly_v2_b777199dcff0d3dbb81372f98612beda7bd12bf2d2bc7725f1dab500e07c39d9", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_lookup_poly_v2_a0710166b8b3057556c2f5907836c0c82fe3b92fccff4633d504c0ff510b6d93", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_lookup_poly_v2_bd8284d4f0c5a7d0cd9dd1f4879d721c70992754e1d5aadf02df9e4f86c15d2c", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_lookup_poly_v2_099cc5bddab2ff60effcbef0d7863f6a78e0d7a9fcc78fa43d9603f6798904b3", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_lookup_poly_v2_e622d001a5cd368b6efef022e0db61a1ab9e30842ef91e4135c0dc5cbd18eb19", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_lookup_poly_v2_1cab02ea628504e58cb4a0dbf15dbca36cccc7cad4f36949bb10265a08cd44cc", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_lookup_poly_v2_74e0c5ba6845f3d863a1b821d0f22ea76e38570ccd234b537ea4fb9e8f19bf77", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_lookup_poly_v2_e9b9d5d433a734c48921694aa7185fafe3fb15e7bd89dc42261cc4290f894352", .owner = .riscv_polynomials },
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
    .{ .path = "src/backends/metal/shaders/include/extension_fields.metal", .source = extension_fields_source },
    .{ .path = "src/backends/metal/shaders/include/circle.metal", .source = circle_source },
    .{ .path = "src/backends/metal/shaders/include/abi_types.metal", .source = abi_types_source },
    .{ .path = "src/backends/metal/shaders/include/felt252.metal", .source = felt252_source },
    .{ .path = "src/backends/metal/shaders/include/ec.metal", .source = ec_source },
    .{ .path = "src/backends/metal/shaders/include/witness_abi.metal", .source = witness_abi_source },
    .{ .path = "src/backends/metal/shaders/include/witness_tables.metal", .source = witness_tables_source },
    .{ .path = "src/backends/metal/shaders/include/witness_deductions.metal", .source = witness_deductions_source },
};

pub const native_support_headers = support_headers[0..8];

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
