const std = @import("std");

pub const core_shader_abi: u32 = 12;
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
    .{ .name = "stwo_zig_base_poly_875d2026fe2fc2b5e1c47b100b1b8f0d", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_base_poly_d170513e9cfabf624e38dfa3d7d2f4ed", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_base_poly_a74fd0125263cc1e887ee5d726ac99a0", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_base_poly_3b018614b76f63e7a28e127029c18704", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_base_poly_aa55ec34af78d3f2b74d4b3d06c708a8", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_base_poly_0ade2040c246f9cad3919da46161d2fd", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_base_poly_6301135c98c38c29971098b60b459397", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_base_poly_95bca92bf8e5c8c0cd1438e06c6c8963", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_base_poly_373e28e4ebf898ce291ed734807dfa00", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_base_poly_2a07b91d7f51809a92cf5dccdf29c1b5", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_base_poly_04a6d5f01089e9ee1136328c062b3055", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_base_poly_7c3d009f184e1add15cea06850337ed9", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_base_poly_ebe47c5c0304bddea66f3a2b7c9cd55c", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_lookup_poly_d3393528172e2c1fd4dfbdc4e0d47c8a", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_lookup_poly_50b304cc2ee4f2f9f39675717cf40382", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_lookup_poly_075758e47d896ea9b9ed480adcc498d1", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_lookup_poly_459147491178ba9a8fea95e70f7ba7de", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_lookup_poly_223a80d6062ce49ec32568323089b631", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_lookup_poly_e6f321d7e6a5216f0493a7d9dd1cce68", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_lookup_poly_cc2c95d2bff4c999fee2f44e08222252", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_lookup_poly_6417a7b6a721b820c56ded08d4ff45d4", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_lookup_poly_b15f9ad4a9abfc83a7cdec6c46ee4ade", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_lookup_poly_65a7491625ceb251a9d27754aba62fe9", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_lookup_poly_4fae56a01407106338de7b5a0585b863", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_lookup_poly_2a7765f5161c42b7e1e47eb4f38042a6", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_lookup_poly_3fe627edfd1799423093b8b5e01e44bc", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_lookup_poly_58c75167f9212f9663711e80d150d46d", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_lookup_poly_05d290ec9454d3ead43a08a8f547ed07", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_lookup_poly_944959c865e0c8dee4d3972badf854b0", .owner = .riscv_polynomials },
    .{ .name = "stwo_zig_lookup_poly_6036f462a378cec7d80f357b57bff1f4", .owner = .riscv_polynomials },
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

test "Native core source exactly covers its non-Cairo export ABI" {
    try std.testing.expectEqual(@as(usize, 118), native_exports.len);
    try std.testing.expectEqual(native_exports.len, std.mem.count(u8, native_amalgamated_source, "kernel void "));
    try std.testing.expect(std.mem.indexOf(u8, native_amalgamated_source, "shaders/cairo/") == null);
    for (native_support_headers) |unit| try std.testing.expect(std.mem.indexOf(u8, unit.path, "/cairo/") == null);
    for (native_translation_units) |unit| try std.testing.expect(std.mem.indexOf(u8, unit.path, "/cairo/") == null);
    for (native_exports) |entry| {
        try std.testing.expect(!isDeferredOwner(entry.owner));
        try std.testing.expectEqual(@as(usize, 1), countKernelDeclarations(native_amalgamated_source, entry.name));
    }
    for (exports) |entry| if (isDeferredOwner(entry.owner))
        try std.testing.expectEqual(@as(usize, 0), countKernelDeclarations(native_amalgamated_source, entry.name));
}

fn expectIsolated(source: []const u8, names: []const []const u8) !void {
    for (names) |name| {
        try std.testing.expectEqual(@as(usize, 0), countKernelDeclarations(legacy_source, name));
        try std.testing.expectEqual(@as(usize, 1), countKernelDeclarations(source, name));
        try std.testing.expectEqual(@as(usize, 1), countKernelDeclarations(amalgamated_source, name));
    }
}

test "metal shader manifest exactly covers source and runtime exports" {
    const runtime_source = @embedFile("../runtime.m");
    try std.testing.expectEqual(@as(usize, 130), exports.len);

    var declaration_count: usize = 0;
    var remaining: []const u8 = amalgamated_source[0 .. amalgamated_source.len - 1];
    const marker = "kernel void ";
    while (std.mem.indexOf(u8, remaining, marker)) |marker_index| {
        const name_start = marker_index + marker.len;
        const name_end = std.mem.indexOfScalarPos(u8, remaining, name_start, '(') orelse
            return error.MalformedMetalKernelDeclaration;
        try std.testing.expect(manifestContains(remaining[name_start..name_end]));
        declaration_count += 1;
        remaining = remaining[name_end + 1 ..];
    }
    try std.testing.expectEqual(exports.len, declaration_count);

    for (exports, 0..) |entry, index| {
        try std.testing.expectEqual(@as(usize, 1), countKernelDeclarations(amalgamated_source, entry.name));
        for (exports[index + 1 ..]) |other| {
            try std.testing.expect(!std.mem.eql(u8, entry.name, other.name));
        }

        var lookup_buffer: [160]u8 = undefined;
        const lookup = try std.fmt.bufPrint(&lookup_buffer, "@\"{s}\"", .{entry.name});
        try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, runtime_source, lookup));
    }
}

test "commitment shader bindings match core ABI version 12" {
    try std.testing.expectEqual(@as(u32, 12), core_shader_abi);
    const bindings = [_]struct { kernel: []const u8, argument: []const u8 }{
        .{ .kernel = "stwo_zig_blake2s_leaves", .argument = "prefix_bytes [[buffer(7)]]" },
        .{ .kernel = "stwo_zig_blake2s_parents", .argument = "prefix_bytes [[buffer(4)]]" },
        .{ .kernel = "stwo_zig_blake2s_parents_sparse", .argument = "prefix_bytes [[buffer(5)]]" },
        .{ .kernel = "stwo_zig_blake2s_parent_tail_sparse", .argument = "transcript_config [[buffer(7)]]" },
        .{ .kernel = "stwo_zig_fri_packed_leaves_resident", .argument = "prefix_bytes [[buffer(7)]]" },
        .{ .kernel = "stwo_zig_qm31_to_coordinates", .argument = "prefix_bytes [[buffer(5)]]" },
        .{ .kernel = "stwo_zig_fri_fold_line", .argument = "prefix_bytes [[buffer(8)]]" },
        .{ .kernel = "stwo_zig_quotient_domain_points_resident", .argument = "mode [[buffer(6)]]" },
        .{ .kernel = "stwo_zig_quotient_partials_raw", .argument = "partials [[buffer(9)]]" },
        .{ .kernel = "stwo_zig_quotient_combine_partials_raw", .argument = "row_count [[buffer(9)]]" },
    };
    for (bindings) |binding| {
        const declaration = try kernelDeclaration(amalgamated_source, binding.kernel);
        try std.testing.expect(std.mem.indexOf(u8, declaration, binding.argument) != null);
    }
}

test "polynomial evaluation is isolated in its owning shader unit" {
    try std.testing.expectEqual(@as(usize, 0), countKernelDeclarations(legacy_source, "stwo_zig_eval_basis"));
    try std.testing.expectEqual(@as(usize, 0), countKernelDeclarations(legacy_source, "stwo_zig_eval_polynomials"));
    try std.testing.expectEqual(@as(usize, 1), countKernelDeclarations(polynomial_eval_source, "stwo_zig_eval_basis"));
    try std.testing.expectEqual(@as(usize, 1), countKernelDeclarations(polynomial_eval_source, "stwo_zig_eval_polynomials"));
    try std.testing.expect(std.mem.indexOf(u8, abi_types_source, "struct PolynomialEvalTask") != null);
    try std.testing.expect(std.mem.indexOf(u8, abi_types_source, "struct PolynomialBasisTask") != null);
    try std.testing.expect(std.mem.indexOf(u8, polynomial_eval_source, "struct PolynomialEvalTask") == null);
}

test "RISC-V polynomial kernels have an exact isolated export ABI" {
    const names = [_][]const u8{
        "stwo_zig_base_poly_450551d90acd324ebbd24fcf112b6e2a",
        "stwo_zig_base_poly_c14a50f654a9c7e71379b41a108194ff",
        "stwo_zig_base_poly_f3458c84073cbe0a1a0cc8d255a028f0",
        "stwo_zig_base_poly_a2a6593402647f120c2a259a1710c6e3",
        "stwo_zig_base_poly_875d2026fe2fc2b5e1c47b100b1b8f0d",
        "stwo_zig_base_poly_d170513e9cfabf624e38dfa3d7d2f4ed",
        "stwo_zig_base_poly_a74fd0125263cc1e887ee5d726ac99a0",
        "stwo_zig_base_poly_3b018614b76f63e7a28e127029c18704",
        "stwo_zig_base_poly_aa55ec34af78d3f2b74d4b3d06c708a8",
        "stwo_zig_base_poly_0ade2040c246f9cad3919da46161d2fd",
        "stwo_zig_base_poly_6301135c98c38c29971098b60b459397",
        "stwo_zig_base_poly_95bca92bf8e5c8c0cd1438e06c6c8963",
        "stwo_zig_base_poly_373e28e4ebf898ce291ed734807dfa00",
        "stwo_zig_base_poly_2a07b91d7f51809a92cf5dccdf29c1b5",
        "stwo_zig_base_poly_04a6d5f01089e9ee1136328c062b3055",
        "stwo_zig_base_poly_7c3d009f184e1add15cea06850337ed9",
        "stwo_zig_base_poly_ebe47c5c0304bddea66f3a2b7c9cd55c",
        "stwo_zig_lookup_poly_d3393528172e2c1fd4dfbdc4e0d47c8a",
        "stwo_zig_lookup_poly_50b304cc2ee4f2f9f39675717cf40382",
        "stwo_zig_lookup_poly_075758e47d896ea9b9ed480adcc498d1",
        "stwo_zig_lookup_poly_459147491178ba9a8fea95e70f7ba7de",
        "stwo_zig_lookup_poly_223a80d6062ce49ec32568323089b631",
        "stwo_zig_lookup_poly_e6f321d7e6a5216f0493a7d9dd1cce68",
        "stwo_zig_lookup_poly_cc2c95d2bff4c999fee2f44e08222252",
        "stwo_zig_lookup_poly_6417a7b6a721b820c56ded08d4ff45d4",
        "stwo_zig_lookup_poly_b15f9ad4a9abfc83a7cdec6c46ee4ade",
        "stwo_zig_lookup_poly_65a7491625ceb251a9d27754aba62fe9",
        "stwo_zig_lookup_poly_4fae56a01407106338de7b5a0585b863",
        "stwo_zig_lookup_poly_2a7765f5161c42b7e1e47eb4f38042a6",
        "stwo_zig_lookup_poly_3fe627edfd1799423093b8b5e01e44bc",
        "stwo_zig_lookup_poly_58c75167f9212f9663711e80d150d46d",
        "stwo_zig_lookup_poly_05d290ec9454d3ead43a08a8f547ed07",
        "stwo_zig_lookup_poly_944959c865e0c8dee4d3972badf854b0",
        "stwo_zig_lookup_poly_6036f462a378cec7d80f357b57bff1f4",
    };
    try std.testing.expectEqual(@as(usize, 34), names.len);
    try std.testing.expectEqual(names.len, std.mem.count(u8, riscv_polynomials_source, "kernel void "));

    var owned_count: usize = 0;
    for (exports) |entry| {
        if (entry.owner == .riscv_polynomials) owned_count += 1;
    }
    try std.testing.expectEqual(names.len, owned_count);

    for (names) |name| {
        try std.testing.expect(manifestContains(name));
        try std.testing.expectEqual(@as(usize, 0), countKernelDeclarations(legacy_source, name));
        try std.testing.expectEqual(@as(usize, 1), countKernelDeclarations(riscv_polynomials_source, name));
        try std.testing.expectEqual(@as(usize, 1), countKernelDeclarations(native_amalgamated_source, name));
        try std.testing.expectEqual(@as(usize, 1), countKernelDeclarations(amalgamated_source, name));
    }
}

test "composition kernels are isolated in their owning shader unit" {
    const names = [_][]const u8{
        "stwo_zig_composition_expand_sparse",
        "stwo_zig_composition_lift_accumulate",
        "stwo_zig_composition_split_coordinates",
        "stwo_zig_composition_random_powers",
        "stwo_zig_composition_ext_params",
    };
    try expectIsolated(composition_source, names[0..]);
    const dependencies = [_][]const u8{
        "#include \"stwo_zig/base.metal\"",
        "#include \"stwo_zig/m31.metal\"",
        "#include \"stwo_zig/extension_fields.metal\"",
    };
    for (dependencies) |dependency| {
        try std.testing.expect(std.mem.indexOf(u8, composition_source, dependency) != null);
    }
}

test "relation kernels are isolated in their owning shader unit with a stable ABI" {
    const names = [_][]const u8{
        "stwo_zig_relation_fused",
        "stwo_zig_relation_block_scan",
        "stwo_zig_relation_scan_blocks",
        "stwo_zig_relation_scan_finalize",
    };
    try expectIsolated(relation_source, names[0..]);

    const dependencies = [_][]const u8{
        "#include \"stwo_zig/base.metal\"",
        "#include \"stwo_zig/m31.metal\"",
        "#include \"stwo_zig/extension_fields.metal\"",
    };
    for (dependencies) |dependency| {
        try std.testing.expect(std.mem.indexOf(u8, relation_source, dependency) != null);
    }

    const abi_fragments = [_][]const u8{
        "device const Qm31Value *z_ptr [[buffer(6)]], constant uint &instance_count [[buffer(7)]]",
        "constant uint &instance_count [[buffer(4)]], uint lane [[thread_index_in_threadgroup]]",
        "uint group [[threadgroup_position_in_grid]]",
        "device Qm31Value *block_sums [[buffer(2)]], constant uint &instance_count [[buffer(3)]]",
        "device const Qm31Value *block_sums [[buffer(3)]],\n    constant uint &instance_count [[buffer(4)]], uint index [[thread_position_in_grid]]",
    };
    for (abi_fragments) |fragment| {
        try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, relation_source, fragment));
    }
}

test "Cairo trace kernels are isolated in their owning shader unit with a stable ABI" {
    const names = [_][]const u8{
        "stwo_zig_witness_input_gather_resident",
        "stwo_zig_execution_table_split_resident",
        "stwo_zig_memory_address_base_trace_resident",
        "stwo_zig_memory_value_base_trace_resident",
        "stwo_zig_memory_rc99_count_resident",
        "stwo_zig_public_memory_seed_resident",
    };
    try expectIsolated(cairo_trace_source, names[0..]);

    try std.testing.expect(std.mem.indexOf(u8, cairo_trace_source, "#include \"stwo_zig/base.metal\"") != null);
    const bindings = [_]struct { kernel: []const u8, argument: []const u8 }{
        .{ .kernel = "stwo_zig_witness_input_gather_resident", .argument = "constant uint &include_iota [[buffer(9)]]" },
        .{ .kernel = "stwo_zig_execution_table_split_resident", .argument = "constant uint *destination_offsets [[buffer(6)]]" },
        .{ .kernel = "stwo_zig_memory_address_base_trace_resident", .argument = "constant uint &multiplicity_words [[buffer(4)]]" },
        .{ .kernel = "stwo_zig_memory_value_base_trace_resident", .argument = "constant uint *output_offsets [[buffer(8)]]" },
        .{ .kernel = "stwo_zig_memory_rc99_count_resident", .argument = "constant uint &count_offset [[buffer(6)]]" },
        .{ .kernel = "stwo_zig_public_memory_seed_resident", .argument = "constant uint &small_count_words [[buffer(8)]]" },
    };
    for (bindings) |binding| {
        const declaration = try kernelDeclaration(cairo_trace_source, binding.kernel);
        try std.testing.expect(std.mem.indexOf(u8, declaration, binding.argument) != null);
    }
}

test "Cairo witness feed is isolated in its owning shader unit with a stable ABI" {
    const name = "stwo_zig_witness_feed_counts";
    try std.testing.expectEqual(@as(usize, 0), countKernelDeclarations(legacy_source, name));
    try std.testing.expectEqual(@as(usize, 1), countKernelDeclarations(cairo_witness_feed_source, name));
    try std.testing.expectEqual(@as(usize, 1), countKernelDeclarations(amalgamated_source, name));
    try std.testing.expect(std.mem.indexOf(u8, cairo_witness_feed_source, "#include \"stwo_zig/base.metal\"") != null);

    const declaration = try kernelDeclaration(cairo_witness_feed_source, name);
    const arguments = [_][]const u8{
        "device atomic_uint *arena [[buffer(0)]]",
        "device const uint *descriptors [[buffer(1)]]",
        "device const uint *luts [[buffer(2)]]",
        "device const uint *destination_offsets [[buffer(3)]]",
        "device const uint *source_offsets [[buffer(4)]]",
        "constant uint &column_length [[buffer(5)]]",
        "constant uint &descriptor_count [[buffer(6)]]",
        "uint row [[thread_position_in_grid]]",
    };
    for (arguments) |argument| {
        try std.testing.expect(std.mem.indexOf(u8, declaration, argument) != null);
    }
}

test "Cairo EC kernels are isolated in their owning shader unit with a stable ABI" {
    const names = [_][]const u8{
        "stwo_zig_felt252_oracle",
        "stwo_zig_ec_op_lookup",
        "stwo_zig_ec_op_witness",
        "stwo_zig_ec_op_base_finalize",
    };
    try expectIsolated(cairo_ec_op_source, names[0..]);
    const dependencies = [_][]const u8{ "base.metal", "felt252.metal", "ec.metal" };
    for (dependencies) |dependency| {
        try std.testing.expect(std.mem.indexOf(u8, cairo_ec_op_source, dependency) != null);
    }
    const bindings = [_]struct { kernel: []const u8, argument: []const u8 }{
        .{ .kernel = names[0], .argument = "device uint *outputs [[buffer(1)]]" },
        .{ .kernel = names[1], .argument = "uint group_size [[threads_per_threadgroup]]" },
        .{ .kernel = names[2], .argument = "device const uint *multiplicity_offsets [[buffer(4)]]" },
        .{ .kernel = names[3], .argument = "uint2 position [[thread_position_in_grid]]" },
    };
    for (bindings) |binding| {
        const declaration = try kernelDeclaration(cairo_ec_op_source, binding.kernel);
        try std.testing.expect(std.mem.indexOf(u8, declaration, binding.argument) != null);
    }
}

test "circle transforms are isolated with standalone dependencies and fused ABI" {
    var owned: usize = 0;
    for (exports) |entry| {
        if (entry.owner != .circle_transform) continue;
        owned += 1;
        try std.testing.expectEqual(@as(usize, 0), countKernelDeclarations(legacy_source, entry.name));
        try std.testing.expectEqual(@as(usize, 1), countKernelDeclarations(circle_transform_all_source, entry.name));
        try std.testing.expectEqual(@as(usize, 1), countKernelDeclarations(amalgamated_source, entry.name));
    }
    try std.testing.expectEqual(@as(usize, 22), owned);
    const dependencies = [_][]const u8{ "base.metal", "m31.metal", "circle.metal" };
    for (dependencies) |dependency| {
        try std.testing.expect(std.mem.indexOf(u8, circle_transform_source, dependency) != null);
    }
    const declaration = try kernelDeclaration(circle_transform_source, "stwo_zig_circle_rfft_fused_tail_sparse");
    try std.testing.expect(std.mem.indexOf(u8, declaration, "uint lane [[thread_index_in_threadgroup]]") != null);
    try std.testing.expect(std.mem.indexOf(u8, declaration, "uint2 group [[threadgroup_position_in_grid]]") != null);
    const wide_declaration = try kernelDeclaration(
        circle_transform_all_source,
        "stwo_zig_circle_rfft_fused_tail_sparse_wide",
    );
    try std.testing.expect(std.mem.indexOf(u8, wide_declaration, "column_count [[buffer(4)]]") != null);
    const high_declaration = try kernelDeclaration(
        circle_transform_source,
        "stwo_zig_circle_rfft_last_sparse",
    );
    try std.testing.expect(std.mem.indexOf(u8, high_declaration, "column_config [[buffer(4)]]") != null);
    try std.testing.expect(std.mem.indexOf(u8, high_declaration, "tile [[threadgroup(0)]]") != null);
}

test "polynomial evaluation declares standalone field and ABI dependencies" {
    const dependencies = [_][]const u8{
        "#include \"stwo_zig/base.metal\"",
        "#include \"stwo_zig/m31.metal\"",
        "#include \"stwo_zig/extension_fields.metal\"",
        "#include \"stwo_zig/abi_types.metal\"",
    };
    for (dependencies) |dependency| {
        try std.testing.expect(std.mem.indexOf(u8, polynomial_eval_source, dependency) != null);
    }
    try std.testing.expectEqual(@as(usize, 0), std.mem.count(u8, legacy_source, "inline uint m31_reduce"));
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, m31_source, "inline uint m31_reduce"));
    try std.testing.expectEqual(@as(usize, 0), std.mem.count(u8, legacy_source, "inline Qm31Value qm_mul("));
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, extension_fields_source, "inline Qm31Value qm_mul("));
}

test "legacy shader unit declares extracted support dependencies" {
    const dependencies = [_][]const u8{
        "#include \"stwo_zig/blake2s.metal\"",
        "#include \"stwo_zig/m31.metal\"",
        "#include \"stwo_zig/extension_fields.metal\"",
        "#include \"stwo_zig/circle.metal\"",
    };
    for (dependencies) |dependency| {
        try std.testing.expect(std.mem.indexOf(u8, legacy_source, dependency) != null);
    }
}

test "decommit kernels are isolated with standalone dependencies and a stable ABI" {
    var owned: usize = 0;
    for (exports) |entry| {
        if (entry.owner != .decommit) continue;
        owned += 1;
        try std.testing.expectEqual(@as(usize, 0), countKernelDeclarations(legacy_source, entry.name));
        try std.testing.expectEqual(@as(usize, 1), countKernelDeclarations(decommit_kernels_source, entry.name));
        try std.testing.expectEqual(@as(usize, 1), countKernelDeclarations(amalgamated_source, entry.name));
    }
    try std.testing.expectEqual(@as(usize, 10), owned);

    const dependencies = [_][]const u8{
        "#include \"stwo_zig/base.metal\"",
        "#include \"stwo_zig/blake2s.metal\"",
        "#include \"stwo_zig/merkle.metal\"",
        "#include \"stwo_zig/decommit.metal\"",
    };
    for (dependencies) |dependency| {
        try std.testing.expect(std.mem.indexOf(u8, decommit_kernels_source, dependency) != null);
    }

    const bindings = [_]struct { kernel: []const u8, argument: []const u8 }{
        .{ .kernel = "stwo_zig_decommit_normalize_queries_resident", .argument = "constant uint &assembly_capacity [[buffer(8)]]" },
        .{ .kernel = "stwo_zig_decommit_sparse_leaf_group_resident", .argument = "constant uint &prefix_bytes [[buffer(12)]]" },
        .{ .kernel = "stwo_zig_decommit_assemble_trace_resident", .argument = "constant uint &capacity [[buffer(20)]]" },
        .{ .kernel = "stwo_zig_decommit_assemble_fri_resident", .argument = "constant uint &capacity [[buffer(13)]]" },
    };
    for (bindings) |binding| {
        const declaration = try kernelDeclaration(decommit_kernels_source, binding.kernel);
        try std.testing.expect(std.mem.indexOf(u8, declaration, binding.argument) != null);
    }
}

test "Merkle support has one guarded lifted-index owner and no exported kernels" {
    const owned_definitions = [_][]const u8{
        "inline uint lifted_index(",
        "inline uint decommit_lifted_index(",
    };
    for (owned_definitions) |definition| {
        try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, merkle_source, definition));
        try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, amalgamated_source, definition));
        try std.testing.expectEqual(@as(usize, 0), std.mem.count(u8, legacy_source, definition));
    }
    try std.testing.expect(std.mem.startsWith(u8, merkle_source, "#ifndef STWO_ZIG_MERKLE_METAL"));
    try std.testing.expectEqual(@as(usize, 0), std.mem.count(u8, merkle_source, "kernel void stwo_zig_"));
    try std.testing.expect(std.mem.indexOf(u8, merkle_source, "#include \"stwo_zig/base.metal\"") != null);
}

test "decommit support has one guarded private helper owner and no exported kernels" {
    const owned_definitions = [_][]const u8{
        "inline uint decommit_sort_unique(",
        "inline uint decommit_map_query_log(",
        "inline ulong decommit_join_word_offset(",
        "inline ulong decommit_wide_word_offset(",
        "inline bool decommit_contains_sorted(",
        "inline bool decommit_reserve(",
        "inline void decommit_copy_hash(",
        "inline ulong decommit_trace_node_hash(",
    };
    for (owned_definitions) |definition| {
        try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, decommit_source, definition));
        try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, amalgamated_source, definition));
        try std.testing.expectEqual(@as(usize, 0), std.mem.count(u8, legacy_source, definition));
    }
    try std.testing.expect(std.mem.startsWith(u8, decommit_source, "#ifndef STWO_ZIG_DECOMMIT_METAL"));
    try std.testing.expectEqual(@as(usize, 0), std.mem.count(u8, decommit_source, "kernel void stwo_zig_"));
    try std.testing.expect(std.mem.indexOf(u8, decommit_source, "#include \"stwo_zig/base.metal\"") != null);
}

test "circle support has one guarded helper owner and no exported kernels" {
    const owned_definitions = [_][]const u8{
        "struct CircleM31Value",
        "inline uint circle_twiddle(",
        "inline CircleM31Value circle_mul(",
        "inline CircleM31Value circle_pow(",
    };
    for (owned_definitions) |definition| {
        try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, circle_source, definition));
        try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, amalgamated_source, definition));
        try std.testing.expectEqual(@as(usize, 0), std.mem.count(u8, legacy_source, definition));
    }
    try std.testing.expect(std.mem.startsWith(u8, circle_source, "#ifndef STWO_ZIG_CIRCLE_METAL"));
    try std.testing.expectEqual(@as(usize, 0), std.mem.count(u8, circle_source, "kernel void stwo_zig_"));
    try std.testing.expect(std.mem.indexOf(u8, circle_source, "#include \"stwo_zig/base.metal\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, circle_source, "#include \"stwo_zig/m31.metal\"") != null);
}

test "Felt252 EC and witness support have explicit header ownership" {
    const owned_definitions = [_]struct {
        source: []const u8,
        definition: []const u8,
    }{
        .{ .source = felt252_source, .definition = "struct Felt252Metal" },
        .{ .source = ec_source, .definition = "struct EcPointMetal" },
        .{ .source = ec_source, .definition = "struct EcProjectiveMetal" },
        .{ .source = witness_abi_source, .definition = "struct WitnessArgs" },
        .{ .source = witness_tables_source, .definition = "inline uint witness_table_limb" },
        .{ .source = witness_deductions_source, .definition = "void witness_deduce_11" },
    };
    for (owned_definitions) |owned| {
        try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, owned.source, owned.definition));
        try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, amalgamated_source, owned.definition));
        try std.testing.expectEqual(@as(usize, 0), std.mem.count(u8, legacy_source, owned.definition));
    }

    const headers = [_][]const u8{
        felt252_source,
        ec_source,
        witness_abi_source,
        witness_tables_source,
        witness_deductions_source,
    };
    for (headers) |header| {
        try std.testing.expect(std.mem.startsWith(u8, header, "#ifndef STWO_ZIG_"));
        try std.testing.expectEqual(@as(usize, 0), std.mem.count(u8, header, "kernel void stwo_zig_"));
    }
}

test "witness support version owns the generated-library cache boundary" {
    try std.testing.expectEqual(@as(u64, 6), witness_codegen_support_version);
    try std.testing.expect(std.mem.indexOf(u8, witness_abi_source, "struct WitnessArgs") != null);
    try std.testing.expect(std.mem.indexOf(u8, witness_tables_source, "witness_table_limb") != null);
    try std.testing.expect(std.mem.indexOf(u8, witness_deductions_source, "witness_deduce_11") != null);
}

test "transcript is isolated in its owning shader unit with a stable ABI" {
    const transcript_exports = [_][]const u8{
        "stwo_zig_transcript_init_resident",
        "stwo_zig_transcript_mix_resident",
        "stwo_zig_transcript_draw_secure_resident",
        "stwo_zig_transcript_draw_queries_resident",
    };
    for (transcript_exports) |name| {
        try std.testing.expectEqual(@as(usize, 0), countKernelDeclarations(legacy_source, name));
        try std.testing.expectEqual(@as(usize, 1), countKernelDeclarations(transcript_source, name));
    }

    const AbiFragment = struct { source: []const u8, count: usize };
    const abi_fragments = [_]AbiFragment{
        .{ .source = "device uint *arena [[buffer(0)]], constant uint &state_base [[buffer(1)]]", .count = 4 },
        .{ .source = "constant uint &source_base [[buffer(2)]], constant uint &source_words [[buffer(3)]]", .count = 1 },
        .{ .source = "constant uint &destination_base [[buffer(2)]], constant uint &felt_count [[buffer(3)]]", .count = 1 },
        .{ .source = "constant uint &destination_base [[buffer(2)]], constant uint &log_domain_size [[buffer(3)]]", .count = 1 },
        .{ .source = "constant uint &query_count [[buffer(4)]], uint lane [[thread_position_in_grid]]", .count = 1 },
    };
    for (abi_fragments) |fragment| {
        try std.testing.expectEqual(fragment.count, std.mem.count(u8, transcript_source, fragment.source));
    }
    try std.testing.expectEqual(
        @as(usize, 4),
        std.mem.count(u8, transcript_source, "uint lane [[thread_position_in_grid]]"),
    );
}

test "transcript declares only its standalone Blake support dependencies" {
    try std.testing.expectEqual(@as(usize, 0), std.mem.count(u8, legacy_source, "inline void blake2s_compress"));
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, blake2s_source, "inline void blake2s_compress"));
    try std.testing.expect(std.mem.indexOf(u8, transcript_source, "#include \"stwo_zig/base.metal\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, transcript_source, "#include \"stwo_zig/blake2s.metal\"") != null);
}

test "arena resource operations are isolated in their owning shader unit" {
    const name = "stwo_zig_clear_arena_spans";
    try std.testing.expectEqual(@as(usize, 0), countKernelDeclarations(legacy_source, name));
    try std.testing.expectEqual(@as(usize, 1), countKernelDeclarations(arena_ops_source, name));
    try std.testing.expectEqual(
        @as(usize, 1),
        std.mem.count(u8, arena_ops_source, "device const uint *spans [[buffer(1)]]"),
    );
}
