//! Shader ownership, isolation, and exported-kernel ABI tests.

const std = @import("std");
const manifest = @import("manifest.zig");

const Unit = manifest.Unit;
const exports = manifest.exports;
const native_exports = manifest.native_exports;
const native_support_headers = manifest.native_support_headers;
const native_translation_units = manifest.native_translation_units;
const native_amalgamated_source = manifest.native_amalgamated_source;
const amalgamated_source = manifest.amalgamated_source;
const core_shader_abi = manifest.core_shader_abi;
const witness_codegen_support_version = manifest.witness_codegen_support_version;
const isDeferredOwner = manifest.isDeferredOwner;
const legacy_source = manifest.testing.legacy_source;
const fri_resident_source = manifest.testing.fri_resident_source;
const base_source = manifest.testing.base_source;
const blake2s_source = manifest.testing.blake2s_source;
const merkle_source = manifest.testing.merkle_source;
const decommit_source = manifest.testing.decommit_source;
const m31_source = manifest.testing.m31_source;
const extension_fields_source = manifest.testing.extension_fields_source;
const circle_source = manifest.testing.circle_source;
const abi_types_source = manifest.testing.abi_types_source;
const felt252_source = manifest.testing.felt252_source;
const ec_source = manifest.testing.ec_source;
const witness_abi_source = manifest.testing.witness_abi_source;
const witness_tables_source = manifest.testing.witness_tables_source;
const witness_deductions_source = manifest.testing.witness_deductions_source;
const commitments_source = manifest.testing.commitments_source;
const cairo_trace_source = manifest.testing.cairo_trace_source;
const cairo_witness_feed_source = manifest.testing.cairo_witness_feed_source;
const cairo_fixed_tables_source = manifest.testing.cairo_fixed_tables_source;
const cairo_ec_op_source = manifest.testing.cairo_ec_op_source;
const circle_transform_source = manifest.testing.circle_transform_source;
const circle_transform_wide_source = manifest.testing.circle_transform_wide_source;
const circle_transform_all_source = manifest.testing.circle_transform_all_source;
const arena_ops_source = manifest.testing.arena_ops_source;
const transcript_source = manifest.testing.transcript_source;
const composition_source = manifest.testing.composition_source;
const relation_source = manifest.testing.relation_source;
const decommit_kernels_source = manifest.testing.decommit_kernels_source;
const polynomial_eval_source = manifest.testing.polynomial_eval_source;
const riscv_polynomials_source = manifest.testing.riscv_polynomials_source;
const manifestContains = manifest.testing.manifestContains;
const countKernelDeclarations = manifest.testing.countKernelDeclarations;
const kernelDeclaration = manifest.testing.kernelDeclaration;

test "Native core source exactly covers its non-Cairo export ABI" {
    try std.testing.expectEqual(@as(usize, 135), native_exports.len);
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
    try std.testing.expectEqual(@as(usize, 147), exports.len);

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
        "stwo_zig_base_poly_a972dafabb2bf5eee1d1cdb560f3572e",
        "stwo_zig_base_poly_09e5f90f9696d165cc36093de2564888",
        "stwo_zig_base_poly_a74fd0125263cc1e887ee5d726ac99a0",
        "stwo_zig_base_poly_3b018614b76f63e7a28e127029c18704",
        "stwo_zig_base_poly_aa55ec34af78d3f2b74d4b3d06c708a8",
        "stwo_zig_base_poly_0ade2040c246f9cad3919da46161d2fd",
        "stwo_zig_base_poly_6301135c98c38c29971098b60b459397",
        "stwo_zig_base_poly_95bca92bf8e5c8c0cd1438e06c6c8963",
        "stwo_zig_base_poly_373e28e4ebf898ce291ed734807dfa00",
        "stwo_zig_base_poly_1d58ef609255595a37488e277d52585c",
        "stwo_zig_base_poly_208adea2af3accc5bd53faa7807024bb",
        "stwo_zig_base_poly_9b9a12367c3aeb8830ac01bf757fa64a",
        "stwo_zig_base_poly_ebe47c5c0304bddea66f3a2b7c9cd55c",
        "stwo_zig_lookup_poly_6bd1123655f7e5fc662f4e397524645b",
        "stwo_zig_lookup_poly_60369e534e1e31666bb1684e6745500b",
        "stwo_zig_lookup_poly_cae77cf99f2127b1108dc5c1609cc16b",
        "stwo_zig_lookup_poly_d1b44ec0cc8a532f04e4e39fd0bb648e",
        "stwo_zig_lookup_poly_88bafd2b2b2bb614f3a37e2e93f88f8f",
        "stwo_zig_lookup_poly_f0435e9fbbd4a7a98c7c5162bee7d7a9",
        "stwo_zig_lookup_poly_cc2c95d2bff4c999fee2f44e08222252",
        "stwo_zig_lookup_poly_b52a532ad3c7e42bdece0624fb56b8aa",
        "stwo_zig_lookup_poly_b15f9ad4a9abfc83a7cdec6c46ee4ade",
        "stwo_zig_lookup_poly_fcc84457fa16172e164408c12324b2c2",
        "stwo_zig_lookup_poly_ff9bf971cfa80d96e0aa0e50e4b1b89d",
        "stwo_zig_lookup_poly_b63d26046143c546183c7769fee7803a",
        "stwo_zig_lookup_poly_60da0a81177c1f7c118d91080a104856",
        "stwo_zig_lookup_poly_d71f7ff4122659b75334f16e7282cd1e",
        "stwo_zig_lookup_poly_2933fad233d8d72eaaaac264f1f08e46",
        "stwo_zig_lookup_poly_55f49d22b3eefd58176c82e98f534eb1",
        "stwo_zig_lookup_poly_34a73d9627a19782b2486c6dcd96f1fe",
        "stwo_zig_lookup_poly_v2_4495e1dc5d58d71f640d011e5e267fc06fe6adfe54e6405fa20aab1ab4a4f496",
        "stwo_zig_lookup_poly_v2_faadbe548bfa104ae056599d5e4910f9812fc7ddf9179da65d5d5e6fba234d35",
        "stwo_zig_lookup_poly_v2_9ed05c9eac769627c64b0e915e2630d0a51bb6325410ea144d9669b85c480514",
        "stwo_zig_lookup_poly_v2_198678cb3ba8974d902c91452544c7f63c81fc0d10de3a87f612c1e9cb9437a8",
        "stwo_zig_lookup_poly_v2_ec1cb673e29351c380eb472b19293e7ea97ab2030393f54c7bcbb1426ae83aa2",
        "stwo_zig_lookup_poly_v2_edade529adf1f7eb6b09313aad8cc71ff739a71d11e2b40cb6101daf378d8489",
        "stwo_zig_lookup_poly_v2_c95e5383b34ea4ad55aaff5bc8ca9054b9fb9abe15db39e6409374e0dd3b5617",
        "stwo_zig_lookup_poly_v2_b64e1478588595c7a3f7c71371ef1e6f1ceae3dd055c9eb56aa4081cf93e97d1",
        "stwo_zig_lookup_poly_v2_b9e7c8afba03add7dd116b67fd791e19256bc093b6eb47e41ca9ee411608c58a",
        "stwo_zig_lookup_poly_v2_b777199dcff0d3dbb81372f98612beda7bd12bf2d2bc7725f1dab500e07c39d9",
        "stwo_zig_lookup_poly_v2_a0710166b8b3057556c2f5907836c0c82fe3b92fccff4633d504c0ff510b6d93",
        "stwo_zig_lookup_poly_v2_bd8284d4f0c5a7d0cd9dd1f4879d721c70992754e1d5aadf02df9e4f86c15d2c",
        "stwo_zig_lookup_poly_v2_099cc5bddab2ff60effcbef0d7863f6a78e0d7a9fcc78fa43d9603f6798904b3",
        "stwo_zig_lookup_poly_v2_e622d001a5cd368b6efef022e0db61a1ab9e30842ef91e4135c0dc5cbd18eb19",
        "stwo_zig_lookup_poly_v2_1cab02ea628504e58cb4a0dbf15dbca36cccc7cad4f36949bb10265a08cd44cc",
        "stwo_zig_lookup_poly_v2_74e0c5ba6845f3d863a1b821d0f22ea76e38570ccd234b537ea4fb9e8f19bf77",
        "stwo_zig_lookup_poly_v2_e9b9d5d433a734c48921694aa7185fafe3fb15e7bd89dc42261cc4290f894352",
    };
    try std.testing.expectEqual(@as(usize, 51), names.len);
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

test "resident FRI standalone includes are inactive in the amalgamated source" {
    const guard = "#ifndef STWO_ZIG_AMALGAMATED\n";
    const guard_at = std.mem.indexOf(u8, fri_resident_source, guard) orelse
        return error.MissingAmalgamationGuard;
    const guard_end = std.mem.indexOfPos(u8, fri_resident_source, guard_at, "#endif\n") orelse
        return error.MissingAmalgamationGuard;
    const dependencies = [_][]const u8{
        "#include \"stwo_zig/blake2s.metal\"",
        "#include \"stwo_zig/m31.metal\"",
        "#include \"stwo_zig/extension_fields.metal\"",
    };
    for (dependencies) |dependency| {
        const include_at = std.mem.indexOf(u8, fri_resident_source, dependency) orelse
            return error.MissingStandaloneDependency;
        try std.testing.expect(guard_at < include_at and include_at < guard_end);
    }
    try std.testing.expect(std.mem.startsWith(
        u8,
        native_amalgamated_source,
        "#define STWO_ZIG_AMALGAMATED 1\n",
    ));
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
