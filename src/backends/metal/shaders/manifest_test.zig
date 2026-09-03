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
const poseidon2_m31_source = manifest.testing.poseidon2_m31_source;
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
    try std.testing.expectEqual(@as(usize, 165), native_exports.len);
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
    try std.testing.expectEqual(@as(usize, 177), exports.len);

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

test "commitment shader bindings match core ABI version 22" {
    try std.testing.expectEqual(@as(u32, 22), core_shader_abi);
    const bindings = [_]struct { kernel: []const u8, argument: []const u8 }{
        .{ .kernel = "stwo_zig_blake2s_leaves", .argument = "prefix_bytes [[buffer(7)]]" },
        .{ .kernel = "stwo_zig_blake2s_parents", .argument = "prefix_bytes [[buffer(4)]]" },
        .{ .kernel = "stwo_zig_blake2s_parents_sparse", .argument = "prefix_bytes [[buffer(5)]]" },
        .{ .kernel = "stwo_zig_blake2s_parent_tail_sparse", .argument = "transcript_config [[buffer(7)]]" },
        .{ .kernel = "stwo_zig_poseidon2_m31_leaves", .argument = "unused_prefix_bytes [[buffer(7)]]" },
        .{ .kernel = "stwo_zig_poseidon2_m31_leaves_wide", .argument = "device const ulong *column_offsets [[buffer(1)]]" },
        .{ .kernel = "stwo_zig_decommit_gather_tree_values_resident_wide", .argument = "constant ulong *column_offsets [[buffer(1)]]" },
        .{ .kernel = "stwo_zig_poseidon2_m31_leaf_absorb_resident", .argument = "unused_leaf_seed [[buffer(9)]]" },
        .{ .kernel = "stwo_zig_poseidon2_m31_leaf_absorb_compact_resident", .argument = "unused_leaf_seed [[buffer(11)]]" },
        .{ .kernel = "stwo_zig_poseidon2_m31_leaf_state_digest_resident_v1", .argument = "destination_offset [[buffer(2)]]" },
        .{ .kernel = "stwo_zig_poseidon2_m31_parents", .argument = "unused_prefix_bytes [[buffer(4)]]" },
        .{ .kernel = "stwo_zig_poseidon2_m31_parents_sparse", .argument = "unused_prefix_bytes [[buffer(5)]]" },
        .{ .kernel = "stwo_zig_poseidon2_m31_parent_tail_sparse", .argument = "transcript_config [[buffer(7)]]" },
        .{ .kernel = "stwo_zig_fri_packed_leaves_resident", .argument = "prefix_bytes [[buffer(7)]]" },
        .{ .kernel = "stwo_zig_poseidon2_m31_fri_packed_leaves_resident", .argument = "unused_prefix_bytes [[buffer(7)]]" },
        .{ .kernel = "stwo_zig_qm31_to_coordinates", .argument = "prefix_bytes [[buffer(5)]]" },
        .{ .kernel = "stwo_zig_fri_fold_line", .argument = "prefix_bytes [[buffer(8)]]" },
        .{ .kernel = "stwo_zig_quotient_domain_points_resident", .argument = "mode [[buffer(6)]]" },
        .{ .kernel = "stwo_zig_quotient_partials_raw", .argument = "partials [[buffer(9)]]" },
        .{ .kernel = "stwo_zig_quotient_combine_partials_raw", .argument = "row_count [[buffer(9)]]" },
        .{ .kernel = "stwo_zig_sampled_barycentric_domain_v1", .argument = "half_coset_step_size [[buffer(4)]]" },
        .{ .kernel = "stwo_zig_sampled_barycentric_evaluate_many_v1", .argument = "device const ulong *column_offsets [[buffer(1)]]" },
    };
    for (bindings) |binding| {
        const declaration = try kernelDeclaration(amalgamated_source, binding.kernel);
        try std.testing.expect(std.mem.indexOf(u8, declaration, binding.argument) != null);
    }
}

test "Poseidon2 M31 commitment support has one guarded exact owner" {
    const helpers = [_][]const u8{
        "inline void stwo_zig_poseidon2_permute(",
        "inline void stwo_zig_poseidon2_leaf_init(",
        "inline void stwo_zig_poseidon2_leaf_absorb(",
        "inline void stwo_zig_poseidon2_leaf_finish(",
        "inline void stwo_zig_poseidon2_parent(",
    };
    for (helpers) |helper| {
        try std.testing.expectEqual(
            @as(usize, 1),
            std.mem.count(u8, poseidon2_m31_source, helper),
        );
        try std.testing.expectEqual(
            @as(usize, 1),
            std.mem.count(u8, native_amalgamated_source, helper),
        );
    }
    try std.testing.expect(std.mem.startsWith(
        u8,
        poseidon2_m31_source,
        "#ifndef STWO_ZIG_POSEIDON2_M31_METAL",
    ));
    try std.testing.expectEqual(
        @as(usize, 0),
        std.mem.count(u8, poseidon2_m31_source, "kernel void stwo_zig_"),
    );
    try std.testing.expect(std.mem.indexOf(
        u8,
        poseidon2_m31_source,
        "constant uint stwo_zig_poseidon2_external_rounds[8][16]",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        poseidon2_m31_source,
        "constant uint stwo_zig_poseidon2_internal_rounds[14]",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        poseidon2_m31_source,
        "constant uint stwo_zig_poseidon2_internal_diagonal[16]",
    ) != null);
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
        "stwo_zig_base_poly_e3d97ada62a6ad9f06872ffebf334097",
        "stwo_zig_base_poly_94bb6ee080d963f1a9b89ba8836e6cbf",
        "stwo_zig_base_poly_43fb3f4df23ca371514fbd130360efba",
        "stwo_zig_base_poly_c435f0a2ee25c59eec1ebd9f12b995cd",
        "stwo_zig_base_poly_116f3173573043d8dc56aa23e5c1fac4",
        "stwo_zig_base_poly_63ea0b65e576f67691cdb43d14a7590b",
        "stwo_zig_base_poly_782a4d5d838c828e4ae55bb81b63e389",
        "stwo_zig_base_poly_0b0c9beaa20a9460c6d8ecfdfe560eba",
        "stwo_zig_base_poly_766a542bb547c7b4eaf4c8a8fb9eef52",
        "stwo_zig_base_poly_a995060c2a616369140d09438c7dac67",
        "stwo_zig_base_poly_9228c4a31e483b8e787375ff1354be9a",
        "stwo_zig_base_poly_c20d068f8ff248590d22364c7c7d5649",
        "stwo_zig_base_poly_4a95ed38e5a6795e8a84b0817ddd37e1",
        "stwo_zig_base_poly_706ca0b14e34ec043cbf5f04e14fb315",
        "stwo_zig_base_poly_40d34cb41f90634e26f0b2bb88a77110",
        "stwo_zig_base_poly_5d744c2fbb612ce7e9954dfd6cc1b4b7",
        "stwo_zig_base_poly_903175038c36e2a6aad8376003874197",
        "stwo_zig_lookup_poly_a5980ef351d2fafc7a22e5aa40300954",
        "stwo_zig_lookup_poly_e5715747fc906de9684a84af2d392d1e",
        "stwo_zig_lookup_poly_8a132b1e9e82b54afcec47fe86f30324",
        "stwo_zig_lookup_poly_bed36219333c2c4ad3c08cfdfda0e8a2",
        "stwo_zig_lookup_poly_020adcddb227238a71dcd523f9c87a7f",
        "stwo_zig_lookup_poly_d6611c9189072c08839d56f6496f63ed",
        "stwo_zig_lookup_poly_94aa7ee9c1399f0ac1615227be890e54",
        "stwo_zig_lookup_poly_ff8f5638e589be25d994070f031c73f4",
        "stwo_zig_lookup_poly_04a5ee0118c370d4f4be88a43aa90c1b",
        "stwo_zig_lookup_poly_71a7dea9a6d87e457404d7286bf51e2b",
        "stwo_zig_lookup_poly_c98fc3b8440d536b2dd11e209cf33406",
        "stwo_zig_lookup_poly_c7ef2b87fccb92355969d231b02a1d52",
        "stwo_zig_lookup_poly_7187bd253b26502c413540ac56eccb23",
        "stwo_zig_lookup_poly_ae8631b5be628fa89a790444be02b7b1",
        "stwo_zig_lookup_poly_d7203c97e13213534f5bd98272130f81",
        "stwo_zig_lookup_poly_fe8c4b8e3259f973cd85613a2dd582bc",
        "stwo_zig_lookup_poly_43726bbe802a5a24b6c16a4bc093608b",
        "stwo_zig_lookup_poly_v2_6e35df3dbb1bb66f7c23e82cdf0f6705509c4f08e5719edab77049660d8e632d",
        "stwo_zig_lookup_poly_v2_253283e6dfe6bf332f2e466400c1f09394999e7935e86d6bb99a351d8d0b1f49",
        "stwo_zig_lookup_poly_v2_28bc2d54b9a33dccb35df8513dc35a810077488a2f4be0c88b5d36a55a9e8bf8",
        "stwo_zig_lookup_poly_v2_be13b51301211f686fd16c2f88309d8f847af74402b7d38c61ef79b645d99f79",
        "stwo_zig_lookup_poly_v2_275d7261fb64f5cf5fc049ceac6422a7d6e64f153e09f81ddcf3311c1e2ffaa6",
        "stwo_zig_lookup_poly_v2_c21e7087e658c83a4ea68ba0339efa466e9023c10538de1236d5e94f360cd70f",
        "stwo_zig_lookup_poly_v2_6e0f5b41382a11695ffc997f00f28eb2a1fd365fac56419e6a58bd35fcecaebc",
        "stwo_zig_lookup_poly_v2_330b38988296b847ce7943460949e4339ec66db537e4d03491747b2c39b920c0",
        "stwo_zig_lookup_poly_v2_77f9c3e7ba9b17eb361ff2af6220464a5777f3a52ef415c3524ac42ab6e32f2c",
        "stwo_zig_lookup_poly_v2_69a3e73ed85579645e6ee7eee831fcd273dc41967143d39561a8b07d44d4b8b7",
        "stwo_zig_lookup_poly_v2_17d893819094787c341d61e34fc145d907ae4f229fc5bdf675450f9cbfc783e7",
        "stwo_zig_lookup_poly_v2_c52d555f957bd0bb3a403a52ba9a00707ea38b95680598413ab0c999a4f2e212",
        "stwo_zig_lookup_poly_v2_1d2cb31b377e1584858df2e1571ab50af833573e09a8e92b509736d894751ff5",
        "stwo_zig_lookup_poly_v2_a58738eaf81c1bd3c20292b4d470433552c7c5bef4faf841e4da8e2a5a04681a",
        "stwo_zig_lookup_poly_v2_a5c335d39317cb0ece5d0ffe5dd536cba3b9c4c84da54f5c8876a3b6cd5520f4",
        "stwo_zig_lookup_poly_v2_23bb5dc1410c56ceab84080bd3239e6c9156f3761b93508f773dee7e448a70dc",
        "stwo_zig_lookup_poly_v2_64c076e4946245d3c0f988997bf90b10774d23a6344d856e147c744b2df6d98c",
        "stwo_zig_base_poly_8ae392ed1a7274608734b90ddc05e147",
        "stwo_zig_base_poly_7be9f94a181c86f487035579b75a3c09",
        "stwo_zig_base_poly_252a366d21097cfa39ddc55b4c8d3732",
        "stwo_zig_base_poly_3ff26f48f99514ff96f9e6242e02689c",
        "stwo_zig_lookup_poly_bfaf5e2aa44bc0bce57377b16d8362a7",
        "stwo_zig_base_poly_e13d2efe7ad236638a213d15673065f1",
        "stwo_zig_base_poly_e7e0dab59a4ca045df197c03e1cde944",
        "stwo_zig_base_poly_b0c8b0812b31ac11d0ed355fdffceaeb",
        "stwo_zig_base_poly_ba19de000ba4a34803e344cadd255681",
        "stwo_zig_lookup_poly_eadeb11637b6b8b330635af67876a763",
    };
    try std.testing.expectEqual(@as(usize, 61), names.len);
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
        "#include \"stwo_zig/circle.metal\"",
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
