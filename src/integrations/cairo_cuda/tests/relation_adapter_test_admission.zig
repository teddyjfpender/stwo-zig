//! admission cases; fixture authority is shared with the other test owners.
const std = @import("std");
const relation_abi = @import("stwo_cuda_backend").abi.stages.relation;
const cairo_adapter = @import("stwo_cairo_frontend").adapter;
const proof_plan = @import("stwo_cairo_frontend").proof_plan;
const composition_bundle = @import("stwo_cairo_frontend").witness.composition_bundle;
const feed_bundle = @import("stwo_cairo_frontend").witness.feed_bundle;
const fixed_table_bundle = @import("stwo_cairo_frontend").witness.fixed_table_bundle;
const relation_bundle = @import("stwo_cairo_frontend").witness.relation_bundle;
const witness_bundle = @import("stwo_cairo_frontend").witness.bundle;
const adapter = @import("../relation_adapter.zig");

const Support = @import("relation_adapter_test_support.zig");
const Fixture = Support.Fixture;
const expectedRelationRealRows = Support.expectedRelationRealRows;
const findInstance = Support.findInstance;
const ceilDiv = Support.ceilDiv;
const inverseRows = Support.inverseRows;

test "canonical CUDA relations bind current opcode builtin and split memory families" {
    const allocator = std.testing.allocator;
    var programs = try witness_bundle.Bundle.readFile(allocator, "vectors/cairo/official/witness_programs_v1.bin");
    defer programs.deinit();
    var topology = try @import("stwo_cairo_frontend").witness.feed_topology.readOfficial(allocator, "vectors/cairo/official/witness_feed_topology_v1.json");
    defer topology.deinit();
    var implicit = try relation_bundle.Bundle.readFile(allocator, "vectors/cairo/cairo_relation_templates.bin");
    defer implicit.deinit();
    const names = [_][]const u8{ "add_ap_opcode", "add_mod_builtin", "blake_round", "partial_ec_mul_window_bits_9", "memory_address_to_id", "memory_id_to_big", "memory_id_to_small" };
    const part = [_]proof_plan.TracePart{.{ .id = .main, .rows = .{ .real_rows = 16, .padded_rows = 16 } }};
    var components: [names.len]proof_plan.Component = undefined;
    for (names, &components, 0..) |name, *component, index| {
        component.* = .{ .name = name, .canonical_ordinal = @intCast(index), .writer = if (index < 4) .recorded_aot else .memory_trace, .trace_parts = &part, .producer_edges = &.{}, .capacity_feeds = &.{} };
    }
    var proof = try proof_plan.CairoProofPlan.init(allocator, &components);
    defer proof.deinit();
    var plan = try adapter.Plan.compileCanonical(allocator, &proof, programs, topology, implicit);
    defer plan.deinit();
    try std.testing.expectEqual(names.len, plan.instances.len);
    for (plan.instances[0..4]) |instance| {
        const source = topology.find(instance.component).?;
        try std.testing.expectEqual(source.logup_columns.len, instance.descriptors.len);
        try std.testing.expectEqual(source.lookup_words_per_row, instance.lookup_word_columns);
    }
    try std.testing.expectEqual(@as(u32, 2), plan.instances[0].descriptors[0].first.multiplicity_kind);
    try std.testing.expectEqual(relation_bundle.SourceLayout.memory_big, plan.instances[5].layout);
    try std.testing.expectEqual(relation_bundle.SourceLayout.memory_small, plan.instances[6].layout);
    try std.testing.expect(!std.mem.allEqual(u8, &plan.topology_identity, 0));
}

test "SN2 relation adapter preserves canonical heterogeneous topology" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    var plan = try adapter.Plan.compile(
        std.testing.allocator,
        &fixture.proof,
        fixture.relations,
    );
    defer plan.deinit();

    try std.testing.expectEqual(@as(usize, 58), plan.instances.len);
    try std.testing.expectEqual(@as(usize, 567), plan.descriptor_storage.len);
    try std.testing.expectEqual(@as(u32, 126), plan.max_alpha_powers);
    try std.testing.expectEqual(@as(u32, 1_324_500), plan.total_pair_blocks);
    try std.testing.expectEqual(
        @as(u32, 331_131),
        plan.total_inverse_blocks,
    );
    try std.testing.expectEqual(@as(u32, 150_748), plan.total_row_blocks);

    const shape = try plan.preparedInputShape();
    try std.testing.expectEqual(@as(u32, 58), shape.instance_count);
    try std.testing.expectEqual(@as(u32, 116), shape.top_level_pointer_words);
    try std.testing.expectEqual(@as(u64, 280), shape.source_pointer_words);
    // Only XOR12 and the three memory trace families require their original
    // rows after the main commitment interpolates its coefficient spans.
    try std.testing.expectEqual(@as(u64, 76_808_192), shape.retained_base_words);
    try std.testing.expectEqual(@as(u64, 9_072), shape.descriptor_words);
    try std.testing.expectEqual(
        @as(u64, 4_536),
        shape.output_pointer_words,
    );
    try std.testing.expectEqual(
        @as(u64, 339_071_248),
        shape.denominator_secure_fields,
    );
    try std.testing.expectEqual(
        @as(u64, 1_356_284_992),
        shape.interaction_coordinate_cells,
    );
    try std.testing.expectEqual(@as(u32, 602_992), shape.scratch_words);

    var expected_pair_first: u32 = 0;
    var expected_inverse_first: u32 = 0;
    var expected_row_first: u32 = 0;
    var expected_big_offset: u32 = 0;
    for (
        plan.instances,
        fixture.proof.canonical_order,
        0..,
    ) |instance, component_index, canonical_ordinal| {
        const component = fixture.proof.components[component_index];
        try std.testing.expectEqual(
            @as(u32, @intCast(canonical_ordinal)),
            component.canonical_ordinal,
        );
        try std.testing.expectEqual(component_index, instance.component_index);
        try std.testing.expectEqualStrings(
            component.name,
            instance.component,
        );
        try std.testing.expectEqual(
            @as(u32, 1) << @intCast(
                fixture.composition.components[canonical_ordinal]
                    .trace_log_size,
            ),
            instance.geometry.rows,
        );
        const trace = fixture.relations
            .components[instance.relation_component_index]
            .traces[instance.relation_trace_index];
        const rows = instance.geometry.rows;
        const expected_real_rows = expectedRelationRealRows(
            component.name,
            rows,
        );
        const row_blocks = ceilDiv(rows, relation_abi.launch_block);
        const expected = relation_abi.Geometry{
            .pair_first = expected_pair_first,
            .pair_blocks = row_blocks * trace.output_columns,
            .inverse_first = expected_inverse_first,
            .inverse_blocks = ceilDiv(
                rows * trace.output_columns,
                relation_abi.inverse_block_values,
            ),
            .row_first = expected_row_first,
            .row_blocks = row_blocks,
            .rows = rows,
            .columns = trace.output_columns,
            .real_rows = expected_real_rows,
            .source_offset_rows = if (trace.part == .each_memory_big)
                expected_big_offset
            else
                0,
            .inverse_rows = inverseRows(rows),
        };
        try std.testing.expect(std.meta.eql(expected, instance.geometry));
        expected_pair_first += expected.pair_blocks;
        expected_inverse_first += expected.inverse_blocks;
        expected_row_first += expected.row_blocks;
        if (trace.part == .each_memory_big)
            expected_big_offset += rows;
    }
    try std.testing.expectEqual(
        plan.total_pair_blocks,
        expected_pair_first,
    );
    try std.testing.expectEqual(
        plan.total_inverse_blocks,
        expected_inverse_first,
    );
    try std.testing.expectEqual(
        plan.total_row_blocks,
        expected_row_first,
    );

    const big = plan.instances[39];
    const small = plan.instances[40];
    try std.testing.expectEqual(
        relation_bundle.TracePart.each_memory_big,
        big.part,
    );
    try std.testing.expectEqual(
        relation_bundle.TracePart.memory_small,
        small.part,
    );
    try std.testing.expectEqual(@as(u32, 0), big.geometry.source_offset_rows);
    try std.testing.expectEqual(@as(u32, 0), small.geometry.source_offset_rows);
    try std.testing.expectEqual(@as(u32, 1 << 18), big.geometry.rows);
    try std.testing.expectEqual(@as(u32, 1 << 21), small.geometry.rows);
    try std.testing.expectEqual(
        @as(u32, 655_360),
        (findInstance(&plan, "blake_round") orelse
            return error.MissingRelationComponent).geometry.real_rows,
    );
    try std.testing.expectEqual(
        @as(u32, 917_504),
        (findInstance(&plan, "partial_ec_mul_window_bits_18") orelse
            return error.MissingRelationComponent).geometry.real_rows,
    );
    try std.testing.expectEqual(
        @as(u32, 499_712),
        (findInstance(&plan, "cube_252") orelse
            return error.MissingRelationComponent).geometry.real_rows,
    );
}

test "exact adapted SN2 real-row geometry compiles fail closed" {
    const allocator = std.testing.allocator;
    const adapted_path = std.process.getEnvVarOwned(
        allocator,
        "STWO_ZIG_TEST_SN2_ADAPTED_INPUT",
    ) catch return error.SkipZigTest;
    defer allocator.free(adapted_path);
    var input = try cairo_adapter.adapted_input.readFile(
        allocator,
        adapted_path,
    );
    defer input.deinit(allocator);
    var witnesses = try witness_bundle.Bundle.readFile(
        allocator,
        "vectors/cairo/sn_pie_2_witness_programs.bin",
    );
    defer witnesses.deinit();
    var feeds = try feed_bundle.Bundle.readFile(
        allocator,
        "vectors/cairo/sn_pie_2_multiplicity_feeds.bin",
    );
    defer feeds.deinit();
    var fixed_tables = try fixed_table_bundle.Bundle.readFile(
        allocator,
        "vectors/cairo/cairo_fixed_tables.bin",
    );
    defer fixed_tables.deinit();
    var composition = try composition_bundle.Bundle.readFile(
        allocator,
        "vectors/cairo/sn_pie_2_composition.bin",
    );
    defer composition.deinit();
    var relations = try relation_bundle.Bundle.readFile(
        allocator,
        "vectors/cairo/cairo_relation_templates.bin",
    );
    defer relations.deinit();
    var proof = try proof_plan.CairoProofPlan.fromSemanticArtifacts(
        allocator,
        witnesses,
        feeds,
        fixed_tables,
        composition,
        &input,
    );
    defer proof.deinit();
    var plan = try adapter.Plan.compile(allocator, &proof, relations);
    defer plan.deinit();

    const add_ap = findInstance(&plan, "add_ap_opcode") orelse
        return error.MissingRelationComponent;
    try std.testing.expectEqual(@as(u32, 524_288), add_ap.geometry.rows);
    // This relation is multiplicity-driven and deliberately has no row
    // enabler, so its runtime geometry spans the complete padded domain.
    try std.testing.expectEqual(add_ap.geometry.rows, add_ap.geometry.real_rows);
    const cube = findInstance(&plan, "cube_252") orelse
        return error.MissingRelationComponent;
    try std.testing.expectEqual(@as(u32, 524_288), cube.geometry.rows);
    try std.testing.expectEqual(@as(u32, 499_712), cube.geometry.real_rows);
    try std.testing.expect(cube.geometry.real_rows < cube.geometry.rows);
    const blake = findInstance(&plan, "blake_round") orelse
        return error.MissingRelationComponent;
    try std.testing.expectEqual(@as(u32, 655_360), blake.geometry.real_rows);
    const partial = findInstance(
        &plan,
        "partial_ec_mul_window_bits_18",
    ) orelse return error.MissingRelationComponent;
    try std.testing.expectEqual(@as(u32, 917_504), partial.geometry.real_rows);
    try std.testing.expectEqual(
        @as(u64, 1_356_284_992),
        (try plan.preparedInputShape()).interaction_coordinate_cells,
    );
}

test "SN2 CUDA descriptors are word-exact copies of semantic templates" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    var plan = try adapter.Plan.compile(
        std.testing.allocator,
        &fixture.proof,
        fixture.relations,
    );
    defer plan.deinit();

    var second = try adapter.Plan.compile(
        std.testing.allocator,
        &fixture.proof,
        fixture.relations,
    );
    defer second.deinit();
    try std.testing.expectEqualSlices(
        u8,
        &plan.topology_identity,
        &second.topology_identity,
    );
    try std.testing.expect(!std.mem.allEqual(
        u8,
        &plan.topology_identity,
        0,
    ));
    var expected_identity: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(
        &expected_identity,
        "ebd25f86d8c0e291ee00c333f4f3a20f7d1e81f170de582cd9aff8e0f3d469c8",
    );
    try std.testing.expectEqualSlices(
        u8,
        &expected_identity,
        &plan.topology_identity,
    );

    for (plan.instances) |instance| {
        const component =
            fixture.relations.components[instance.relation_component_index];
        const trace = component.traces[instance.relation_trace_index];
        try std.testing.expectEqual(
            trace.output_columns,
            instance.descriptors.len,
        );
        try std.testing.expectEqualSlices(
            u8,
            std.mem.sliceAsBytes(trace.descriptors),
            std.mem.sliceAsBytes(instance.descriptors),
        );
        const bounds = relation_abi.SourceBounds{
            .source_pointer_count = instance.source_pointer_count,
            .lookup_word_columns = instance.lookup_word_columns,
            .max_alpha_powers = plan.max_alpha_powers,
        };
        for (instance.descriptors) |descriptor|
            try descriptor.validate(bounds);
    }
}
