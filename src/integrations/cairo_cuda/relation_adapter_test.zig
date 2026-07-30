const std = @import("std");
const relation_abi = @import("stwo_cuda_backend").abi.stages.relation;
const field = @import("stwo_cuda_backend").abi.field;
const column = @import("stwo_cuda_backend").runtime.column;
const common = @import("stwo_cuda_backend").runtime.stages.common;
const relation_stage = @import("stwo_cuda_backend").runtime.stages.relation;
const cairo_adapter = @import("stwo_cairo_frontend").adapter;
const proof_plan = @import("stwo_cairo_frontend").proof_plan;
const composition_bundle = @import("stwo_cairo_frontend").witness.composition_bundle;
const feed_bundle = @import("stwo_cairo_frontend").witness.feed_bundle;
const fixed_table_bundle = @import("stwo_cairo_frontend").witness.fixed_table_bundle;
const relation_bundle = @import("stwo_cairo_frontend").witness.relation_bundle;
const witness_bundle = @import("stwo_cairo_frontend").witness.bundle;
const adapter = @import("relation_adapter.zig");

const Fixture = struct {
    allocator: std.mem.Allocator,
    composition: composition_bundle.Bundle,
    relations: relation_bundle.Bundle,
    proof: proof_plan.CairoProofPlan,

    fn init(allocator: std.mem.Allocator) !Fixture {
        var composition = try composition_bundle.Bundle.readFile(
            allocator,
            "vectors/cairo/sn_pie_2_composition.bin",
        );
        errdefer composition.deinit();
        var relations = try relation_bundle.Bundle.readFile(
            allocator,
            "vectors/cairo/cairo_relation_templates.bin",
        );
        errdefer relations.deinit();
        const parts = try allocator.alloc(
            proof_plan.TracePart,
            composition.components.len,
        );
        defer allocator.free(parts);
        const components = try allocator.alloc(
            proof_plan.Component,
            composition.components.len,
        );
        defer allocator.free(components);
        for (
            composition.components,
            parts,
            components,
            0..,
        ) |component, *part, *planned, index| {
            const rows = @as(u32, 1) <<
                @intCast(component.trace_log_size);
            part.* = .{
                .id = .main,
                .rows = .{
                    .real_rows = if (derivedRelationRows(component.label))
                        null
                    else
                        rows,
                    .padded_rows = rows,
                },
            };
            planned.* = .{
                .name = component.label,
                .instance = component.instance,
                .canonical_ordinal = @intCast(index),
                .writer = .recorded_aot,
                .trace_parts = parts[index .. index + 1],
                .producer_edges = if (derivedRelationRows(component.label))
                    proof_plan.gatheredProducerEdges(component.label).?
                else
                    &.{},
                .capacity_feeds = &.{},
            };
        }
        return .{
            .allocator = allocator,
            .composition = composition,
            .relations = relations,
            .proof = try proof_plan.CairoProofPlan.init(
                allocator,
                components,
            ),
        };
    }

    fn deinit(self: *Fixture) void {
        self.proof.deinit();
        self.relations.deinit();
        self.composition.deinit();
        self.* = undefined;
    }
};

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

test "relation adapter fails closed on order descriptor and coverage drift" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();

    std.mem.swap(
        u32,
        &fixture.proof.canonical_order[0],
        &fixture.proof.canonical_order[1],
    );
    try std.testing.expectError(
        adapter.Error.InvalidComponentOrder,
        adapter.Plan.compile(
            std.testing.allocator,
            &fixture.proof,
            fixture.relations,
        ),
    );
    std.mem.swap(
        u32,
        &fixture.proof.canonical_order[0],
        &fixture.proof.canonical_order[1],
    );

    const add = fixture.relations.find("add_opcode") orelse
        return error.MissingTemplate;
    add.traces[0].descriptors[15] = 1;
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        adapter.Plan.compile(
            std.testing.allocator,
            &fixture.proof,
            fixture.relations,
        ),
    );
    add.traces[0].descriptors[15] = 0;

    const memory = fixture.relations.find("memory_id_to_big") orelse
        return error.MissingTemplate;
    const saved_part = memory.traces[1].part;
    memory.traces[1].part = .component;
    try std.testing.expectError(
        adapter.Error.InvalidRelationTrace,
        adapter.Plan.compile(
            std.testing.allocator,
            &fixture.proof,
            fixture.relations,
        ),
    );
    memory.traces[1].part = saved_part;

    var plan = try adapter.Plan.compile(
        std.testing.allocator,
        &fixture.proof,
        fixture.relations,
    );
    defer plan.deinit();
    var uploader = UploadRecorder{};
    try std.testing.expectError(
        adapter.Error.InvalidPreparedInputShape,
        plan.prepareAndUpload(
            std.testing.allocator,
            &uploader,
            std.mem.zeroes(
                @import("stwo_cuda_backend").runtime.stages.relation.DeviceBuffers,
            ),
            &.{},
        ),
    );
}

test "SN2 canonical CUDA ingress derives every device table" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    var plan = try adapter.Plan.compile(
        std.testing.allocator,
        &fixture.proof,
        fixture.relations,
    );
    defer plan.deinit();
    var device = try DeviceFixture.init(std.testing.allocator, &plan);
    defer device.deinit();
    var uploader = UploadRecorder{};

    const prepared = try plan.prepareAndUpload(
        std.testing.allocator,
        &uploader,
        device.buffers,
        device.instances,
    );
    defer relation_stage.deinit(std.testing.allocator, prepared);

    try std.testing.expectEqual(@as(u32, 180), uploader.calls);
    try std.testing.expectEqual(
        plan.descriptor_storage.len,
        uploader.descriptor_records,
    );
    try std.testing.expectEqual(
        plan.geometry.len,
        uploader.geometry_records,
    );
    try std.testing.expectEqual(
        device.source_storage[0].address,
        uploader.first_pointer,
    );
    try std.testing.expectEqualSlices(
        u8,
        &plan.topology_identity,
        &relation_stage.topologyIdentity(prepared),
    );
}

test "SN2 canonical CUDA ingress rejects lookup undersize and tail alias" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    var plan = try adapter.Plan.compile(
        std.testing.allocator,
        &fixture.proof,
        fixture.relations,
    );
    defer plan.deinit();
    var device = try DeviceFixture.init(std.testing.allocator, &plan);
    defer device.deinit();
    var uploader = UploadRecorder{};

    const source_length = device.source_storage[0].len;
    device.source_storage[0].len = plan.instances[0].geometry.rows;
    try std.testing.expect(device.source_storage[0].len < source_length);
    try std.testing.expectError(
        error.InvalidDeviceAddress,
        plan.prepareAndUpload(
            std.testing.allocator,
            &uploader,
            device.buffers,
            device.instances,
        ),
    );
    try std.testing.expectEqual(@as(u32, 0), uploader.calls);

    device.source_storage[0].len = source_length;
    device.output_storage[0].address =
        device.source_storage[0].address +
        @as(usize, plan.instances[0].geometry.rows) * @sizeOf(u32);
    try std.testing.expectError(
        error.OverlappingDeviceRange,
        plan.prepareAndUpload(
            std.testing.allocator,
            &uploader,
            device.buffers,
            device.instances,
        ),
    );
    try std.testing.expectEqual(@as(u32, 0), uploader.calls);
}

test "relation adapter enforces Rust layout-domain bounds" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();

    const memory_address = fixture.relations.find(
        "memory_address_to_id",
    ) orelse return error.MissingTemplate;
    const saved_chunks = memory_address.traces[0].layout_arg;
    memory_address.traces[0].layout_arg = 2048;
    try std.testing.expectError(
        adapter.Error.InvalidProofGeometry,
        adapter.Plan.compile(
            std.testing.allocator,
            &fixture.proof,
            fixture.relations,
        ),
    );
    memory_address.traces[0].layout_arg = saved_chunks;

    const xor = fixture.proof.find("verify_bitwise_xor_12") orelse
        return error.MissingRelationComponent;
    const xor_parts: []proof_plan.TracePart = @constCast(xor.trace_parts);
    const saved_rows = xor_parts[0].rows;
    xor_parts[0].rows = .{
        .real_rows = 1 << 19,
        .padded_rows = 1 << 19,
    };
    try std.testing.expectError(
        adapter.Error.InvalidProofGeometry,
        adapter.Plan.compile(
            std.testing.allocator,
            &fixture.proof,
            fixture.relations,
        ),
    );
    xor_parts[0].rows = saved_rows;
}

const device_owner: usize = 71;
const device_generation: u64 = 13;

const DeviceFixture = struct {
    allocator: std.mem.Allocator,
    buffers: relation_stage.DeviceBuffers,
    instances: []adapter.DeviceInstanceBinding,
    source_storage: []common.Words,
    output_storage: []common.Words,

    fn init(
        allocator: std.mem.Allocator,
        plan: *const adapter.Plan,
    ) !DeviceFixture {
        var source_count: usize = 0;
        var output_count: usize = 0;
        for (plan.instances) |instance| {
            source_count = try checkedAdd(source_count, instance.source_pointer_count);
            output_count = try checkedAdd(
                output_count,
                try mul(instance.geometry.columns, 4),
            );
        }
        const instances = try allocator.alloc(
            adapter.DeviceInstanceBinding,
            plan.instances.len,
        );
        errdefer allocator.free(instances);
        const sources = try allocator.alloc(common.Words, source_count);
        errdefer allocator.free(sources);
        const outputs = try allocator.alloc(common.Words, output_count);
        errdefer allocator.free(outputs);

        var cursor: usize = 0x10_0000;
        var source_cursor: usize = 0;
        var output_cursor: usize = 0;
        for (plan.instances, instances) |instance, *resident| {
            const source_end = try checkedAdd(
                source_cursor,
                instance.source_pointer_count,
            );
            const source_columns = sources[source_cursor..source_end];
            for (source_columns, 0..) |*source, source_index| {
                const extent = if (instance.layout == .lookup_words)
                    try mul(
                        instance.geometry.rows,
                        instance.lookup_word_columns,
                    )
                else
                    instance.geometry.rows;
                if (instance.layout == .lookup_words and source_index != 0)
                    return error.InvalidTestFixture;
                source.* = try deviceSlice(u32, &cursor, extent);
            }
            const coordinates = try mul(instance.geometry.columns, 4);
            const output_end = try checkedAdd(output_cursor, coordinates);
            const output_columns = outputs[output_cursor..output_end];
            for (output_columns) |*output| {
                output.* = try deviceSlice(
                    u32,
                    &cursor,
                    instance.geometry.rows,
                );
            }
            resident.* = .{
                .source_pointer_table = try deviceSlice(
                    u32,
                    &cursor,
                    try mul(instance.source_pointer_count, 2),
                ),
                .source_columns = source_columns,
                .descriptor_storage = try deviceSlice(
                    u32,
                    &cursor,
                    try mul(
                        instance.geometry.columns,
                        relation_abi.descriptor_words,
                    ),
                ),
                .output_pointer_table = try deviceSlice(
                    u32,
                    &cursor,
                    try mul(coordinates, 2),
                ),
                .output_coordinates = output_columns,
                .denominator_slab = try deviceSlice(
                    field.SecureField,
                    &cursor,
                    try mul(
                        instance.geometry.rows,
                        instance.geometry.columns,
                    ),
                ),
                .claimed_sum = try deviceSlice(
                    field.SecureField,
                    &cursor,
                    1,
                ),
            };
            source_cursor = source_end;
            output_cursor = output_end;
        }
        std.debug.assert(source_cursor == sources.len);
        std.debug.assert(output_cursor == outputs.len);

        const count = plan.instances.len;
        const pointer_table_words = try mul(count, 2);
        const scratch_words = try plan.topology().scratchWords();
        const buffers = relation_stage.DeviceBuffers{
            .drawn_z_alpha = try deviceSlice(
                field.SecureField,
                &cursor,
                2,
            ),
            .alpha_powers = try deviceSlice(
                field.SecureField,
                &cursor,
                plan.max_alpha_powers,
            ),
            .z = try deviceSlice(field.SecureField, &cursor, 1),
            .source_tables = try deviceSlice(
                u32,
                &cursor,
                pointer_table_words,
            ),
            .descriptors = try deviceSlice(
                u32,
                &cursor,
                pointer_table_words,
            ),
            .output_tables = try deviceSlice(
                u32,
                &cursor,
                pointer_table_words,
            ),
            .denominator_slabs = try deviceSlice(
                u32,
                &cursor,
                pointer_table_words,
            ),
            .geometry = try deviceSlice(
                relation_abi.Geometry,
                &cursor,
                count,
            ),
            .claimed_sums = try deviceSlice(
                u32,
                &cursor,
                pointer_table_words,
            ),
            .reduction_partials = try deviceSlice(
                u32,
                &cursor,
                scratch_words,
            ),
            .scan_block_sums = try deviceSlice(
                u32,
                &cursor,
                scratch_words,
            ),
        };
        return .{
            .allocator = allocator,
            .buffers = buffers,
            .instances = instances,
            .source_storage = sources,
            .output_storage = outputs,
        };
    }

    fn deinit(self: *DeviceFixture) void {
        self.allocator.free(self.output_storage);
        self.allocator.free(self.source_storage);
        self.allocator.free(self.instances);
        self.* = undefined;
    }
};

const UploadRecorder = struct {
    calls: u32 = 0,
    descriptor_records: usize = 0,
    geometry_records: usize = 0,
    first_pointer: usize = 0,

    pub fn uploadSlice(
        self: *UploadRecorder,
        comptime F: type,
        destination: column.DeviceSlice(F),
        source: []const F,
    ) !void {
        if (destination.len != source.len) return error.InvalidUpload;
        if (self.calls == 0 and F == u32 and source.len >= 2) {
            self.first_pointer =
                @as(usize, source[0]) |
                (@as(usize, source[1]) << 32);
        }
        if (F == relation_abi.ColumnDescriptor)
            self.descriptor_records += source.len;
        if (F == relation_abi.Geometry)
            self.geometry_records += source.len;
        self.calls += 1;
    }
};

fn deviceSlice(
    comptime F: type,
    cursor: *usize,
    len: usize,
) !column.DeviceSlice(F) {
    if (len == 0) return error.InvalidTestFixture;
    const address = std.mem.alignForward(usize, cursor.*, @alignOf(F));
    const bytes = try mul(len, @sizeOf(F));
    cursor.* = try checkedAdd(address, bytes);
    return .{
        .address = address,
        .len = len,
        .owner = device_owner,
        .generation = device_generation,
    };
}

fn derivedRelationRows(component: []const u8) bool {
    return std.mem.eql(u8, component, "blake_round") or
        std.mem.eql(u8, component, "partial_ec_mul_window_bits_18") or
        std.mem.eql(u8, component, "cube_252");
}

fn expectedRelationRealRows(component: []const u8, padded_rows: u32) u32 {
    if (std.mem.eql(u8, component, "blake_round")) return 655_360;
    if (std.mem.eql(u8, component, "partial_ec_mul_window_bits_18"))
        return 917_504;
    if (std.mem.eql(u8, component, "cube_252")) return 499_712;
    return padded_rows;
}

fn checkedAdd(left: anytype, right: anytype) !usize {
    const lhs = std.math.cast(usize, left) orelse return error.SizeOverflow;
    const rhs = std.math.cast(usize, right) orelse return error.SizeOverflow;
    return std.math.add(usize, lhs, rhs) catch error.SizeOverflow;
}

fn mul(left: anytype, right: anytype) !usize {
    const lhs = std.math.cast(usize, left) orelse return error.SizeOverflow;
    const rhs = std.math.cast(usize, right) orelse return error.SizeOverflow;
    return std.math.mul(usize, lhs, rhs) catch error.SizeOverflow;
}

fn findInstance(
    plan: *const adapter.Plan,
    name: []const u8,
) ?*const adapter.Instance {
    for (plan.instances) |*instance| {
        if (std.mem.eql(u8, instance.component, name)) return instance;
    }
    return null;
}

fn ceilDiv(value: u32, divisor: u32) u32 {
    return value / divisor + @intFromBool(value % divisor != 0);
}

fn inverseRows(rows: u32) u32 {
    const log_rows = std.math.log2_int(u32, rows);
    return if (log_rows == 0)
        1
    else
        @as(u32, 1) << @intCast(31 - log_rows);
}
