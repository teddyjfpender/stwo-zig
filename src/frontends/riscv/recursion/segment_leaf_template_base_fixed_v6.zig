//! Independent V6 fixed rows with no leaf values: native control and
//! transcript schedules, inactive statement, shared Poseidon marker, and
//! the canonical byte-pair table.
//! Other base rows remain unavailable until their own shape writers pass.
const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const catalog_mod = @import("air/segment_outer_typed_catalog_v2.zig");
const template_mod = @import("air/segment_leaf_wrapper_template_v6.zig");
const shape_mod = @import("air/segment_leaf_wrapper_roster_direct_v4.zig");
const statement = @import("../air/statement.zig");
const schedule = @import("air/verifier_schedule.zig");
const control_air = @import("air/control.zig");
const control_witness = @import("air/control_witness.zig");
const inactive_air = @import("air/statement_input.zig");
const range_air = @import("air/range_check_8_8_contract.zig");
const framework = @import("air/framework_interaction.zig");
const transcript_fixed = @import("transcript_fixed_schedule_v6.zig");
const frame_fixed = @import("transcript_word_template_v6.zig");
const frame_air = @import("air/transcript_word_direct_v4.zig");
const binding_air = @import("air/transcript_binding.zig");
const state_air = @import("air/transcript_state.zig");
const relation_air = @import("air/relation_challenge.zig");
const randomness_air = @import("air/verifier_randomness.zig");
const public_logup_air = @import("air/vm_public_logup_control_v6.zig");
const public_logup = @import("air/vm_public_logup_control_witness_v6.zig");
const public_source = @import("segment_public_outer_source_v2.zig");
const public_components = @import("segment_public_outer_components_v2_contract.zig");
const public_air = @import("air/segment_public_outer_air_v2.zig");
const public_hash_source = @import("segment_public_claim_hash_authority_v2.zig");
const authority_source = @import("segment_leaf_authority_v2.zig");
const merkle_path_air = @import("air/merkle_path.zig");
const query_bits_air = @import("air/query_bits.zig");
const query_bits = @import("air/query_bits_witness.zig");
const query_mapping_air = @import("air/query_mapping.zig");
const query_mapping = @import("air/query_mapping_witness.zig");

pub const PRODUCTION_PROOF_ACTIVATION = false;
/// Rows 13--14 are fixed from the admitted descriptor and wire dimensions.
/// Rows 15--16 still carry graph use counts specialized by the canonical
/// statement topology, so they have no shape-only writer here.
pub const QUALIFIED_ROWS = [_]u8{ 0, 1, 2, 3, 4, 6, 7, 8, 9, 10, 12, 13, 14, 17, 20, 21, 33, 34, 35 };

pub const Writer = struct {
    allocator: std.mem.Allocator,
    manifest: template_mod.TemplateManifestV6,
    control_rows: []control_witness.Row,
    transcript_rows: transcript_fixed.Fixed,
    frame_rows: frame_fixed.Template,
    public_logup_rows: public_logup.PreparedV6,
    query_bit_rows: query_bits.Preprocessed,
    query_mapping_rows: query_mapping.Preprocessed,

    pub fn init(
        allocator: std.mem.Allocator,
        catalog: *const catalog_mod.Catalog,
        shape: shape_mod.Shape,
        component_descs: []const statement.FamilyComponentDesc,
        infra_descs: []const statement.InfraComponentDesc,
        native_plan: *const schedule.Plan,
        core_profile: *const template_mod.CoreProfileV6,
        core_query_mapping: *const @import("air/query_mapping_witness.zig").Reference,
        native_wire_word_count: u32,
        lookup_enabled: bool,
    ) !Writer {
        const manifest = try template_mod.TemplateManifestV6.build(
            allocator,
            catalog,
            shape,
            component_descs,
            infra_descs,
            native_plan,
            core_profile,
            core_query_mapping,
            native_wire_word_count,
            lookup_enabled,
        );
        const control_rows = try controlRowsFromPlan(allocator, native_plan);
        errdefer allocator.free(control_rows);
        var transcript_rows = try transcript_fixed.Fixed.initFromAdmittedShape(
            allocator,
            native_plan,
            native_wire_word_count,
            component_descs,
            infra_descs,
            lookup_enabled,
        );
        errdefer transcript_rows.deinit();
        var frame_rows = try frame_fixed.Template.buildFromAdmittedShape(
            allocator,
            native_plan,
            native_wire_word_count,
            component_descs,
            infra_descs,
            lookup_enabled,
        );
        errdefer frame_rows.deinit();
        const public_logup_rows = try public_logup.preflight(native_plan, &.{ .value = M31.zero() });
        const core_reference = try core_profile.reference();
        var query_bit_rows = try query_bits.Preprocessed.init(allocator, try core_reference.queryBitsReference());
        errdefer query_bit_rows.deinit();
        var query_mapping_rows = try query_mapping.Preprocessed.init(allocator, core_reference);
        errdefer query_mapping_rows.deinit();
        if (manifest.placements[0].geometry.preprocessed_columns != control_air.PREPROCESSED_COLUMN_COUNT or
            manifest.placements[0].geometry.log_size >= @bitSizeOf(usize) or
            control_rows.len > @as(usize, 1) << @intCast(manifest.placements[0].geometry.log_size))
            return error.FixedControlGeometryMismatchV6;
        if (manifest.placements[20].geometry.log_size != query_bit_rows.log_size or
            manifest.placements[21].geometry.log_size != query_mapping_rows.log_size)
            return error.FixedCoreQueryGeometryMismatchV6;
        if (manifest.placements[17].geometry.log_size != public_logup_air.TRACE_LOG_SIZE or
            !std.meta.eql(manifest.placements[17].geometry.semantic_digest, public_logup_air.SEMANTIC_DIGEST))
            return error.FixedPublicLogupGeometryMismatchV6;
        if (manifest.placements[4].geometry.preprocessed_columns != frame_air.PREPROCESSED_COLUMN_COUNT or
            frame_rows.rows.len > @as(usize, 1) << @intCast(manifest.placements[4].geometry.log_size) or
            !std.meta.eql(try frame_rows.preprocessedId(manifest.placements[4].geometry.log_size), manifest.shape.row4_preprocessed_id))
            return error.FixedFrameGeometryMismatchV6;
        return .{ .allocator = allocator, .manifest = manifest, .control_rows = control_rows, .transcript_rows = transcript_rows, .frame_rows = frame_rows, .public_logup_rows = public_logup_rows, .query_bit_rows = query_bit_rows, .query_mapping_rows = query_mapping_rows };
    }

    pub fn deinit(self: *Writer) void {
        self.frame_rows.deinit();
        self.query_mapping_rows.deinit();
        self.query_bit_rows.deinit();
        self.transcript_rows.deinit();
        self.allocator.free(self.control_rows);
        self.* = undefined;
    }

    /// Caller supplies one fresh row-local Tree0 column set. This writer
    /// derives every value from a pinned plan/profile or fixed table formula.
    pub fn writeRow(self: *const Writer, row: u8, columns: [][]M31) !void {
        if (!qualified(row)) return error.UnqualifiedFixedRowV6;
        if (row == 13 or row == 14) try self.manifest.validate();
        const geometry = self.manifest.placements[row].geometry;
        if (geometry.log_size >= @bitSizeOf(usize) or columns.len != geometry.preprocessed_columns)
            return error.FixedBaseGeometryMismatchV6;
        const capacity = @as(usize, 1) << @intCast(geometry.log_size);
        for (columns) |column| {
            if (column.len != capacity) return error.FixedBaseGeometryMismatchV6;
            for (column) |value| if (!value.isZero()) return error.FixedBaseDestinationNotFreshV6;
        }
        switch (row) {
            0 => {
                if (columns.len != control_air.PREPROCESSED_COLUMN_COUNT or self.control_rows.len > capacity)
                    return error.FixedBaseGeometryMismatchV6;
                for (self.control_rows, 0..) |fixed, index| {
                    const values = fixed.values();
                    put(columns, geometry.log_size, index, &values);
                }
            },
            1, 6, 7 => if (columns.len != 0) return error.FixedBaseGeometryMismatchV6,
            2 => {
                if (columns.len != binding_air.PREPROCESSED_COLUMN_COUNT or
                    self.transcript_rows.bindings.len > capacity)
                    return error.FixedBaseGeometryMismatchV6;
                for (self.transcript_rows.bindings, 0..) |fixed, index| {
                    const values = fixed.values();
                    put(columns, geometry.log_size, index, &values);
                }
            },
            3 => {
                if (columns.len != state_air.PREPROCESSED_COLUMN_COUNT or
                    self.transcript_rows.states.len > capacity)
                    return error.FixedBaseGeometryMismatchV6;
                for (self.transcript_rows.states, 0..) |fixed, index| {
                    const values = fixed.values();
                    put(columns, geometry.log_size, index, &values);
                }
            },
            4 => {
                if (columns.len != frame_air.PREPROCESSED_COLUMN_COUNT or self.frame_rows.rows.len > capacity)
                    return error.FixedBaseGeometryMismatchV6;
                for (self.frame_rows.rows, 0..) |fixed, index| {
                    const values = fixed.preprocessing.values();
                    var physical: [frame_air.PREPROCESSED_COLUMN_COUNT]M31 = undefined;
                    @memcpy(physical[0..values.len], &values);
                    physical[values.len] = M31.fromCanonical(fixed.tree0_bridge);
                    put(columns, geometry.log_size, index, &physical);
                }
            },
            8 => {
                if (columns.len != relation_air.PREPROCESSED_COLUMN_COUNT or
                    self.transcript_rows.relations.len > capacity)
                    return error.FixedBaseGeometryMismatchV6;
                for (self.transcript_rows.relations, 0..) |fixed, index| {
                    const values = fixed.values();
                    put(columns, geometry.log_size, index, &values);
                }
            },
            9 => {
                if (columns.len != randomness_air.PREPROCESSED_COLUMN_COUNT or
                    self.transcript_rows.randomness.len > capacity)
                    return error.FixedBaseGeometryMismatchV6;
                for (self.transcript_rows.randomness, 0..) |fixed, index| {
                    const values = fixed.values();
                    put(columns, geometry.log_size, index, &values);
                }
            },
            10 => {
                if (columns.len != inactive_air.PREPROCESSED_COLUMN_COUNT or
                    geometry.log_size != catalog_mod.INACTIVE_STATEMENT_LOG_SIZE)
                    return error.FixedBaseGeometryMismatchV6;
                // V2's row-10 is explicitly inactive in every physical lane.
            },
            12, 14 => {
                const first: usize = switch (row) {
                    12 => 0,
                    14 => public_source.PUBLICATION_SEAL_START,
                    else => unreachable,
                };
                const count: usize = switch (row) {
                    12 => public_source.PUBLICATION_HEADER_WORD_COUNT,
                    14 => public_source.PUBLICATION_SEAL_WORD_COUNT,
                    else => unreachable,
                };
                const expected_width: usize = switch (row) {
                    12 => public_air.PublicationHeader.PREPROCESSED_COLUMN_COUNT,
                    14 => public_air.PublicationSeal.PREPROCESSED_COLUMN_COUNT,
                    else => unreachable,
                };
                if (columns.len != expected_width or count > capacity)
                    return error.FixedBaseGeometryMismatchV6;
                for (0..count) |index| {
                    const fixed = try publicationRow(first + index, self.manifest.shape.native_wire_word_count, M31.zero());
                    const logical = public_components.logicalRow(fixed);
                    put(columns, geometry.log_size, index, logical[public_air.PublicationHeader.PHYSICAL_MAIN_COLUMN_COUNT..][0..columns.len]);
                }
            },
            13 => {
                if (columns.len != public_air.NativePublicSums.PREPROCESSED_COLUMN_COUNT)
                    return error.FixedBaseGeometryMismatchV6;
                const descriptor_count = try std.math.add(usize, self.manifest.shape.component_descriptors, self.manifest.shape.infra_descriptors);
                const preimage_words = try std.math.add(usize, authority_source.AUTHORITY_HASH_FIXED_PREIMAGE_WORD_COUNT, try std.math.mul(usize, descriptor_count, authority_source.AUTHORITY_HASH_WORDS_PER_DESCRIPTOR));
                const call_count = @import("poseidon2_channel.zig").canonicalWordPermutationCount(preimage_words);
                const active = @max(public_source.NATIVE_PUBLIC_SUM_WORD_COUNT, call_count);
                if (active > capacity or geometry.log_size != @as(u32, @intCast(std.math.log2_int_ceil(usize, @max(active, 16)))))
                    return error.FixedBaseGeometryMismatchV6;
                for (0..active) |index| {
                    const fixed = try claimHashFixedRow(index, call_count, self.manifest.shape.native_wire_word_count);
                    put(columns, geometry.log_size, index, &fixed);
                }
            },
            17 => {
                if (columns.len != public_logup_air.PREPROCESSED_COLUMN_COUNT or capacity != public_logup_air.TRACE_ROW_COUNT)
                    return error.FixedBaseGeometryMismatchV6;
                for (self.public_logup_rows.rows, 0..) |fixed, index| {
                    const values = fixed.values();
                    put(columns, geometry.log_size, index, values[public_logup_air.PHYSICAL_MAIN_COLUMN_COUNT..]);
                }
            },
            20 => {
                if (columns.len != query_bits_air.PREPROCESSED_COLUMN_COUNT or
                    geometry.log_size != self.query_bit_rows.log_size or
                    self.query_bit_rows.rows.len > capacity)
                    return error.FixedCoreQueryGeometryMismatchV6;
                const reference = try self.manifest.shape.core_profile.reference();
                try self.query_bit_rows.validateAgainst(try reference.queryBitsReference());
                for (self.query_bit_rows.rows, 0..) |fixed, index| {
                    const values = fixed.values();
                    put(columns, geometry.log_size, index, &values);
                }
            },
            21 => {
                if (columns.len != query_mapping_air.PREPROCESSED_COLUMN_COUNT or
                    geometry.log_size != self.query_mapping_rows.log_size or
                    self.query_mapping_rows.rows.len > capacity)
                    return error.FixedCoreQueryGeometryMismatchV6;
                const reference = try self.manifest.shape.core_profile.reference();
                try self.query_mapping_rows.validateAgainst(reference);
                for (self.query_mapping_rows.rows, 0..) |fixed, index| {
                    const values = fixed.values();
                    put(columns, geometry.log_size, index, &values);
                }
            },
            33 => if (columns.len != merkle_path_air.PREPROCESSED_COLUMN_COUNT)
                return error.FixedBaseGeometryMismatchV6,
            34 => {
                if (columns.len != 1)
                    return error.FixedBaseGeometryMismatchV6;
                columns[0][framework.committedRow(0, geometry.log_size)] = M31.one();
            },
            35 => {
                if (columns.len != range_air.FRAMEWORK_PREPROCESSED_COLUMN_COUNT or
                    geometry.log_size != range_air.LOG_SIZE or capacity != range_air.TABLE_SIZE)
                    return error.FixedBaseGeometryMismatchV6;
                columns[0][0] = M31.one();
                for (0..capacity) |logical| {
                    const committed = framework.committedRow(logical, geometry.log_size);
                    columns[1][committed] = M31.fromCanonical(@intCast(logical & 0xff));
                    columns[2][committed] = M31.fromCanonical(@intCast(logical >> 8));
                }
            },
            else => unreachable,
        }
    }

    pub fn requireCompletePreprocessing(_: *const Writer) error{UnqualifiedFixedRowsV6}!void {
        return error.UnqualifiedFixedRowsV6;
    }
};

pub fn qualified(row: u8) bool {
    for (QUALIFIED_ROWS) |candidate| if (row == candidate) return true;
    return false;
}

/// Matches the V2 source writer's native-lane control tuple exactly; the
/// verifier schedule, not captured source rows, owns all ten fixed fields.
pub fn controlRowsFromPlan(allocator: std.mem.Allocator, plan: *const schedule.Plan) ![]control_witness.Row {
    try plan.validate();
    const rows = try allocator.alloc(control_witness.Row, plan.steps.len);
    for (plan.steps, rows, 0..) |step, *row, index| {
        const encoded = step.encode();
        row.* = .{
            .segment_mask = 1,
            .binary_mask = 0,
            .verifier_id = 0,
            .sequence = @intCast(index),
            .tag = encoded.tag,
            .args = encoded.args,
            .terminal_mask = @intFromBool(step.terminal()),
        };
    }
    return rows;
}

fn put(columns: [][]M31, log_size: u32, logical: usize, values: []const M31) void {
    const committed = framework.committedRow(logical, log_size);
    for (values, columns) |value, column| column[committed] = value;
}

fn publicationRow(index: usize, wire_word_count: u32, value: M31) !public_source.RelayRowV2 {
    const arithmetic = index >= public_source.PUBLICATION_SUM_START and
        index < public_source.PUBLICATION_SEAL_START + public_source.NATIVE_TOTAL_WORD_COUNT;
    const control = index == public_source.CONTROL_PUBLICATION_INDEX;
    const node = if (arithmetic)
        try std.math.add(u32, wire_word_count, @intCast(index - public_source.PUBLICATION_SUM_START))
    else
        0;
    return .{
        .source_kind = .publication_bridge,
        .source_fields = .{ public_source.PUBLICATION_BRIDGE_CIRCUIT_ID, @intCast(index), 0, 0, 0 },
        .value = value,
        .arithmetic_mask = @intFromBool(arithmetic),
        .arithmetic_node_id = node,
        .arithmetic_use_count = @intFromBool(arithmetic),
        .control_mask = @intFromBool(control),
        .control_use_count = @intFromBool(control),
    };
}

fn claimHashFixedRow(index: usize, call_count: usize, wire_word_count: u32) ![public_air.NativePublicSums.PREPROCESSED_COLUMN_COUNT]M31 {
    if (index >= @max(public_source.NATIVE_PUBLIC_SUM_WORD_COUNT, call_count))
        return error.FixedBaseGeometryMismatchV6;
    const relay_active = index < public_source.NATIVE_PUBLIC_SUM_WORD_COUNT;
    const authority_active = index < call_count;
    const relay = if (relay_active)
        try publicationRow(public_source.PUBLICATION_SUM_START + index, wire_word_count, M31.zero())
    else
        public_source.RelayRowV2{ .enabler = 0, .source_kind = .publication_bridge, .value = M31.zero(), .arithmetic_circuit_id = 0, .control_circuit_id = 0 };
    var call_nodes: [public_hash_source.CALL_WIRE_GROUP_COUNT]u32 = @splat(0);
    if (authority_active) for (&call_nodes, 0..) |*node, group| {
        node.* = std.math.cast(u32, try std.math.add(usize, try std.math.mul(usize, index, public_hash_source.CALL_WIRE_GROUP_COUNT), group)) orelse return error.FixedBaseGeometryMismatchV6;
    };
    const row = public_hash_source.RowV2{
        .relay_value = M31.zero(),
        .relay_mask = @intFromBool(relay_active),
        .authority_mask = @intFromBool(authority_active),
        .bind_mask = @intFromBool(index == 0),
        .source_fields = relay.source_fields,
        .arithmetic_circuit_id = relay.arithmetic_circuit_id,
        .arithmetic_node_id = relay.arithmetic_node_id,
        .arithmetic_use_count = relay.arithmetic_use_count,
        .control_circuit_id = relay.control_circuit_id,
        .control_node_id = relay.control_node_id,
        .control_use_count = relay.control_use_count,
        .poseidon_tuple = @splat(M31.zero()),
        .call_wire_nodes = call_nodes,
    };
    const logical = row.values();
    return logical[public_air.NativePublicSums.PHYSICAL_MAIN_COLUMN_COUNT..][0..public_air.NativePublicSums.PREPROCESSED_COLUMN_COUNT].*;
}

test "V6 base fixed control matches executed V2 native source" {
    const allocator = std.testing.allocator;
    const fixture_support = @import("segment_transcript_outer_source_v2_test_support.zig");
    const source_contract = @import("segment_transcript_outer_source_v2_contract.zig");
    const source_writer = @import("segment_transcript_outer_source_v2_write_rows_assume_valid.zig");
    var fixture = try fixture_support.Fixture.init(allocator);
    defer fixture.deinit();
    const rows = try controlRowsFromPlan(allocator, &fixture.plan);
    defer allocator.free(rows);
    const counts = try source_contract.deriveCounts(&fixture.program, &fixture.execution, &fixture.plan);
    var destinations = try fixture_support.OwnedDestinations.init(allocator, counts);
    defer destinations.deinit();
    source_writer.writeRowsAssumeValid(destinations.view(), &fixture.program, &fixture.execution, &fixture.plan);
    try std.testing.expectEqualDeep(rows, destinations.control);
}

test "V6 base fixed rows reconstruct without a leaf" {
    const allocator = std.testing.allocator;
    const fixture = @import("../wrapper_roster_v3_test_root.zig");
    const child_fixture = @import("tests/ethereum_leaf_child_field_test.zig");
    var plans = try @import("segment_profile.zig").initPlans(allocator, 16, 16);
    defer plans.vm.deinit();
    defer plans.recursion.deinit();
    var logs = fixture.fixtureLogSizes();
    logs[0] = @max(logs[0], @as(u32, @intCast(std.math.log2_int_ceil(usize, plans.vm.steps.len))));
    var fixed_schedule = try transcript_fixed.Fixed.initFromAdmittedShape(allocator, &plans.vm, 128, &child_fixture.components, &child_fixture.infra, false);
    defer fixed_schedule.deinit();
    inline for (.{ .{ 2, fixed_schedule.bindings.len }, .{ 3, fixed_schedule.states.len }, .{ 8, fixed_schedule.relations.len }, .{ 9, fixed_schedule.randomness.len } }) |item|
        logs[item[0]] = @max(logs[item[0]], @as(u32, @intCast(std.math.log2_int_ceil(usize, @max(item[1], 1)))));
    const core_profile = try template_mod.testFrozenCoreProfileV6();
    const core_query_mapping = try core_profile.reference();
    var bit_shape = try query_bits.Preprocessed.init(allocator, try core_query_mapping.queryBitsReference());
    defer bit_shape.deinit();
    var map_shape = try query_mapping.Preprocessed.init(allocator, core_query_mapping);
    defer map_shape.deinit();
    logs[20] = bit_shape.log_size;
    logs[21] = map_shape.log_size;
    const catalog = try catalog_mod.build(logs, fixture.boundaryComponents());
    const instructions = try @import("transcript_instruction_template_v6.zig").InstructionTemplateV6.build(
        allocator,
        &plans.vm,
        128,
        &child_fixture.components,
        &child_fixture.infra,
        false,
    );
    const shape = shape_mod.Shape{ .program_words = instructions.canonical_program_word_count, .base_poseidon_calls = 1193 };
    var writer = try Writer.init(allocator, &catalog, shape, &child_fixture.components, &child_fixture.infra, &plans.vm, &core_profile, &core_query_mapping, 128, false);
    defer writer.deinit();
    const changed_relay = try public_logup.preflight(&plans.vm, &.{ .value = M31.fromCanonical(9182) });
    for (writer.public_logup_rows.rows, changed_relay.rows) |first, second| {
        const first_values = first.values();
        const second_values = second.values();
        try std.testing.expectEqualDeep(first_values[public_logup_air.PHYSICAL_MAIN_COLUMN_COUNT..], second_values[public_logup_air.PHYSICAL_MAIN_COLUMN_COUNT..]);
    }
    for (QUALIFIED_ROWS) |row| {
        const geometry = writer.manifest.placements[row].geometry;
        const capacity = @as(usize, 1) << @intCast(geometry.log_size);
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const a = arena.allocator();
        const columns = try a.alloc([]M31, geometry.preprocessed_columns);
        for (columns) |*column| {
            column.* = try a.alloc(M31, capacity);
            @memset(column.*, M31.zero());
        }
        try writer.writeRow(row, columns);
        switch (row) {
            0 => {
                for (writer.control_rows, 0..) |fixed, logical| {
                    const committed = framework.committedRow(logical, geometry.log_size);
                    for (fixed.values(), columns) |value, column|
                        try std.testing.expectEqual(value.toU32(), column[committed].toU32());
                }
            },
            1, 6, 7, 33 => try std.testing.expectEqual(@as(usize, 0), columns.len),
            2 => try expectFixedRows(columns, geometry.log_size, writer.transcript_rows.bindings),
            3 => try expectFixedRows(columns, geometry.log_size, writer.transcript_rows.states),
            4 => {
                for (writer.frame_rows.rows, 0..) |fixed, logical| {
                    const values = fixed.preprocessing.values();
                    const committed = framework.committedRow(logical, geometry.log_size);
                    for (values, columns[0..values.len]) |value, column|
                        try std.testing.expectEqual(value.toU32(), column[committed].toU32());
                    try std.testing.expectEqual(fixed.tree0_bridge, columns[values.len][committed].toU32());
                }
            },
            8 => try expectFixedRows(columns, geometry.log_size, writer.transcript_rows.relations),
            9 => try expectFixedRows(columns, geometry.log_size, writer.transcript_rows.randomness),
            10 => for (columns) |column| for (column) |value| {
                try std.testing.expect(value.isZero());
            },
            12 => {
                for (0..public_source.PUBLICATION_HEADER_WORD_COUNT) |logical| {
                    const expected = public_components.logicalRow(try publicationRow(logical, writer.manifest.shape.native_wire_word_count, M31.fromCanonical(123)));
                    const committed = framework.committedRow(logical, geometry.log_size);
                    for (expected[public_air.PublicationHeader.PHYSICAL_MAIN_COLUMN_COUNT..][0..columns.len], columns) |value, column|
                        try std.testing.expectEqual(value.toU32(), column[committed].toU32());
                }
            },
            13 => {
                const descriptor_count = @as(usize, writer.manifest.shape.component_descriptors) + writer.manifest.shape.infra_descriptors;
                const words = authority_source.AUTHORITY_HASH_FIXED_PREIMAGE_WORD_COUNT + descriptor_count * authority_source.AUTHORITY_HASH_WORDS_PER_DESCRIPTOR;
                const calls = @import("poseidon2_channel.zig").canonicalWordPermutationCount(words);
                for (0..@max(public_source.NATIVE_PUBLIC_SUM_WORD_COUNT, calls)) |logical| {
                    const committed = framework.committedRow(logical, geometry.log_size);
                    try std.testing.expect(columns[0][committed].isOne());
                    try std.testing.expectEqual(@as(u32, @intFromBool(logical < public_source.NATIVE_PUBLIC_SUM_WORD_COUNT)), columns[1][committed].toU32());
                    try std.testing.expectEqual(@as(u32, @intFromBool(logical < calls)), columns[2][committed].toU32());
                    try std.testing.expectEqual(@as(u32, @intCast(if (logical < calls) logical * public_hash_source.CALL_WIRE_GROUP_COUNT else 0)), columns[15][committed].toU32());
                }
            },
            14 => {
                for (0..public_source.PUBLICATION_SEAL_WORD_COUNT) |logical| {
                    const expected = public_components.logicalRow(try publicationRow(public_source.PUBLICATION_SEAL_START + logical, writer.manifest.shape.native_wire_word_count, M31.fromCanonical(123)));
                    const committed = framework.committedRow(logical, geometry.log_size);
                    for (expected[public_air.PublicationSeal.PHYSICAL_MAIN_COLUMN_COUNT..][0..columns.len], columns) |value, column|
                        try std.testing.expectEqual(value.toU32(), column[committed].toU32());
                }
            },
            17 => {
                for (writer.public_logup_rows.rows, 0..) |fixed, logical| {
                    const values = fixed.values();
                    const committed = framework.committedRow(logical, geometry.log_size);
                    for (values[public_logup_air.PHYSICAL_MAIN_COLUMN_COUNT..], columns) |value, column|
                        try std.testing.expectEqual(value.toU32(), column[committed].toU32());
                }
            },
            20 => try expectCorePreprocessedParity(query_bits_air, query_bits, allocator, a, &writer.query_bit_rows, try core_query_mapping.queryBitsReference(), columns, geometry.log_size),
            21 => try expectCorePreprocessedParity(query_mapping_air, query_mapping, allocator, a, &writer.query_mapping_rows, core_query_mapping, columns, geometry.log_size),
            34 => {
                const committed = framework.committedRow(0, geometry.log_size);
                try std.testing.expect(columns[0][committed].isOne());
            },
            35 => {
                try std.testing.expect(columns[0][0].isOne());
                for ([_]usize{ 0, 1, 255, 256, 65535 }) |logical| {
                    const committed = framework.committedRow(logical, geometry.log_size);
                    try std.testing.expectEqual(@as(u32, @intCast(logical & 255)), columns[1][committed].toU32());
                    try std.testing.expectEqual(@as(u32, @intCast(logical >> 8)), columns[2][committed].toU32());
                }
            },
            else => unreachable,
        }
        if (row != 10 and columns.len > 0) try std.testing.expectError(error.FixedBaseDestinationNotFreshV6, writer.writeRow(row, columns));
    }
    var mutation_arena = std.heap.ArenaAllocator.init(allocator);
    defer mutation_arena.deinit();
    const mutation_allocator = mutation_arena.allocator();
    for ([_]u8{ 20, 21 }) |row| {
        const geometry = writer.manifest.placements[row].geometry;
        const capacity = @as(usize, 1) << @intCast(geometry.log_size);
        const columns = try mutation_allocator.alloc([]M31, geometry.preprocessed_columns);
        for (columns) |*column| {
            column.* = try mutation_allocator.alloc(M31, capacity);
            @memset(column.*, M31.zero());
        }
        if (row == 20) {
            writer.query_bit_rows.rows[0].query += 1;
            try std.testing.expectError(error.AuthorityMismatch, writer.writeRow(row, columns));
            writer.query_bit_rows.rows[0].query -= 1;
        } else {
            writer.query_mapping_rows.rows[0].query += 1;
            try std.testing.expectError(error.AuthorityMismatch, writer.writeRow(row, columns));
            writer.query_mapping_rows.rows[0].query -= 1;
        }
        for (columns) |column| for (column) |value| try std.testing.expect(value.isZero());
    }
    for ([_]u8{ 13, 14 }) |row| {
        const geometry = writer.manifest.placements[row].geometry;
        const capacity = @as(usize, 1) << @intCast(geometry.log_size);
        const columns = try mutation_allocator.alloc([]M31, geometry.preprocessed_columns);
        for (columns) |*column| {
            column.* = try mutation_allocator.alloc(M31, capacity);
            @memset(column.*, M31.zero());
        }
        writer.manifest.shape.native_wire_word_count += 1;
        try std.testing.expectError(error.InvalidTemplateManifestV6, writer.writeRow(row, columns));
        writer.manifest.shape.native_wire_word_count -= 1;
        writer.manifest.placements[row].geometry.semantic_digest[0] ^= 1;
        try std.testing.expectError(error.InvalidTemplateManifestV6, writer.writeRow(row, columns));
        writer.manifest.placements[row].geometry.semantic_digest[0] ^= 1;
        for (columns) |column| for (column) |value| try std.testing.expect(value.isZero());
    }
    logs[20] += 1;
    const wrong_catalog = try catalog_mod.build(logs, fixture.boundaryComponents());
    try std.testing.expectError(error.FixedCoreQueryGeometryMismatchV6, Writer.init(allocator, &wrong_catalog, shape, &child_fixture.components, &child_fixture.infra, &plans.vm, &core_profile, &core_query_mapping, 128, false));
    try std.testing.expectError(error.UnqualifiedFixedRowV6, writer.writeRow(11, &.{}));
    try std.testing.expectError(error.UnqualifiedFixedRowsV6, writer.requireCompletePreprocessing());
}

test "V6 claim-hash fixed tail carries only admitted authority calls" {
    const with_call = try claimHashFixedRow(20, 24, 128);
    try std.testing.expectEqual(@as(u32, 1), with_call[0].toU32());
    try std.testing.expectEqual(@as(u32, 0), with_call[1].toU32());
    try std.testing.expectEqual(@as(u32, 1), with_call[2].toU32());
    try std.testing.expectEqual(@as(u32, 0), with_call[9].toU32());
    try std.testing.expectEqual(@as(u32, 20 * public_hash_source.CALL_WIRE_GROUP_COUNT), with_call[15].toU32());
    try std.testing.expectError(error.FixedBaseGeometryMismatchV6, claimHashFixedRow(20, 20, 128));
}

test "V6 public rows 13 and 14 match authenticated native-sum graph and authority witness" {
    const allocator = std.testing.allocator;
    const support = @import("segment_public_outer_test_support.zig");
    const graph_mod = @import("segment_public_native_sum_authority_v2.zig");
    const poseidon_air = @import("../air/memory_commitment/poseidon2_air.zig");
    const public_contract = @import("segment_public_outer_source_v2_contract.zig");
    const public_writer = @import("segment_public_outer_source_v2_write_into_bound.zig");
    for ([_]u32{ 0, 0x05060708 }) |register_value| {
        var fixture = try support.Fixture.initWithRegister7(allocator, register_value);
        defer fixture.deinit();
        const prepared = try public_source.preflight(fixture.inputs());
        var graph = try graph_mod.SourceV2.init(allocator, &prepared, fixture.inputs());
        defer graph.deinit();
        const binding = try graph.publicBinding(&prepared);
        const wire_count = fixture.owned_public.data.words().len;
        for (0..public_source.ARITHMETIC_PUBLICATION_WORD_COUNT) |index|
            try std.testing.expectEqual(@as(u32, 1), binding.input_use_counts[wire_count + index]);

        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const a = arena.allocator();
        const counts = prepared.counts();
        const destinations = public_source.DestinationsV2{
            .publication_header = try a.alloc(public_source.RelayRowV2, counts.publication_header),
            .native_public_sums = try a.alloc(public_source.RelayRowV2, counts.native_public_sums),
            .publication_seal = try a.alloc(public_source.RelayRowV2, counts.publication_seal),
            .boundary_bridge = try a.alloc(public_source.RelayRowV2, counts.boundary_bridge),
            .native_challenges = try a.alloc(public_source.RelayRowV2, counts.native_challenges),
            .relation_events = try a.alloc(public_source.RelationEventV2, counts.relay_relation_events),
            .control = undefined,
        };
        const publication_events = try public_contract.publicationEvents(&fixture.publication);
        const challenge_words = @import("segment_public_outer_source_v2_arithmetic_graph_binding_v2.zig").challengeWords(&fixture.relations);
        public_writer.writeAssumeValid(destinations, &prepared, fixture.owned_public.data.words(), &publication_events, &challenge_words, binding.input_use_counts);

        const hash_prepared = try public_hash_source.PreparedV2.initFromPublic(&prepared);
        const calls = try hash_prepared.callCount();
        const scratch = try allocator.alloc(poseidon_air.Call, calls);
        defer allocator.free(scratch);
        const rows = try allocator.alloc(public_hash_source.LogicalRowV2, hash_prepared.logical_row_count);
        defer allocator.free(rows);
        const events = try allocator.alloc(public_hash_source.RelationEventV2, try hash_prepared.eventCount());
        defer allocator.free(events);
        try public_hash_source.writeInto(&hash_prepared, &prepared, fixture.inputs(), destinations.native_public_sums, scratch, rows, events);
        for (rows, 0..) |actual, index| {
            const fixed = try claimHashFixedRow(index, calls, @intCast(wire_count));
            try std.testing.expectEqualDeep(fixed, actual[public_air.NativePublicSums.PHYSICAL_MAIN_COLUMN_COUNT..][0..fixed.len].*);
        }
        for (0..public_source.PUBLICATION_SEAL_WORD_COUNT) |index| {
            const actual = destinations.publication_seal[index];
            const fixed = try publicationRow(public_source.PUBLICATION_SEAL_START + index, @intCast(wire_count), M31.zero());
            const actual_logical = public_components.logicalRow(actual);
            const fixed_logical = public_components.logicalRow(fixed);
            try std.testing.expectEqualDeep(actual_logical[public_air.PublicationSeal.PHYSICAL_MAIN_COLUMN_COUNT..], fixed_logical[public_air.PublicationSeal.PHYSICAL_MAIN_COLUMN_COUNT..]);
        }
    }
}

fn expectFixedRows(columns: [][]M31, log_size: u32, rows: anytype) !void {
    for (rows, 0..) |fixed, logical| {
        const committed = framework.committedRow(logical, log_size);
        for (fixed.values(), columns) |value, column|
            try std.testing.expectEqual(value.toU32(), column[committed].toU32());
    }
}

fn expectCorePreprocessedParity(
    comptime Air: type,
    comptime Witness: type,
    allocator: std.mem.Allocator,
    arena: std.mem.Allocator,
    preprocessing: anytype,
    reference: anytype,
    physical: [][]M31,
    log_size: u32,
) !void {
    var definition = try Air.build(allocator);
    defer definition.deinit();
    const binding = try Witness.Binding.canonical(&definition);
    const executor = try Witness.Executor.init(&definition, &binding);
    const capacity = @as(usize, 1) << @intCast(log_size);
    var raw: [Air.PREPROCESSED_COLUMN_COUNT][]M31 = undefined;
    for (&raw) |*column| column.* = try arena.alloc(M31, capacity);
    try executor.generatePreprocessedInto(preprocessing, reference, &raw);
    for (raw, physical) |core_column, template_column| {
        for (core_column, 0..) |value, logical| {
            const committed = framework.committedRow(logical, log_size);
            try std.testing.expectEqual(value.toU32(), template_column[committed].toU32());
        }
    }
}
