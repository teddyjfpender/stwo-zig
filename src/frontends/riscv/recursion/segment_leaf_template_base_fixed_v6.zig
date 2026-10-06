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
const merkle_path_air = @import("air/merkle_path.zig");
const query_bits_air = @import("air/query_bits.zig");
const query_bits = @import("air/query_bits_witness.zig");
const query_mapping_air = @import("air/query_mapping.zig");
const query_mapping = @import("air/query_mapping_witness.zig");

pub const PRODUCTION_PROOF_ACTIVATION = false;
pub const QUALIFIED_ROWS = [_]u8{ 0, 1, 2, 3, 4, 6, 7, 8, 9, 10, 12, 17, 20, 21, 33, 34, 35 };

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
            12 => {
                if (columns.len != public_air.PublicationHeader.PREPROCESSED_COLUMN_COUNT or
                    public_source.PUBLICATION_HEADER_WORD_COUNT > capacity)
                    return error.FixedBaseGeometryMismatchV6;
                for (0..public_source.PUBLICATION_HEADER_WORD_COUNT) |index| {
                    const fixed = publicationHeaderRow(index, M31.zero());
                    const logical = public_components.logicalRow(fixed);
                    put(columns, geometry.log_size, index, logical[public_air.PublicationHeader.PHYSICAL_MAIN_COLUMN_COUNT..][0..columns.len]);
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

fn publicationHeaderRow(index: usize, value: M31) public_source.RelayRowV2 {
    return .{
        .source_kind = .publication_bridge,
        .source_fields = .{ public_source.PUBLICATION_BRIDGE_CIRCUIT_ID, @intCast(index), 0, 0, 0 },
        .value = value,
    };
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
                    const expected = public_components.logicalRow(publicationHeaderRow(logical, M31.fromCanonical(123)));
                    const committed = framework.committedRow(logical, geometry.log_size);
                    for (expected[public_air.PublicationHeader.PHYSICAL_MAIN_COLUMN_COUNT..][0..columns.len], columns) |value, column|
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
    logs[20] += 1;
    const wrong_catalog = try catalog_mod.build(logs, fixture.boundaryComponents());
    try std.testing.expectError(error.FixedCoreQueryGeometryMismatchV6, Writer.init(allocator, &wrong_catalog, shape, &child_fixture.components, &child_fixture.infra, &plans.vm, &core_profile, &core_query_mapping, 128, false));
    try std.testing.expectError(error.UnqualifiedFixedRowV6, writer.writeRow(11, &.{}));
    try std.testing.expectError(error.UnqualifiedFixedRowsV6, writer.requireCompletePreprocessing());
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
