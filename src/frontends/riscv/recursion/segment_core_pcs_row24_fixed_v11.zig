//! Candidate verifier-owned fixed Tree0 writer for PCS-DEEP input row 24.
//!
//! The direct leaf uses one proof-independent PCS circuit in all three
//! verifier lanes. A caller-selected expected profile supplies exact ordered
//! tree columns, sample-point tags and physical mask logs before any child
//! capture is examined. The circuit, bindings and use counts are rebuilt from
//! that policy. V10 does not yet seal this authority; proof activation is off.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const template = @import("air/segment_leaf_wrapper_template_v10.zig");
const trace_row23 = @import("segment_core_trace_row23_fixed_v11.zig");
const circuit_mod = @import("air/pcs_deep_circuit.zig");
const witness = @import("air/pcs_deep_input_witness.zig");
const air = @import("air/pcs_deep_input.zig");
const protocol = @import("protocol.zig");
const geometry_mod = @import("air/universal_manifest_contract.zig");
const typed_geometry = @import("air/universal_typed_geometry.zig");
const framework = @import("air/framework_interaction.zig");

pub const ROW: u8 = 24;
pub const FIXED_COLUMNS_DOMAIN = "stwo-zig/riscv-v11-row24-complete-fixed-columns/v1\x00";
pub const PRODUCTION_PROOF_ACTIVATION = false;
pub const TEMPLATE_ADMISSION_AVAILABLE = false;
// Direct-leaf IDs from detached_fri_core_part_01.zig, not the binary outer
// source's separate 401-series FRI or PCS namespace.
const SEGMENT_CIRCUIT_ID: u32 = 201;
const LEFT_CIRCUIT_ID: u32 = 202;
const RIGHT_CIRCUIT_ID: u32 = 203;

pub const ExpectedProfile = struct {
    ordered_tree_logs: []const []const u32,
    sample_layouts: []const circuit_mod.SamplePointLayout,
    mask_log_sizes: []const u32 = &.{},

    pub fn profile(self: ExpectedProfile, key: *const template.TemplateManifestV10, trees: []const circuit_mod.TreeProfile) circuit_mod.Profile {
        return .{
            .trees = trees,
            .sample_layouts = self.sample_layouts,
            .mask_log_sizes = self.mask_log_sizes,
            .lifting_log_size = key.v9_template.v8_template.v7_template.v6_template.shape.core_profile.vm.lifting_log_size,
            .log_blowup_factor = protocol.FRI_LOG_BLOWUP_FACTOR,
            .query_count = key.v9_template.schedule_shape.query_count,
        };
    }

    pub fn validateAgainst(self: ExpectedProfile, key: *const template.TemplateManifestV10) !void {
        const v9 = key.v9_template;
        const core = v9.v8_template.v7_template.v6_template.shape.core_profile;
        if (core.vm.tree_count != core.recursion.tree_count or
            core.vm.query_count != core.recursion.query_count or
            core.vm.lifting_log_size != core.recursion.lifting_log_size or
            !std.mem.eql(u32, core.vm.tree_heights[0..core.vm.tree_count], core.recursion.tree_heights[0..core.recursion.tree_count]))
            return error.Row24DirectLaneProfileMismatchV11;
        const both = trace_row23.ExpectedLayout{ .vm_trees = self.ordered_tree_logs, .recursion_trees = self.ordered_tree_logs };
        try both.validateAgainst(key);
        if (self.sample_layouts.len != v9.schedule_shape.table_count or
            (self.mask_log_sizes.len != 0 and self.mask_log_sizes.len != self.sample_layouts.len))
            return error.Row24ExpectedLayoutCountMismatchV11;
        var samples: usize = 0;
        for (self.sample_layouts) |layout| samples = try std.math.add(usize, samples, layout.sampleCount());
        if (samples != v9.schedule_shape.sampled_value_count) return error.Row24ExpectedSampleCountMismatchV11;
        var storage: [8]circuit_mod.TreeProfile = undefined;
        const trees = storage[0..self.ordered_tree_logs.len];
        for (trees, self.ordered_tree_logs) |*tree, logs| tree.* = .{ .column_log_sizes = logs };
        try self.profile(key, trees).validate();
    }

    pub fn orderedLayoutId(self: ExpectedProfile) [32]u8 {
        return (trace_row23.ExpectedLayout{ .vm_trees = self.ordered_tree_logs, .recursion_trees = self.ordered_tree_logs }).identityDigest();
    }
};

pub const FixedDescriptor = struct {
    v10_template_seal: [32]u8,
    ordered_layout_id: [32]u8,
    profile_identity: [32]u8,
    circuit_identity: [32]u8,
    geometry: geometry_mod.Geometry,
    fixed_columns_id: [32]u8,
};

pub const Writer = struct {
    allocator: std.mem.Allocator,
    key_seal: [32]u8,
    ordered_layout_id: [32]u8,
    circuit: *circuit_mod.Circuit,
    reference: witness.Reference,
    preprocessing: witness.Preprocessed,

    pub fn initFromExpectedProfile(allocator: std.mem.Allocator, key: *const template.TemplateManifestV10, expected: ExpectedProfile) !Writer {
        try key.validate();
        try expected.validateAgainst(key);
        const trees = try allocator.alloc(circuit_mod.TreeProfile, expected.ordered_tree_logs.len);
        defer allocator.free(trees);
        for (trees, expected.ordered_tree_logs) |*tree, logs| tree.* = .{ .column_log_sizes = logs };
        const circuit = try allocator.create(circuit_mod.Circuit);
        errdefer allocator.destroy(circuit);
        circuit.* = try circuit_mod.build(allocator, expected.profile(key, trees));
        errdefer circuit.deinit();
        const lane_profile = try circuit.profile().laneProfile();
        const lanes = [3]witness.Lane{
            .{ .verifier_id = witness.SEGMENT_VERIFIER_ID, .circuit_id = SEGMENT_CIRCUIT_ID, .profile = lane_profile, .graph = circuit.graph(), .bindings = circuit.bindings },
            .{ .verifier_id = witness.LEFT_RECURSION_VERIFIER_ID, .circuit_id = LEFT_CIRCUIT_ID, .profile = lane_profile, .graph = circuit.graph(), .bindings = circuit.bindings },
            .{ .verifier_id = witness.RIGHT_RECURSION_VERIFIER_ID, .circuit_id = RIGHT_CIRCUIT_ID, .profile = lane_profile, .graph = circuit.graph(), .bindings = circuit.bindings },
        };
        const reference = try witness.Reference.authenticate(lanes, witness.computeReferenceDigest(lanes));
        var preprocessing = try witness.Preprocessed.init(allocator, reference);
        errdefer preprocessing.deinit();
        return .{
            .allocator = allocator,
            .key_seal = key.seal,
            .ordered_layout_id = expected.orderedLayoutId(),
            .circuit = circuit,
            .reference = reference,
            .preprocessing = preprocessing,
        };
    }

    pub fn deinit(self: *Writer) void {
        self.preprocessing.deinit();
        self.circuit.deinit();
        self.allocator.destroy(self.circuit);
        self.* = undefined;
    }

    pub fn geometry(self: *const Writer) geometry_mod.Geometry {
        return typed_geometry.manifestGeometryForAir(air, geometry_mod, .pcs_deep_input, self.preprocessing.log_size);
    }

    pub fn requireTemplateAdmission(_: *const Writer) error{Row24FixedKeyNotInTemplateV10}!void {
        return error.Row24FixedKeyNotInTemplateV10;
    }

    pub fn writePhysical(self: *const Writer, key: *const template.TemplateManifestV10, geometry_value: geometry_mod.Geometry, columns: [][]M31) !void {
        if (!std.meta.eql(geometry_value, self.geometry()) or
            geometry_value.log_size >= @bitSizeOf(usize) or
            columns.len != air.PREPROCESSED_COLUMN_COUNT)
            return error.Row24FixedGeometryMismatchV11;
        const capacity = @as(usize, 1) << @intCast(geometry_value.log_size);
        const protected = try addressRange(witness.Row, self.preprocessing.rows);
        for (columns, 0..) |column, index| {
            if (column.len != capacity) return error.Row24FixedGeometryMismatchV11;
            const destination = try addressRange(M31, column);
            if (destination.overlaps(protected)) return error.Row24FixedAliasedDestinationV11;
            for (columns[0..index]) |prior| if (destination.overlaps(try addressRange(M31, prior)))
                return error.Row24FixedAliasedDestinationV11;
            for (column) |word| if (!word.isZero()) return error.Row24FixedDestinationNotFreshV11;
        }
        try key.validate();
        if (!std.meta.eql(key.seal, self.key_seal)) return error.Row24TemplateMismatchV11;
        try self.circuit.validate();
        try self.reference.validate();
        try self.preprocessing.validateAgainstAuthority(self.reference);
        if (self.preprocessing.rows.len > capacity) return error.Row24FixedGeometryMismatchV11;
        for (self.preprocessing.rows, 0..) |row, logical| {
            const committed = framework.committedRow(logical, geometry_value.log_size);
            const values = row.values();
            for (columns, values) |column, value| column[committed] = value;
        }
    }

    pub fn descriptor(self: *const Writer, key: *const template.TemplateManifestV10) !FixedDescriptor {
        const geometry_value = self.geometry();
        const capacity = @as(usize, 1) << @intCast(geometry_value.log_size);
        const columns = try self.allocator.alloc([]M31, air.PREPROCESSED_COLUMN_COUNT);
        defer self.allocator.free(columns);
        var made: usize = 0;
        defer for (columns[0..made]) |column| self.allocator.free(column);
        for (columns) |*column| {
            column.* = try self.allocator.alloc(M31, capacity);
            @memset(column.*, M31.zero());
            made += 1;
        }
        try self.writePhysical(key, geometry_value, columns);
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(FIXED_COLUMNS_DOMAIN);
        hashInt(&hash, u8, ROW);
        hashInt(&hash, u32, geometry_value.log_size);
        hashInt(&hash, u16, geometry_value.preprocessed_columns);
        hash.update(&air.SEMANTIC_DIGEST);
        for (columns) |column| for (column) |word| hashInt(&hash, u32, word.toU32());
        return .{
            .v10_template_seal = self.key_seal,
            .ordered_layout_id = self.ordered_layout_id,
            .profile_identity = self.circuit.profile_digest,
            .circuit_identity = self.circuit.identity_digest,
            .geometry = geometry_value,
            .fixed_columns_id = hash.finalResult(),
        };
    }
};

const AddressRange = struct {
    start: usize,
    end: usize,
    fn overlaps(self: AddressRange, other: AddressRange) bool {
        return self.start < other.end and other.start < self.end;
    }
};

fn addressRange(comptime T: type, values: []const T) !AddressRange {
    const start = @intFromPtr(values.ptr);
    const size = try std.math.mul(usize, values.len, @sizeOf(T));
    return .{ .start = start, .end = try std.math.add(usize, start, size) };
}

fn hashInt(hash: *std.crypto.hash.sha2.Sha256, comptime T: type, value: T) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    hash.update(&bytes);
}

test "V11 row24 q193-shaped fixed input rows match native executor" {
    const allocator = std.testing.allocator;
    const key = try testKey(allocator);
    const logs0 = [_]u32{21} ** 38;
    const logs1 = [_]u32{21} ** 625;
    const logs2 = [_]u32{21} ** 200;
    const logs3 = [_]u32{21} ** 8;
    const trees = [_][]const u32{ &logs0, &logs1, &logs2, &logs3 };
    var layouts = [_]circuit_mod.SamplePointLayout{.current} ** 871;
    for (layouts[38 + 625 .. 38 + 625 + 200]) |*layout| layout.* = .current_previous;
    const expected = ExpectedProfile{ .ordered_tree_logs = &trees, .sample_layouts = &layouts };
    try expected.validateAgainst(&key);
    var permuted_layouts = layouts;
    std.mem.swap(circuit_mod.SamplePointLayout, &permuted_layouts[0], &permuted_layouts[38 + 625]);
    const permuted = ExpectedProfile{ .ordered_tree_logs = &trees, .sample_layouts = &permuted_layouts };
    try permuted.validateAgainst(&key);
    var profile_trees: [4]circuit_mod.TreeProfile = undefined;
    for (&profile_trees, trees) |*tree, logs| tree.* = .{ .column_log_sizes = logs };
    try std.testing.expect(!std.meta.eql(expected.profile(&key, &profile_trees).identityDigest(), permuted.profile(&key, &profile_trees).identityDigest()));
    var writer = try Writer.initFromExpectedProfile(allocator, &key, expected);
    defer writer.deinit();
    const geometry_value = writer.geometry();
    const capacity = @as(usize, 1) << @intCast(geometry_value.log_size);
    const columns = try allocColumns(allocator, capacity);
    defer freeColumns(allocator, columns);
    try writer.writePhysical(&key, geometry_value, columns);
    var definition = try air.build(allocator);
    defer definition.deinit();
    const binding = try witness.Binding.canonical(&definition);
    const executor = try witness.Executor.init(&definition, &binding);
    var logical: [air.PREPROCESSED_COLUMN_COUNT][]M31 = undefined;
    var made: usize = 0;
    defer for (logical[0..made]) |column| allocator.free(column);
    for (&logical) |*column| {
        column.* = try allocator.alloc(M31, capacity);
        made += 1;
    }
    try executor.generatePreprocessedInto(&writer.preprocessing, writer.reference, &logical);
    for (logical, columns) |native_column, physical_column|
        for (native_column, 0..) |value, row|
            try std.testing.expectEqual(value, physical_column[framework.committedRow(row, geometry_value.log_size)]);
    const descriptor = try writer.descriptor(&key);
    try std.testing.expectEqualDeep(writer.circuit.identity_digest, descriptor.circuit_identity);
    try std.testing.expectEqualDeep(expected.orderedLayoutId(), descriptor.ordered_layout_id);
    try std.testing.expectError(error.Row24FixedKeyNotInTemplateV10, writer.requireTemplateAdmission());
    try std.testing.expect(!PRODUCTION_PROOF_ACTIVATION);

    // The builder owns its exact sample tags; later caller mutation cannot
    // rewrite the already admitted graph or its fixed schedule.
    layouts[0] = .none;
    try std.testing.expectEqualDeep(descriptor, try writer.descriptor(&key));
    writer.preprocessing.rows[0].use_count += 1;
    for (columns) |column| @memset(column, M31.zero());
    try std.testing.expectError(error.AuthorityMismatch, writer.writePhysical(&key, geometry_value, columns));
    for (columns) |column| for (column) |word| try std.testing.expect(word.isZero());
}

test "V11 row24 rejects sample-count and physical-mask mutation" {
    const allocator = std.testing.allocator;
    const key = try testKey(allocator);
    const logs0 = [_]u32{21} ** 38;
    const logs1 = [_]u32{21} ** 625;
    const logs2 = [_]u32{21} ** 200;
    const logs3 = [_]u32{21} ** 8;
    const trees = [_][]const u32{ &logs0, &logs1, &logs2, &logs3 };
    var layouts = [_]circuit_mod.SamplePointLayout{.current} ** 871;
    for (layouts[38 + 625 .. 38 + 625 + 200]) |*layout| layout.* = .current_previous;
    layouts[0] = .none;
    const wrong_sample = ExpectedProfile{ .ordered_tree_logs = &trees, .sample_layouts = &layouts };
    try std.testing.expectError(error.Row24ExpectedSampleCountMismatchV11, wrong_sample.validateAgainst(&key));
    layouts[0] = .current;
    var wrong_mask = [_]u32{20} ** 871;
    wrong_mask[0] = 19;
    const wrong_physical = ExpectedProfile{ .ordered_tree_logs = &trees, .sample_layouts = &layouts, .mask_log_sizes = &wrong_mask };
    try std.testing.expectError(error.InvalidProfile, wrong_physical.validateAgainst(&key));
}

fn testKey(allocator: std.mem.Allocator) !template.TemplateManifestV10 {
    const fixture = @import("../wrapper_roster_v3_test_root.zig");
    const v6 = @import("air/segment_leaf_wrapper_template_v6.zig");
    const catalog = @import("air/segment_outer_typed_catalog_v2.zig");
    const shape_mod = @import("air/segment_leaf_wrapper_roster_direct_v4.zig");
    const child_fixture = @import("tests/ethereum_leaf_child_field_test.zig");
    const source_catalog = try catalog.build(fixture.fixtureLogSizes(), fixture.boundaryComponents());
    var plans = try @import("segment_profile.zig").initPlans(allocator, 16, 16);
    defer plans.vm.deinit();
    defer plans.recursion.deinit();
    const profile = try v6.testFrozenCoreProfileV6();
    const mapping = try profile.reference();
    const instructions = try @import("transcript_instruction_template_v6.zig").InstructionTemplateV6.build(
        allocator,
        &plans.vm,
        128,
        &child_fixture.components,
        &child_fixture.infra,
        false,
    );
    const wrapper_shape = shape_mod.Shape{ .program_words = instructions.canonical_program_word_count, .base_poseidon_calls = 1193 };
    return template.TemplateManifestV10.build(
        allocator,
        &source_catalog,
        wrapper_shape,
        &child_fixture.components,
        &child_fixture.infra,
        &plans.vm,
        &profile,
        &mapping,
        128,
        false,
        try @import("segment_profile.zig").transcriptShape(),
    );
}

fn allocColumns(allocator: std.mem.Allocator, capacity: usize) ![][]M31 {
    const columns = try allocator.alloc([]M31, air.PREPROCESSED_COLUMN_COUNT);
    errdefer allocator.free(columns);
    var made: usize = 0;
    errdefer for (columns[0..made]) |column| allocator.free(column);
    for (columns) |*column| {
        column.* = try allocator.alloc(M31, capacity);
        @memset(column.*, M31.zero());
        made += 1;
    }
    return columns;
}

fn freeColumns(allocator: std.mem.Allocator, columns: [][]M31) void {
    for (columns) |column| allocator.free(column);
    allocator.free(columns);
}
