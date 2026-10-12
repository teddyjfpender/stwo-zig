//! Candidate verifier-owned row-23 fixed Tree0 writer.
//!
//! V10 does not contain the ordered per-tree column logs needed by the
//! trace-Merkle leaf schedule. `ExpectedLayout` must be selected by verifier
//! policy before any child capture is read. This writer owns a copy, derives
//! every padded fixed cell, and exposes its digest for a successor key. V10
//! itself cannot admit the row, and production proof activation stays off.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const template = @import("air/segment_leaf_wrapper_template_v10.zig");
const core_profile_mod = @import("air/segment_leaf_wrapper_template_v6.zig");
const schedule = @import("air/verifier_schedule.zig");
const witness = @import("air/trace_merkle_witness.zig");
const air = @import("air/trace_merkle.zig");
const geometry_mod = @import("air/universal_manifest_contract.zig");
const typed_geometry = @import("air/universal_typed_geometry.zig");
const framework = @import("air/framework_interaction.zig");

pub const ROW: u8 = 23;
pub const LAYOUT_DOMAIN = "stwo-zig/riscv-v11-row23-ordered-column-layout/v1\x00";
pub const FIXED_COLUMNS_DOMAIN = "stwo-zig/riscv-v11-row23-complete-fixed-columns/v1\x00";
pub const PRODUCTION_PROOF_ACTIVATION = false;
pub const TEMPLATE_ADMISSION_AVAILABLE = false;

pub const ExpectedLayout = struct {
    /// Physical commitment-tree order, then native column order within each
    /// tree. These values are trusted verifier policy, never capture output.
    vm_trees: []const []const u32,
    recursion_trees: []const []const u32,

    pub fn validateAgainst(self: ExpectedLayout, key: *const template.TemplateManifestV10) !void {
        const v9 = key.v9_template;
        const core = v9.v8_template.v7_template.v6_template.shape.core_profile;
        try validateLane(self.vm_trees, core.vm.tree_heights[0..core.vm.tree_count], v9.schedule_shape.table_count);
        try validateLane(self.recursion_trees, core.recursion.tree_heights[0..core.recursion.tree_count], v9.schedule_shape.table_count);
    }

    pub fn identityDigest(self: ExpectedLayout) [32]u8 {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(LAYOUT_DOMAIN);
        for ([_][]const []const u32{ self.vm_trees, self.recursion_trees }) |lane| {
            hashInt(&hash, u32, @intCast(lane.len));
            for (lane) |tree| {
                hashInt(&hash, u32, @intCast(tree.len));
                for (tree) |log_size| hashInt(&hash, u32, log_size);
            }
        }
        return hash.finalResult();
    }
};

pub const FixedDescriptor = struct {
    v10_template_seal: [32]u8,
    ordered_layout_id: [32]u8,
    vm_plan_digest: [8]u32,
    recursion_plan_digest: [8]u32,
    geometry: geometry_mod.Geometry,
    fixed_columns_id: [32]u8,
};

pub const Writer = struct {
    allocator: std.mem.Allocator,
    key_seal: [32]u8,
    layout_id: [32]u8,
    core_profile: *core_profile_mod.CoreProfileV6,
    vm_logs: []u32,
    recursion_logs: []u32,
    vm_trees: []witness.TreeProfile,
    recursion_trees: []witness.TreeProfile,
    vm_plan: schedule.Plan,
    recursion_plan: schedule.Plan,
    reference: witness.Reference,
    preprocessing: witness.Preprocessed,

    pub fn initFromExpectedLayout(
        allocator: std.mem.Allocator,
        key: *const template.TemplateManifestV10,
        expected: ExpectedLayout,
    ) !Writer {
        try key.validate();
        try expected.validateAgainst(key);
        const v9 = key.v9_template;
        // The reference borrows the FRI-width slices. Keep this profile at a
        // stable owned address instead of borrowing a stack copy of the key.
        const core = try allocator.create(core_profile_mod.CoreProfileV6);
        errdefer allocator.destroy(core);
        core.* = v9.v8_template.v7_template.v6_template.shape.core_profile;
        const vm_logs = try cloneLogs(allocator, expected.vm_trees);
        errdefer allocator.free(vm_logs);
        const recursion_logs = try cloneLogs(allocator, expected.recursion_trees);
        errdefer allocator.free(recursion_logs);
        const vm_trees = try cloneTrees(allocator, expected.vm_trees, core.vm.tree_heights[0..core.vm.tree_count], vm_logs);
        errdefer allocator.free(vm_trees);
        const recursion_trees = try cloneTrees(allocator, expected.recursion_trees, core.recursion.tree_heights[0..core.recursion.tree_count], recursion_logs);
        errdefer allocator.free(recursion_trees);
        var vm = try schedule.Plan.initShape(allocator, v9.vm_program_spec, v9.schedule_shape);
        errdefer vm.deinit();
        var recursion = try schedule.Plan.initShape(allocator, schedule.RECURSION_PROGRAM_SPEC_V1, v9.schedule_shape);
        errdefer recursion.deinit();
        if (!std.meta.eql(vm.authority_digest, v9.v8_template.v7_template.v6_template.shape.native_plan_id) or
            !std.meta.eql(recursion.authority_digest, v9.recursion_plan_digest))
            return error.Row23PlanMismatchV11;
        const reference = try witness.Reference.seal(
            .{ .query_count = core.vm.query_count, .lifting_log_size = core.vm.lifting_log_size, .trees = vm_trees, .fri_fold_widths = core.vm.fri_fold_widths[0..core.vm.fri_count] },
            &vm,
            .{ .query_count = core.recursion.query_count, .lifting_log_size = core.recursion.lifting_log_size, .trees = recursion_trees, .fri_fold_widths = core.recursion.fri_fold_widths[0..core.recursion.fri_count] },
            &recursion,
        );
        try reference.validateQueryMapping(try core.reference());
        var preprocessing = try witness.Preprocessed.init(allocator, reference);
        errdefer preprocessing.deinit();
        return .{
            .allocator = allocator,
            .key_seal = key.seal,
            .layout_id = expected.identityDigest(),
            .core_profile = core,
            .vm_logs = vm_logs,
            .recursion_logs = recursion_logs,
            .vm_trees = vm_trees,
            .recursion_trees = recursion_trees,
            .vm_plan = vm,
            .recursion_plan = recursion,
            .reference = reference,
            .preprocessing = preprocessing,
        };
    }

    pub fn deinit(self: *Writer) void {
        self.preprocessing.deinit();
        self.recursion_plan.deinit();
        self.vm_plan.deinit();
        self.allocator.free(self.recursion_trees);
        self.allocator.free(self.vm_trees);
        self.allocator.free(self.recursion_logs);
        self.allocator.free(self.vm_logs);
        self.allocator.destroy(self.core_profile);
        self.* = undefined;
    }

    pub fn geometry(self: *const Writer) geometry_mod.Geometry {
        return typed_geometry.manifestGeometryForAir(air, geometry_mod, .trace_merkle, self.preprocessing.log_size);
    }

    pub fn requireTemplateAdmission(_: *const Writer) error{Row23FixedKeyNotInTemplateV10}!void {
        return error.Row23FixedKeyNotInTemplateV10;
    }

    pub fn writePhysical(self: *const Writer, key: *const template.TemplateManifestV10, geometry_value: geometry_mod.Geometry, columns: [][]M31) !void {
        if (!std.meta.eql(geometry_value, self.geometry()) or
            geometry_value.log_size >= @bitSizeOf(usize) or
            columns.len != air.PREPROCESSED_COLUMN_COUNT)
            return error.Row23FixedGeometryMismatchV11;
        const capacity = @as(usize, 1) << @intCast(geometry_value.log_size);
        const protected = try addressRange(witness.Row, self.preprocessing.rows);
        for (columns, 0..) |column, index| {
            if (column.len != capacity) return error.Row23FixedGeometryMismatchV11;
            const destination = try addressRange(M31, column);
            if (destination.overlaps(protected)) return error.Row23FixedAliasedDestinationV11;
            for (columns[0..index]) |prior| if (destination.overlaps(try addressRange(M31, prior)))
                return error.Row23FixedAliasedDestinationV11;
            for (column) |word| if (!word.isZero()) return error.Row23FixedDestinationNotFreshV11;
        }
        try key.validate();
        if (!std.meta.eql(key.seal, self.key_seal) or
            !std.meta.eql(self.core_profile.*, key.v9_template.v8_template.v7_template.v6_template.shape.core_profile) or
            !std.meta.eql(self.vm_plan.authority_digest, key.v9_template.v8_template.v7_template.v6_template.shape.native_plan_id) or
            !std.meta.eql(self.recursion_plan.authority_digest, key.v9_template.recursion_plan_digest))
            return error.Row23TemplateMismatchV11;
        try self.reference.validateQueryMapping(try self.core_profile.reference());
        try self.preprocessing.validateAgainstAuthority(self.reference);
        if (self.preprocessing.rows.len > capacity) return error.Row23FixedGeometryMismatchV11;
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
            .ordered_layout_id = self.layout_id,
            .vm_plan_digest = self.vm_plan.authority_digest,
            .recursion_plan_digest = self.recursion_plan.authority_digest,
            .geometry = geometry_value,
            .fixed_columns_id = hash.finalResult(),
        };
    }
};

fn validateLane(trees: []const []const u32, heights: []const u32, table_count: u32) !void {
    if (trees.len != heights.len) return error.Row23ExpectedTreeCountMismatchV11;
    var count: usize = 0;
    for (trees, heights) |logs, height| {
        if (logs.len == 0) return error.Row23ExpectedColumnLayoutMismatchV11;
        var maximum: u32 = 0;
        for (logs) |log_size| {
            if (log_size == 0 or log_size > height) return error.Row23ExpectedColumnLayoutMismatchV11;
            maximum = @max(maximum, log_size);
        }
        if (maximum != height) return error.Row23ExpectedColumnLayoutMismatchV11;
        count = try std.math.add(usize, count, logs.len);
    }
    if (count != table_count) return error.Row23ExpectedTableCountMismatchV11;
}

fn cloneLogs(allocator: std.mem.Allocator, trees: []const []const u32) ![]u32 {
    var count: usize = 0;
    for (trees) |tree| count = try std.math.add(usize, count, tree.len);
    const result = try allocator.alloc(u32, count);
    var offset: usize = 0;
    for (trees) |tree| {
        @memcpy(result[offset..][0..tree.len], tree);
        offset += tree.len;
    }
    return result;
}

fn cloneTrees(allocator: std.mem.Allocator, source: []const []const u32, heights: []const u32, logs: []u32) ![]witness.TreeProfile {
    const result = try allocator.alloc(witness.TreeProfile, source.len);
    var offset: usize = 0;
    for (result, source, heights) |*target, tree, height| {
        target.* = .{ .height = height, .column_log_sizes = logs[offset..][0..tree.len] };
        offset += tree.len;
    }
    return result;
}

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

test "V11 row23 exact fixed writer respects verifier-selected ordering" {
    const allocator = std.testing.allocator;
    const key = try testKey(allocator);
    var first_logs = [_]u32{21} ** 38;
    first_logs[0] = 20;
    var swapped_logs = first_logs;
    std.mem.swap(u32, &swapped_logs[0], &swapped_logs[1]);
    const main_logs = [_]u32{21} ** 625;
    const interaction_logs = [_]u32{21} ** 200;
    const composition_logs = [_]u32{21} ** 8;
    const first_trees = [_][]const u32{ &first_logs, &main_logs, &interaction_logs, &composition_logs };
    const swapped_trees = [_][]const u32{ &swapped_logs, &main_logs, &interaction_logs, &composition_logs };
    const first_expected = ExpectedLayout{ .vm_trees = &first_trees, .recursion_trees = &first_trees };
    const swapped_expected = ExpectedLayout{ .vm_trees = &swapped_trees, .recursion_trees = &swapped_trees };
    try first_expected.validateAgainst(&key);
    try swapped_expected.validateAgainst(&key);
    try std.testing.expect(!std.meta.eql(first_expected.identityDigest(), swapped_expected.identityDigest()));
    var first = try Writer.initFromExpectedLayout(allocator, &key, first_expected);
    defer first.deinit();
    var swapped = try Writer.initFromExpectedLayout(allocator, &key, swapped_expected);
    defer swapped.deinit();
    const first_desc = try first.descriptor(&key);
    const swapped_desc = try swapped.descriptor(&key);
    try std.testing.expectEqualDeep(first.geometry(), swapped.geometry());
    try std.testing.expect(!std.meta.eql(first_desc.fixed_columns_id, swapped_desc.fixed_columns_id));
    try std.testing.expectError(error.Row23FixedKeyNotInTemplateV10, first.requireTemplateAdmission());
    try std.testing.expect(!PRODUCTION_PROOF_ACTIVATION);
    try std.testing.expect(!TEMPLATE_ADMISSION_AVAILABLE);

    const geometry_value = first.geometry();
    const capacity = @as(usize, 1) << @intCast(geometry_value.log_size);
    const physical = try allocColumns(allocator, capacity);
    defer freeColumns(allocator, physical);
    try first.writePhysical(&key, geometry_value, physical);
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
    try executor.generatePreprocessedInto(&first.preprocessing, first.reference, &logical);
    for (logical, physical) |native_column, physical_column|
        for (native_column, 0..) |value, row|
            try std.testing.expectEqual(value, physical_column[framework.committedRow(row, geometry_value.log_size)]);

    // A caller may release or mutate its layout after cold admission; the
    // writer owns an authenticated copy and must not follow the mutation.
    first_logs[0] = 18;
    try std.testing.expectEqualDeep(first_desc, try first.descriptor(&key));
    first.vm_logs[0] = 18;
    for (physical) |column| @memset(column, M31.zero());
    try std.testing.expectError(error.AuthorityMismatch, first.writePhysical(&key, geometry_value, physical));
    for (physical) |column| for (column) |value| try std.testing.expect(value.isZero());
}

test "V11 row23 rejects malformed expected shape before fixed writes" {
    const allocator = std.testing.allocator;
    const key = try testKey(allocator);
    const full = [_]u32{21} ** 38;
    const main = [_]u32{21} ** 625;
    const interaction = [_]u32{21} ** 200;
    const composition = [_]u32{21} ** 8;
    const valid_trees = [_][]const u32{ &full, &main, &interaction, &composition };
    var bad_trees = valid_trees;
    bad_trees[0] = full[0..37];
    try std.testing.expectError(error.Row23ExpectedTableCountMismatchV11, (ExpectedLayout{
        .vm_trees = &bad_trees,
        .recursion_trees = &valid_trees,
    }).validateAgainst(&key));
    bad_trees[0] = &[_]u32{0};
    try std.testing.expectError(error.Row23ExpectedColumnLayoutMismatchV11, (ExpectedLayout{
        .vm_trees = &bad_trees,
        .recursion_trees = &valid_trees,
    }).validateAgainst(&key));
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
