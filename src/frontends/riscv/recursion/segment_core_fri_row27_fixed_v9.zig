//! Candidate exact fixed Tree0 writer for FRI-Merkle anchor row 27.
//!
//! V9 already seals the verifier-selected VM and recursion control plans.
//! Together with its core FRI profile, they determine every row-27 fixed
//! cell, including padding. This module derives that schedule without a child
//! proof. V9 does not yet seal the resulting row-27 fixed digest or corrected
//! placement, so template admission deliberately fails closed.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const template = @import("air/segment_leaf_wrapper_template_v9.zig");
const schedule = @import("air/verifier_schedule.zig");
const fri_fixed = @import("segment_core_fri_rows25_26_fixed_v7.zig");
const witness = @import("air/fri_merkle_anchor_witness.zig");
const air = @import("air/fri_merkle_anchor.zig");
const geometry_mod = @import("air/universal_manifest_contract.zig");
const typed_geometry = @import("air/universal_typed_geometry.zig");
const framework = @import("air/framework_interaction.zig");

pub const ROW: u8 = 27;
pub const FIXED_COLUMNS_DOMAIN = "stwo-zig/riscv-v9-row27-complete-fixed-columns/v1\x00";
pub const PRODUCTION_PROOF_ACTIVATION = false;
pub const TEMPLATE_ADMISSION_AVAILABLE = false;

pub const FixedDescriptor = struct {
    v9_template_seal: [32]u8,
    vm_plan_digest: [8]u32,
    recursion_plan_digest: [8]u32,
    geometry: geometry_mod.Geometry,
    fixed_columns_id: [32]u8,
};

pub const Writer = struct {
    allocator: std.mem.Allocator,
    key_seal: [32]u8,
    vm_plan: schedule.Plan,
    recursion_plan: schedule.Plan,
    fri: fri_fixed.Writer,
    preprocessing: witness.Preprocessed,

    pub fn initFromVerifierTemplate(allocator: std.mem.Allocator, key: *const template.TemplateManifestV9) !Writer {
        try key.validate();
        var vm = try schedule.Plan.initShape(allocator, key.vm_program_spec, key.schedule_shape);
        errdefer vm.deinit();
        var recursion = try schedule.Plan.initShape(allocator, schedule.RECURSION_PROGRAM_SPEC_V1, key.schedule_shape);
        errdefer recursion.deinit();
        if (!std.meta.eql(vm.authority_digest, key.v8_template.v7_template.v6_template.shape.native_plan_id) or
            !std.meta.eql(recursion.authority_digest, key.recursion_plan_digest))
            return error.CoreFriAnchorPlanMismatchV9;
        var fri = try fri_fixed.Writer.init(allocator, &key.v8_template.v7_template.v6_template.shape.core_profile);
        errdefer fri.deinit();
        var preprocessing = try witness.Preprocessed.init(allocator, fri.reference, &vm, &recursion);
        errdefer preprocessing.deinit();
        return .{
            .allocator = allocator,
            .key_seal = key.seal,
            .vm_plan = vm,
            .recursion_plan = recursion,
            .fri = fri,
            .preprocessing = preprocessing,
        };
    }

    pub fn deinit(self: *Writer) void {
        self.preprocessing.deinit();
        self.fri.deinit();
        self.recursion_plan.deinit();
        self.vm_plan.deinit();
        self.* = undefined;
    }

    pub fn geometry(self: *const Writer) geometry_mod.Geometry {
        return typed_geometry.manifestGeometryForAir(air, geometry_mod, .fri_merkle_anchor, self.preprocessing.log_size);
    }

    pub fn requireTemplateAdmission(_: *const Writer) error{CoreFriAnchorFixedKeyNotInTemplateV9}!void {
        return error.CoreFriAnchorFixedKeyNotInTemplateV9;
    }

    pub fn writePhysical(
        self: *const Writer,
        key: *const template.TemplateManifestV9,
        geometry_value: geometry_mod.Geometry,
        columns: [][]M31,
    ) !void {
        if (!std.meta.eql(geometry_value, self.geometry()) or
            geometry_value.log_size >= @bitSizeOf(usize) or
            columns.len != air.PREPROCESSED_COLUMN_COUNT)
            return error.CoreFriAnchorFixedGeometryMismatchV9;
        const capacity = @as(usize, 1) << @intCast(geometry_value.log_size);
        const protected = try addressRange(witness.Row, self.preprocessing.rows);
        for (columns, 0..) |column, index| {
            if (column.len != capacity) return error.CoreFriAnchorFixedGeometryMismatchV9;
            const destination = try addressRange(M31, column);
            if (destination.overlaps(protected)) return error.CoreFriAnchorFixedAliasedDestinationV9;
            for (columns[0..index]) |prior| if (destination.overlaps(try addressRange(M31, prior)))
                return error.CoreFriAnchorFixedAliasedDestinationV9;
            for (column) |word| if (!word.isZero()) return error.CoreFriAnchorFixedDestinationNotFreshV9;
        }
        try key.validate();
        if (!std.meta.eql(key.seal, self.key_seal) or
            !std.meta.eql(self.vm_plan.authority_digest, key.v8_template.v7_template.v6_template.shape.native_plan_id) or
            !std.meta.eql(self.recursion_plan.authority_digest, key.recursion_plan_digest))
            return error.CoreFriAnchorTemplateMismatchV9;
        try self.preprocessing.validateAgainstAuthority(self.fri.reference, &self.vm_plan, &self.recursion_plan);
        if (self.preprocessing.rows.len > capacity) return error.CoreFriAnchorFixedGeometryMismatchV9;
        for (self.preprocessing.rows, 0..) |row, logical| {
            const committed = framework.committedRow(logical, geometry_value.log_size);
            const values = row.values();
            for (columns, values) |column, value| column[committed] = value;
        }
    }

    pub fn descriptor(self: *const Writer, key: *const template.TemplateManifestV9) !FixedDescriptor {
        const geometry_value = self.geometry();
        const capacity = @as(usize, 1) << @intCast(geometry_value.log_size);
        const columns = try self.allocator.alloc([]M31, air.PREPROCESSED_COLUMN_COUNT);
        defer self.allocator.free(columns);
        for (columns) |*column| {
            column.* = try self.allocator.alloc(M31, capacity);
            @memset(column.*, M31.zero());
        }
        defer for (columns) |column| self.allocator.free(column);
        try self.writePhysical(key, geometry_value, columns);
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(FIXED_COLUMNS_DOMAIN);
        hashInt(&hash, u8, ROW);
        hashInt(&hash, u32, geometry_value.log_size);
        hashInt(&hash, u16, geometry_value.preprocessed_columns);
        hash.update(&air.SEMANTIC_DIGEST);
        for (columns) |column| for (column) |word| hashInt(&hash, u32, word.toU32());
        return .{
            .v9_template_seal = self.key_seal,
            .vm_plan_digest = self.vm_plan.authority_digest,
            .recursion_plan_digest = self.recursion_plan.authority_digest,
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

test "V9 row27 fixed columns match native writer at every committed cell" {
    const allocator = std.testing.allocator;
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
    const key = try template.TemplateManifestV9.build(
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
    var writer = try Writer.initFromVerifierTemplate(allocator, &key);
    defer writer.deinit();
    const geometry_value = writer.geometry();
    const capacity = @as(usize, 1) << @intCast(geometry_value.log_size);
    const columns = try allocator.alloc([]M31, air.PREPROCESSED_COLUMN_COUNT);
    defer allocator.free(columns);
    for (columns) |*column| {
        column.* = try allocator.alloc(M31, capacity);
        @memset(column.*, M31.zero());
    }
    defer for (columns) |column| allocator.free(column);
    try writer.writePhysical(&key, geometry_value, columns);

    var definition = try air.build(allocator);
    defer definition.deinit();
    const binding = try witness.Binding.canonical(&definition);
    const executor = try witness.Executor.init(&definition, &binding);
    var logical: [air.PREPROCESSED_COLUMN_COUNT][]M31 = undefined;
    for (&logical) |*column| column.* = try allocator.alloc(M31, capacity);
    defer for (logical) |column| allocator.free(column);
    try executor.generatePreprocessedInto(&writer.preprocessing, writer.fri.reference, &writer.vm_plan, &writer.recursion_plan, &logical);
    for (logical, columns) |native_column, physical_column|
        for (native_column, 0..) |value, index|
            try std.testing.expectEqual(value, physical_column[framework.committedRow(index, geometry_value.log_size)]);

    const first = try writer.descriptor(&key);
    try std.testing.expectEqualDeep(geometry_value, first.geometry);
    try std.testing.expectEqualDeep(key.recursion_plan_digest, first.recursion_plan_digest);
    try std.testing.expectError(error.CoreFriAnchorFixedKeyNotInTemplateV9, writer.requireTemplateAdmission());
    try std.testing.expectError(error.CoreFriAnchorFixedDestinationNotFreshV9, writer.writePhysical(&key, geometry_value, columns));
    for (columns) |column| @memset(column, M31.zero());
    const alias = try allocator.dupe([]M31, columns);
    defer allocator.free(alias);
    alias[1] = alias[0];
    try std.testing.expectError(error.CoreFriAnchorFixedAliasedDestinationV9, writer.writePhysical(&key, geometry_value, alias));
    var wrong = geometry_value;
    wrong.semantic_digest[0] ^= 1;
    try std.testing.expectError(error.CoreFriAnchorFixedGeometryMismatchV9, writer.writePhysical(&key, wrong, columns));
    wrong = geometry_value;
    wrong.protocol_constraint_degree += 1;
    try std.testing.expectError(error.CoreFriAnchorFixedGeometryMismatchV9, writer.writePhysical(&key, wrong, columns));
    var wrong_key = key;
    wrong_key.seal[0] ^= 1;
    if (writer.writePhysical(&wrong_key, geometry_value, columns)) |_| return error.TestExpectedError else |_| {}
    for (columns) |column| for (column) |word| try std.testing.expect(word.isZero());
}

test "V9 row27 writer detects verifier plan mutation before Tree0 writes" {
    const allocator = std.testing.allocator;
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
    const key = try template.TemplateManifestV9.build(
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
    var writer = try Writer.initFromVerifierTemplate(allocator, &key);
    defer writer.deinit();
    const geometry_value = writer.geometry();
    const capacity = @as(usize, 1) << @intCast(geometry_value.log_size);
    const columns = try allocator.alloc([]M31, air.PREPROCESSED_COLUMN_COUNT);
    defer allocator.free(columns);
    for (columns) |*column| {
        column.* = try allocator.alloc(M31, capacity);
        @memset(column.*, M31.zero());
    }
    defer for (columns) |column| allocator.free(column);
    const first = writer.recursion_plan.steps[0];
    defer @constCast(writer.recursion_plan.steps)[0] = first;
    @constCast(writer.recursion_plan.steps)[0] = .bind_statement;
    try std.testing.expectError(error.ScheduleDigestMismatch, writer.writePhysical(&key, geometry_value, columns));
    for (columns) |column| for (column) |word| try std.testing.expect(word.isZero());
    @constCast(writer.recursion_plan.steps)[0] = first;
    writer.preprocessing.rows[0].control_tag += 1;
    try std.testing.expectError(error.AuthorityMismatch, writer.writePhysical(&key, geometry_value, columns));
    for (columns) |column| for (column) |word| try std.testing.expect(word.isZero());
}
