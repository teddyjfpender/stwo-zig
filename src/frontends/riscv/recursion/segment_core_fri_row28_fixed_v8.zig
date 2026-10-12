//! Candidate exact fixed Tree0 writer for universal FRI-control row 28.
//!
//! VM and recursion verifier plans plus their query/FRI profiles are inputs
//! selected by the verifier. The child proof supplies no row, witness value,
//! or schedule digest. The current V8 direct-leaf template does not yet seal
//! the recursion plan's authority digest, so this writer cannot be admitted
//! as a complete production key until that plan is added to the template.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const core_profile = @import("air/segment_leaf_wrapper_template_v6.zig");
const schedule = @import("air/verifier_schedule.zig");
const mapping = @import("air/query_mapping_witness.zig");
const witness = @import("air/fri_verifier_control_witness.zig");
const air = @import("air/fri_verifier_control.zig");
const geometry_mod = @import("air/universal_manifest_contract.zig");
const typed_geometry = @import("air/universal_typed_geometry.zig");
const framework = @import("air/framework_interaction.zig");

pub const ROW: u8 = 28;
pub const PRODUCTION_PROOF_ACTIVATION = false;
pub const TEMPLATE_ADMISSION_AVAILABLE = false;

pub const Writer = struct {
    allocator: std.mem.Allocator,
    profile: core_profile.CoreProfileV6,
    reference: witness.Reference,
    preprocessing: witness.Preprocessed,

    /// Both plan pointers must remain alive and immutable until `deinit`.
    /// `Reference.seal` independently validates their full schedule digests.
    pub fn init(
        allocator: std.mem.Allocator,
        profile: *const core_profile.CoreProfileV6,
        vm_plan: *const schedule.Plan,
        recursion_plan: *const schedule.Plan,
    ) !Writer {
        const mapping_reference = try profile.reference();
        const reference = try witness.Reference.seal(
            .{ .plan = vm_plan, .mapping = profile.vm.view() },
            .{ .plan = recursion_plan, .mapping = profile.recursion.view() },
        );
        const expected_mapping = try reference.mappingReference();
        if (!std.meta.eql(expected_mapping.authority_digest, mapping_reference.authority_digest))
            return error.CoreFriControlMappingMismatchV8;
        const preprocessing = try witness.Preprocessed.init(allocator, reference);
        return .{
            .allocator = allocator,
            .profile = profile.*,
            .reference = reference,
            .preprocessing = preprocessing,
        };
    }

    pub fn deinit(self: *Writer) void {
        self.preprocessing.deinit();
        self.* = undefined;
    }

    pub fn geometry(self: *const Writer) geometry_mod.Geometry {
        return typed_geometry.manifestGeometryForAir(air, geometry_mod, .fri_verifier_control, self.preprocessing.log_size);
    }

    /// The current V8 shape seals the VM schedule only. Publishing row 28
    /// under it would let an unbound recursion plan select fixed columns.
    pub fn requireTemplateAdmission(_: *const Writer) error{CoreFriControlPlanNotInTemplateV8}!void {
        return error.CoreFriControlPlanNotInTemplateV8;
    }

    /// All geometry, authority, freshness and alias checks precede writes.
    /// Every padded cell remains zero; the native logical writer is compared
    /// against these exact committed cells in the tests below.
    pub fn writePhysical(self: *const Writer, geometry_value: geometry_mod.Geometry, columns: [][]M31) !void {
        const expected = self.geometry();
        if (!std.meta.eql(geometry_value, expected) or
            geometry_value.log_size >= @bitSizeOf(usize) or
            columns.len != air.PREPROCESSED_COLUMN_COUNT)
            return error.CoreFriControlFixedGeometryMismatchV8;
        const capacity = @as(usize, 1) << @intCast(geometry_value.log_size);
        const protected = try addressRange(witness.Row, self.preprocessing.rows);
        for (columns, 0..) |column, index| {
            if (column.len != capacity) return error.CoreFriControlFixedGeometryMismatchV8;
            const destination = try addressRange(M31, column);
            if (destination.overlaps(protected)) return error.CoreFriControlFixedAliasedDestinationV8;
            for (columns[0..index]) |prior| {
                if (destination.overlaps(try addressRange(M31, prior)))
                    return error.CoreFriControlFixedAliasedDestinationV8;
            }
            for (column) |value| if (!value.isZero()) return error.CoreFriControlFixedDestinationNotFreshV8;
        }
        try self.reference.validateAuthority();
        const profile_mapping = try self.profile.reference();
        const expected_mapping = try self.reference.mappingReference();
        if (!std.meta.eql(profile_mapping.authority_digest, expected_mapping.authority_digest))
            return error.CoreFriControlMappingMismatchV8;
        try self.preprocessing.validateAgainstAuthority(self.reference);
        if (self.preprocessing.rows.len > capacity) return error.CoreFriControlFixedGeometryMismatchV8;
        for (self.preprocessing.rows, 0..) |row, logical| {
            const physical = framework.committedRow(logical, geometry_value.log_size);
            const values = row.values();
            for (columns, values) |column, value| column[physical] = value;
        }
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

test "V8 row28 fixed writer matches native logical columns at every committed cell" {
    const allocator = std.testing.allocator;
    var plans = try @import("segment_profile.zig").initPlans(allocator, 16, 16);
    defer plans.vm.deinit();
    defer plans.recursion.deinit();
    const profile = try core_profile.testFrozenCoreProfileV6();
    var writer = try Writer.init(allocator, &profile, &plans.vm, &plans.recursion);
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
    try writer.writePhysical(geometry_value, columns);

    var definition = try air.build(allocator);
    defer definition.deinit();
    const binding = try witness.Binding.canonical(&definition);
    const executor = try witness.Executor.init(&definition, &binding);
    var logical: [air.PREPROCESSED_COLUMN_COUNT][]M31 = undefined;
    for (&logical) |*column| column.* = try allocator.alloc(M31, capacity);
    defer for (logical) |column| allocator.free(column);
    try executor.generatePreprocessedInto(&writer.preprocessing, writer.reference, &logical);
    for (logical, columns) |native_column, physical_column|
        for (native_column, 0..) |value, logical_row|
            try std.testing.expectEqual(value, physical_column[framework.committedRow(logical_row, geometry_value.log_size)]);
    try std.testing.expectError(error.CoreFriControlPlanNotInTemplateV8, writer.requireTemplateAdmission());
    try std.testing.expectError(error.CoreFriControlFixedDestinationNotFreshV8, writer.writePhysical(geometry_value, columns));
    for (columns) |column| @memset(column, M31.zero());
    const duplicate = try allocator.dupe([]M31, columns);
    defer allocator.free(duplicate);
    duplicate[1] = duplicate[0];
    try std.testing.expectError(error.CoreFriControlFixedAliasedDestinationV8, writer.writePhysical(geometry_value, duplicate));
    var changed = geometry_value;
    changed.semantic_digest[0] ^= 1;
    try std.testing.expectError(error.CoreFriControlFixedGeometryMismatchV8, writer.writePhysical(changed, columns));
    changed = geometry_value;
    changed.protocol_constraint_degree += 1;
    try std.testing.expectError(error.CoreFriControlFixedGeometryMismatchV8, writer.writePhysical(changed, columns));
}

test "V8 row28 fixed writer rejects plan and profile mutation before Tree0 writes" {
    const allocator = std.testing.allocator;
    var plans = try @import("segment_profile.zig").initPlans(allocator, 16, 16);
    defer plans.vm.deinit();
    defer plans.recursion.deinit();
    const profile = try core_profile.testFrozenCoreProfileV6();
    var writer = try Writer.init(allocator, &profile, &plans.vm, &plans.recursion);
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

    const first = plans.recursion.steps[0];
    defer @constCast(plans.recursion.steps)[0] = first;
    @constCast(plans.recursion.steps)[0] = .bind_statement;
    try std.testing.expectError(error.ScheduleDigestMismatch, writer.writePhysical(geometry_value, columns));
    for (columns) |column| for (column) |word| try std.testing.expect(word.isZero());
    @constCast(plans.recursion.steps)[0] = first;
    writer.profile.recursion.query_count += 1;
    try std.testing.expectError(error.CoreFriControlMappingMismatchV8, writer.writePhysical(geometry_value, columns));
    for (columns) |column| for (column) |word| try std.testing.expect(word.isZero());
}
