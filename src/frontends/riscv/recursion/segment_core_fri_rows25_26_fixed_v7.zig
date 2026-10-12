//! Verifier-owned fixed Tree0 rows for the FRI leaf and node components.
//!
//! These two schedules depend only on the admitted VM/recursion FRI geometry.
//! No child proof, statement digest, opening, or captured source column enters
//! the key. Other core rows require additional shape authorities and remain
//! deliberately outside this writer.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const profile_mod = @import("air/segment_leaf_wrapper_template_v6.zig");
const geometry_mod = @import("air/universal_manifest_contract.zig");
const typed_geometry = @import("air/universal_typed_geometry.zig");
const framework = @import("air/framework_interaction.zig");
const leaf_air = @import("air/fri_merkle_leaf.zig");
const node_air = @import("air/fri_merkle_node.zig");
const leaf = @import("air/fri_merkle_leaf_witness.zig");
const node = @import("air/fri_merkle_node_witness.zig");

pub const QUALIFIED_ROWS = [_]u8{ 25, 26 };
pub const PRODUCTION_PROOF_ACTIVATION = false;

pub const Writer = struct {
    allocator: std.mem.Allocator,
    profile: profile_mod.CoreProfileV6,
    vm_layers: []leaf.LayerProfile,
    recursion_layers: []leaf.LayerProfile,
    reference: leaf.Reference,
    leaf_rows: leaf.Preprocessed,
    node_rows: node.Preprocessed,

    pub fn init(allocator: std.mem.Allocator, profile: *const profile_mod.CoreProfileV6) !Writer {
        _ = try profile.reference();
        const vm_layers = try layersFor(allocator, &profile.vm);
        errdefer allocator.free(vm_layers);
        const recursion_layers = try layersFor(allocator, &profile.recursion);
        errdefer allocator.free(recursion_layers);
        const reference = try leaf.Reference.seal(
            .{ .query_count = profile.vm.query_count, .lifting_log_size = profile.vm.lifting_log_size, .layers = vm_layers },
            .{ .query_count = profile.recursion.query_count, .lifting_log_size = profile.recursion.lifting_log_size, .layers = recursion_layers },
        );
        try reference.validateQueryMapping(try profile.reference());
        var leaf_rows = try leaf.Preprocessed.init(allocator, reference);
        errdefer leaf_rows.deinit();
        var node_rows = try node.Preprocessed.init(allocator, reference);
        errdefer node_rows.deinit();
        return .{
            .allocator = allocator,
            .profile = profile.*,
            .vm_layers = vm_layers,
            .recursion_layers = recursion_layers,
            .reference = reference,
            .leaf_rows = leaf_rows,
            .node_rows = node_rows,
        };
    }

    pub fn deinit(self: *Writer) void {
        self.node_rows.deinit();
        self.leaf_rows.deinit();
        self.allocator.free(self.recursion_layers);
        self.allocator.free(self.vm_layers);
        self.* = undefined;
    }

    /// The caller supplies fresh, complete physical columns for one row.
    /// All validation precedes the first write.
    pub fn writeRow(self: *const Writer, row: u8, geometry: geometry_mod.Geometry, columns: [][]M31) !void {
        if (row != 25 and row != 26) return error.UnqualifiedCoreFixedRowV7;
        const expected_log = if (row == 25) self.leaf_rows.log_size else self.node_rows.log_size;
        const expected = if (row == 25)
            typed_geometry.manifestGeometryForAir(leaf_air, geometry_mod, .fri_merkle_leaf, expected_log)
        else
            typed_geometry.manifestGeometryForAir(node_air, geometry_mod, .fri_merkle_node, expected_log);
        if (!std.meta.eql(geometry, expected) or geometry.log_size >= @bitSizeOf(usize) or
            columns.len != expected.preprocessed_columns)
            return error.CoreFixedGeometryMismatchV7;
        const capacity = @as(usize, 1) << @intCast(geometry.log_size);
        const protected_rows = if (row == 25)
            try addressRange(leaf.Row, self.leaf_rows.rows)
        else
            try addressRange(node.Row, self.node_rows.rows);
        for (columns, 0..) |column, index| {
            if (column.len != capacity) return error.CoreFixedGeometryMismatchV7;
            const destination = try addressRange(M31, column);
            if (destination.overlaps(protected_rows)) return error.CoreFixedAliasedDestinationV7;
            for (columns[0..index]) |earlier| {
                if (destination.overlaps(try addressRange(M31, earlier)))
                    return error.CoreFixedAliasedDestinationV7;
            }
        }
        for (columns) |column| for (column) |value| {
            if (!value.isZero()) return error.CoreFixedDestinationNotFreshV7;
        };
        try self.reference.validateQueryMapping(try self.profile.reference());
        if (row == 25) {
            try self.leaf_rows.validateAgainstAuthority(self.reference);
            if (self.leaf_rows.rows.len > capacity) return error.CoreFixedGeometryMismatchV7;
            for (self.leaf_rows.rows, 0..) |fixed, logical| {
                const values = fixed.values();
                put(columns, geometry.log_size, logical, &values);
            }
        } else {
            try self.node_rows.validateAgainstAuthority(self.reference);
            if (self.node_rows.rows.len > capacity) return error.CoreFixedGeometryMismatchV7;
            for (self.node_rows.rows, 0..) |fixed, logical| {
                const values = fixed.values();
                put(columns, geometry.log_size, logical, &values);
            }
        }
    }
};

fn layersFor(allocator: std.mem.Allocator, lane: *const profile_mod.CoreLaneV6) ![]leaf.LayerProfile {
    try lane.validate();
    const widths = lane.fri_fold_widths[0..lane.fri_count];
    const layers = try allocator.alloc(leaf.LayerProfile, widths.len);
    errdefer allocator.free(layers);
    var folded_bits: u32 = 0;
    for (widths, layers) |width, *item| {
        if (width < 2 or !std.math.isPowerOfTwo(width)) return error.InvalidCoreFriShapeV7;
        const fold_step = std.math.log2_int(u32, width);
        const leaf_bits: u32 = if (fold_step > 1) @min(fold_step, std.math.log2_int(u32, leaf.PACKED_LEAF_SIZE)) else 0;
        const height = try std.math.sub(u32, try std.math.sub(u32, lane.lifting_log_size, folded_bits), leaf_bits);
        item.* = .{ .width = width, .tree_height = height };
        folded_bits = try std.math.add(u32, folded_bits, fold_step);
    }
    return layers;
}

fn put(columns: [][]M31, log_size: u32, logical: usize, values: []const M31) void {
    const physical = framework.committedRow(logical, log_size);
    for (values, columns) |value, column| column[physical] = value;
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
    const byte_count = try std.math.mul(usize, values.len, @sizeOf(T));
    return .{ .start = start, .end = try std.math.add(usize, start, byte_count) };
}

test "FRI leaf and node fixed columns are independently reconstructed from admitted profile" {
    const typed = @import("air/universal_typed_component.zig");
    const allocator = std.testing.allocator;
    const profile = try profile_mod.testFrozenCoreProfileV6();
    var writer = try Writer.init(allocator, &profile);
    defer writer.deinit();
    for (QUALIFIED_ROWS) |row| {
        const geometry = if (row == 25)
            typed.manifestGeometryForAir(leaf_air, geometry_mod, .fri_merkle_leaf, writer.leaf_rows.log_size)
        else
            typed.manifestGeometryForAir(node_air, geometry_mod, .fri_merkle_node, writer.node_rows.log_size);
        const capacity = @as(usize, 1) << @intCast(geometry.log_size);
        const columns = try allocator.alloc([]M31, geometry.preprocessed_columns);
        defer allocator.free(columns);
        for (columns) |*column| {
            column.* = try allocator.alloc(M31, capacity);
            @memset(column.*, M31.zero());
        }
        defer for (columns) |column| allocator.free(column);
        try writer.writeRow(row, geometry, columns);
        if (row == 25)
            try expectNativeSourceParity(leaf_air, leaf, allocator, &writer.leaf_rows, writer.reference, geometry.log_size, columns)
        else
            try expectNativeSourceParity(node_air, node, allocator, &writer.node_rows, writer.reference, geometry.log_size, columns);
        const rows_len = if (row == 25) writer.leaf_rows.rows.len else writer.node_rows.rows.len;
        for (0..capacity) |logical| {
            const physical = framework.committedRow(logical, geometry.log_size);
            if (logical < rows_len) {
                if (row == 25) {
                    const expected = writer.leaf_rows.rows[logical].values();
                    for (columns, &expected) |column, value| try std.testing.expectEqual(value.toU32(), column[physical].toU32());
                } else {
                    const expected = writer.node_rows.rows[logical].values();
                    for (columns, &expected) |column, value| try std.testing.expectEqual(value.toU32(), column[physical].toU32());
                }
            } else {
                for (columns) |column| try std.testing.expect(column[physical].isZero());
            }
        }
        try std.testing.expectError(error.CoreFixedDestinationNotFreshV7, writer.writeRow(row, geometry, columns));
        const alias = try allocator.dupe([]M31, columns);
        defer allocator.free(alias);
        alias[1] = alias[0];
        try std.testing.expectError(error.CoreFixedAliasedDestinationV7, writer.writeRow(row, geometry, alias));
        var wrong = geometry;
        wrong.semantic_digest[0] ^= 1;
        try std.testing.expectError(error.CoreFixedGeometryMismatchV7, writer.writeRow(row, wrong, columns));
        wrong = geometry;
        wrong.protocol_constraint_degree += 1;
        try std.testing.expectError(error.CoreFixedGeometryMismatchV7, writer.writeRow(row, wrong, columns));
        try std.testing.expectError(error.UnqualifiedCoreFixedRowV7, writer.writeRow(24, geometry, columns));
    }
}

fn expectNativeSourceParity(
    comptime Air: type,
    comptime Witness: type,
    allocator: std.mem.Allocator,
    preprocessing: *const Witness.Preprocessed,
    reference: Witness.Reference,
    log_size: u32,
    physical: [][]M31,
) !void {
    var definition = try Air.build(allocator);
    defer definition.deinit();
    const binding = try Witness.Binding.canonical(&definition);
    const executor = try Witness.Executor.init(&definition, &binding);
    const capacity = @as(usize, 1) << @intCast(log_size);
    var source: [Air.PREPROCESSED_COLUMN_COUNT][]M31 = undefined;
    for (&source) |*column| column.* = try allocator.alloc(M31, capacity);
    defer for (source) |column| allocator.free(column);
    try executor.generatePreprocessedInto(preprocessing, reference, &source);
    for (source, physical) |logical_column, physical_column| {
        for (logical_column, 0..) |value, logical| {
            try std.testing.expectEqual(value.toU32(), physical_column[framework.committedRow(logical, log_size)].toU32());
        }
    }
}

test "FRI fixed writer rejects changed authority before touching Tree0" {
    const typed = @import("air/universal_typed_component.zig");
    const allocator = std.testing.allocator;
    const profile = try profile_mod.testFrozenCoreProfileV6();
    var writer = try Writer.init(allocator, &profile);
    defer writer.deinit();
    const geometry = typed.manifestGeometryForAir(leaf_air, geometry_mod, .fri_merkle_leaf, writer.leaf_rows.log_size);
    const capacity = @as(usize, 1) << @intCast(geometry.log_size);
    const columns = try allocator.alloc([]M31, geometry.preprocessed_columns);
    defer allocator.free(columns);
    for (columns) |*column| {
        column.* = try allocator.alloc(M31, capacity);
        @memset(column.*, M31.zero());
    }
    defer for (columns) |column| allocator.free(column);
    writer.leaf_rows.rows[0].query += 1;
    try std.testing.expectError(error.AuthorityMismatch, writer.writeRow(25, geometry, columns));
    for (columns) |column| for (column) |value| try std.testing.expect(value.isZero());
    writer.leaf_rows.rows[0].query -= 1;
    writer.profile.vm.query_count += 1;
    try std.testing.expectError(error.AuthorityMismatch, writer.writeRow(25, geometry, columns));
    for (columns) |column| for (column) |value| try std.testing.expect(value.isZero());
}
