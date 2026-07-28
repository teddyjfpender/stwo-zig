//! Materialize fixed-table lookup words from authenticated source recipes.

const std = @import("std");
const preprocessed = @import("../preprocessed/columns.zig");
const pedersen_table = @import("../preprocessed/pedersen_table.zig");
const fixed_table_bundle = @import("fixed_table_bundle.zig");
const interaction_source = @import("interaction_source.zig");
const multiplicity_tables = @import("../conformance/multiplicity_tables.zig");

pub const Materialized = struct {
    allocator: std.mem.Allocator,
    rows: u32,
    columns: u32,
    /// Column-major lookup values.
    values: []u32,

    pub fn deinit(self: *Materialized) void {
        self.allocator.free(self.values);
        self.* = undefined;
    }
};

pub const Error = error{
    AllocationSizeOverflow,
    InvalidDescriptor,
    MissingMultiplicityColumn,
};

/// Lazy fixed-table lookup source. The descriptor bundle remains the source of
/// column order, while large preprocessed tables can remain in their native
/// representation instead of being expanded into another lookup matrix.
pub const Source = struct {
    entry: fixed_table_bundle.Entry,
    tables: *multiplicity_tables.Tables,
    pedersen: ?*const pedersen_table.Table = null,

    pub fn lookupColumns(self: *const Source) interaction_source.Error!interaction_source.LookupColumns {
        return interaction_source.LookupColumns.virtual(
            self.entry.row_count,
            self.entry.lookupCount(),
            self,
            read,
        );
    }

    fn read(
        raw_context: *const anyopaque,
        column: usize,
        row: usize,
    ) interaction_source.Error!u32 {
        const self: *const Source = @ptrCast(@alignCast(raw_context));
        if (column >= self.entry.lookupCount() or row >= self.entry.row_count)
            return error.InvalidSourceShape;
        const descriptor = self.entry.lookup_descriptors[column * 4 ..][0..4];
        return switch (descriptor[0]) {
            0 => descriptor[1],
            1 => self.preprocessedValue(descriptor[1], row),
            2 => self.tables.value(
                self.entry.component,
                descriptor[1],
                row,
            ) catch error.InvalidSourceShape,
            3, 4, 5 => expandedXorValue(descriptor, row) catch
                error.InvalidSourceShape,
            else => error.InvalidSourceShape,
        };
    }

    fn preprocessedValue(
        self: *const Source,
        source_index: u32,
        row: usize,
    ) interaction_source.Error!u32 {
        if (source_index >= self.entry.preprocessed_sources.len)
            return error.InvalidSourceShape;
        const identity = self.entry.preprocessed_sources[source_index];
        if (pedersenIdentity(identity)) |expected| {
            const table = self.pedersen orelse return error.InvalidSourceShape;
            if (table.window != expected) return error.InvalidSourceShape;
            const column = pedersenColumn(identity) orelse return error.InvalidSourceShape;
            return table.value(column, row) catch return error.InvalidSourceShape;
        }
        return preprocessed.value(identity, @intCast(row)) catch
            return error.InvalidSourceShape;
    }
};

pub fn materialize(
    allocator: std.mem.Allocator,
    entry: fixed_table_bundle.Entry,
    tables: *multiplicity_tables.Tables,
) !Materialized {
    const columns: u32 = @intCast(entry.lookupCount());
    const value_count = std.math.mul(usize, entry.row_count, columns) catch
        return Error.AllocationSizeOverflow;
    const values = try allocator.alloc(u32, value_count);
    errdefer allocator.free(values);
    const zeros = try allocator.alloc(u32, entry.row_count);
    defer allocator.free(zeros);
    @memset(zeros, 0);

    for (0..columns) |column| {
        const descriptor = entry.lookup_descriptors[column * 4 ..][0..4];
        const destination = values[column * entry.row_count ..][0..entry.row_count];
        switch (descriptor[0]) {
            0 => @memset(destination, descriptor[1]),
            1 => {
                if (descriptor[1] >= entry.preprocessed_sources.len)
                    return Error.InvalidDescriptor;
                for (destination, 0..) |*value, row|
                    value.* = try preprocessed.value(
                        entry.preprocessed_sources[descriptor[1]],
                        @intCast(row),
                    );
            },
            2 => {
                const source = tables.column(entry.component, descriptor[1], zeros) catch
                    return Error.MissingMultiplicityColumn;
                @memcpy(destination, source);
            },
            3, 4, 5 => try writeExpandedXor(descriptor, destination),
            else => return Error.InvalidDescriptor,
        }
    }
    return .{
        .allocator = allocator,
        .rows = entry.row_count,
        .columns = columns,
        .values = values,
    };
}

fn writeExpandedXor(descriptor: []const u32, destination: []u32) !void {
    const relation = descriptor[1];
    const low_bits: u5 = std.math.cast(u5, descriptor[2]) orelse
        return Error.InvalidDescriptor;
    const partition_bits: u5 = std.math.cast(u5, descriptor[3]) orelse
        return Error.InvalidDescriptor;
    if (low_bits == 0 or partition_bits == 0 or
        relation >= @as(u32, 1) << @intCast(partition_bits * 2) or
        destination.len != @as(usize, 1) << @intCast(low_bits * 2))
        return Error.InvalidDescriptor;
    const low_mask = (@as(u32, 1) << low_bits) - 1;
    const partition_mask = (@as(u32, 1) << partition_bits) - 1;
    for (destination, 0..) |*value, row| {
        const lhs = ((relation >> partition_bits) << low_bits) |
            (@as(u32, @intCast(row)) >> low_bits);
        const rhs = ((relation & partition_mask) << low_bits) |
            (@as(u32, @intCast(row)) & low_mask);
        value.* = switch (descriptor[0]) {
            3 => lhs,
            4 => rhs,
            5 => lhs ^ rhs,
            else => unreachable,
        };
    }
}

fn expandedXorValue(descriptor: []const u32, row: usize) !u32 {
    const relation = descriptor[1];
    const low_bits: u5 = std.math.cast(u5, descriptor[2]) orelse
        return Error.InvalidDescriptor;
    const partition_bits: u5 = std.math.cast(u5, descriptor[3]) orelse
        return Error.InvalidDescriptor;
    if (low_bits == 0 or partition_bits == 0 or
        relation >= @as(u32, 1) << @intCast(partition_bits * 2) or
        row >= @as(usize, 1) << @intCast(low_bits * 2))
        return Error.InvalidDescriptor;
    const low_mask = (@as(u32, 1) << low_bits) - 1;
    const partition_mask = (@as(u32, 1) << partition_bits) - 1;
    const lhs = ((relation >> partition_bits) << low_bits) |
        (@as(u32, @intCast(row)) >> low_bits);
    const rhs = ((relation & partition_mask) << low_bits) |
        (@as(u32, @intCast(row)) & low_mask);
    return switch (descriptor[0]) {
        3 => lhs,
        4 => rhs,
        5 => lhs ^ rhs,
        else => Error.InvalidDescriptor,
    };
}

fn pedersenIdentity(identity: []const u8) ?pedersen_table.Window {
    if (std.mem.startsWith(u8, identity, "pedersen_points_small_")) return .small;
    if (std.mem.startsWith(u8, identity, "pedersen_points_")) return .standard;
    return null;
}

fn pedersenColumn(identity: []const u8) ?usize {
    const prefix = if (std.mem.startsWith(u8, identity, "pedersen_points_small_"))
        "pedersen_points_small_"
    else if (std.mem.startsWith(u8, identity, "pedersen_points_"))
        "pedersen_points_"
    else
        return null;
    return std.fmt.parseUnsigned(usize, identity[prefix.len..], 10) catch null;
}
