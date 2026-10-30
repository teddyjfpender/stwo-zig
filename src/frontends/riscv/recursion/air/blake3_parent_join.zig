//! Isolated child-verifier witnesses to one final column layout. No expanded
//! logical main rows are materialized. Span/key admission belongs to the caller.
const std = @import("std");
const core = @import("stwo_core");
const storage = @import("blake3_parent_row_storage.zig");
const Column = @import("stwo_prover_engine").pcs.ColumnEvaluation;
const M = core.fields.m31.M31;
const committed = @import("framework_interaction.zig").committedRow;
pub const Range = struct {
    first: u32,
    end: u32,
    fn validate(self: Range) !void {
        if (self.first >= self.end or self.end > core.fields.m31.Modulus) return error.InvalidParentJoinNamespace;
    }
};
pub fn join(a: std.mem.Allocator, left: *const storage.Prepared, right: *const storage.Prepared, ranges: [2]Range) !storage.Prepared {
    return joinImpl(false, a, left, right, ranges, null);
}
/// Destructive column transfer: the caller must deinit both children on success
/// or failure and must not reuse their rows. Admission precedes any mutation.
/// A bounded column batch is allocated/copied before its source buffers are freed.
pub fn joinDraining(a: std.mem.Allocator, left: *storage.Prepared, right: *storage.Prepared, ranges: [2]Range) !storage.Prepared {
    if (left == right) return error.AliasedAggregateChildren;
    return joinImpl(true, a, left, right, ranges, null);
}
/// Concatenate an already admitted/rebased roster directly into its final
/// column geometry. Unlike repeated binary joins, every output cell is written
/// once. Inputs must be destroyed on success/error and cannot be reused.
pub fn joinManyDraining(a: std.mem.Allocator, sources: []const *storage.Prepared, ranges: []const Range) !storage.Prepared {
    if (sources.len < 2 or sources.len > 64 or sources.len != ranges.len) return error.InvalidParentJoinColumns;
    var input_count: usize = 0;
    var counts: [storage.Airs.len]usize = @splat(0);
    // Complete admission precedes mutation, including every source namespace.
    for (sources, ranges, 0..) |source, range, index| {
        try range.validate();
        try validateColumns(source);
        for (sources[0..index], ranges[0..index]) |previous, prior| {
            if (previous == source) return error.AliasedAggregateChildren;
            if (range.first < prior.end and prior.first < range.end) return error.OverlappingParentNamespaces;
        }
        try @import("blake3_parent_namespace.zig").rejectRange(source, 0, range.first);
        try @import("blake3_parent_namespace.zig").rejectRange(source, range.end, core.fields.m31.Modulus);
        input_count = try std.math.add(usize, input_count, source.input_count);
        inline for (0..storage.Airs.len) |i| {
            counts[i] = try std.math.add(usize, counts[i], source.fixed[i].len);
            if (counts[i] > 1 << 30) return error.InvalidParentJoinColumns;
        }
    }
    var result = storage.Prepared{ .allocator = a, .main = @splat(&.{}), .fixed = undefined, .input_count = input_count };
    inline for (0..storage.Airs.len) |i| result.fixed[i] = &.{};
    errdefer result.deinit();
    inline for (storage.Airs, 0..) |Air, i| {
        const count = counts[i];
        const log: u32 = if (count < 2) 1 else std.math.log2_int_ceil(usize, count);
        var ends: [64]usize = undefined;
        var offset: usize = 0;
        result.fixed[i] = try a.alloc(storage.FixedRow(Air), count);
        for (sources, ends[0..sources.len]) |source, *end| {
            const next = offset + source.fixed[i].len;
            @memcpy(result.fixed[i][offset..next], source.fixed[i]);
            source.allocator.free(source.fixed[i]);
            source.fixed[i] = &.{};
            end.* = next;
            offset = next;
        }
        result.main[i] = try a.alloc(Column, Air.PHYSICAL_MAIN_COLUMN_COUNT);
        for (result.main[i]) |*column| column.* = .{ .log_size = log, .values = &.{} };
        var first: usize = 0;
        while (first < result.main[i].len) {
            const end = @min(first + COLUMN_BATCH, result.main[i].len);
            const output = result.main[i][first..end];
            for (output) |*column| column.values = try a.alloc(M, @as(usize, 1) << @intCast(log));
            copyManyColumns(i, sources, ends[0..sources.len], first, output);
            for (sources) |source| for (source.main[i][first..end]) |*column| {
                source.allocator.free(column.values);
                column.values = &.{};
            };
            first = end;
        }
    }
    return result;
}
pub fn copyManyColumns(comptime air: usize, sources: []const *storage.Prepared, ends: []const usize, first_column: usize, output: []Column) void {
    if (output.len == 0) return;
    const log = output[0].log_size;
    const Mapping = struct { source: usize, row: usize };
    var mapping: [1024]Mapping = undefined;
    var first: usize = 0;
    while (first < output[0].values.len) {
        const size = @min(mapping.len, output[0].values.len - first);
        for (mapping[0..size], 0..) |*mapped, at| {
            const logical = core.utils.circleDomainIndexToCosetIndex(core.utils.bitReverseIndex(first + at, log), log);
            // First cumulative end strictly above logical; empty children
            // deliberately occupy no rows, including the all-empty case.
            var low: usize = 0;
            var high = sources.len;
            while (low < high) {
                const middle = low + (high - low) / 2;
                if (logical < ends[middle]) high = middle else low = middle + 1;
            }
            mapped.* = if (low == sources.len) .{ .source = low, .row = 0 } else .{
                .source = low,
                .row = committed(logical - (if (low == 0) @as(usize, 0) else ends[low - 1]), sources[low].main[air][first_column].log_size),
            };
        }
        for (output, 0..) |column, c| for (@constCast(column.values)[first..][0..size], mapping[0..size]) |*value, mapped| {
            value.* = if (mapped.source == sources.len) M.zero() else sources[mapped.source].main[air][first_column + c].values[mapped.row];
        };
        first += size;
    }
}
/// Both partitions must be destroyed on every path. The shared owner keeps its
/// backing on failure and transfers it only after all fallible assembly succeeds.
pub fn joinShared(left: *storage.Partition, right: *storage.Partition, ranges: [2]Range, owner: *@import("../blake3_native_hash_columns.zig").Owner) !storage.Prepared {
    if (left == right or !owner.owns_backing) return error.InvalidParentJoinColumns;
    _ = try owner.view();
    inline for (0..2) |i| {
        const count = try std.math.add(usize, left.fixed[i].len, right.fixed[i].len);
        const expected = if (i == 0) owner.layout.total.g else owner.layout.total.xor;
        if (count != expected or owner.first[i] != 0) return error.InvalidParentJoinColumns;
        const log: u32 = if (count < 2) 1 else std.math.log2_int_ceil(usize, count);
        if (left.first[i] != 0 or right.first[i] != left.fixed[i].len or owner.main[i].len != storage.Airs[i].PHYSICAL_MAIN_COLUMN_COUNT) return error.InvalidParentJoinColumns;
        for ([_]*storage.Partition{ left, right }) |part| {
            if (part.fixed[i].len != part.capacity[i]) return error.InvalidParentJoinColumns;
            if (part.main[i].ptr != owner.main[i].ptr or part.main[i].len != owner.main[i].len) return error.InvalidParentJoinColumns;
        }
        for (owner.main[i]) |column| if (column.log_size != log or column.values.len != @as(usize, 1) << @intCast(log)) return error.InvalidParentJoinColumns;
    }
    return joinImpl(true, owner.allocator, left, right, ranges, owner);
}
const COLUMN_BATCH = 16;
fn joinImpl(comptime drain: bool, a: std.mem.Allocator, left: anytype, right: @TypeOf(left), ranges: [2]Range, shared: ?*@import("../blake3_native_hash_columns.zig").Owner) !storage.Prepared {
    for (ranges) |range| try range.validate();
    if (ranges[0].first < ranges[1].end and ranges[1].first < ranges[0].end) return error.OverlappingParentNamespaces;
    for ([_]@TypeOf(left){ left, right }, ranges) |source, range| {
        try validateColumns(source);
        try @import("blake3_parent_namespace.zig").rejectRange(source, 0, range.first);
        try @import("blake3_parent_namespace.zig").rejectRange(source, range.end, core.fields.m31.Modulus);
    }
    var result = storage.Prepared{ .allocator = a, .main = @splat(&.{}), .fixed = undefined, .input_count = try std.math.add(usize, left.input_count, right.input_count) };
    inline for (0..storage.Airs.len) |i| result.fixed[i] = &.{};
    errdefer result.deinit();
    inline for (storage.Airs, 0..) |Air, i| {
        const left_count = left.fixed[i].len;
        const count = try std.math.add(usize, left_count, right.fixed[i].len);
        if (count > (1 << 30)) return error.InvalidParentJoinColumns;
        const log: u32 = if (count < 2) 1 else std.math.log2_int_ceil(usize, count);
        result.fixed[i] = try a.alloc(storage.FixedRow(Air), count);
        @memcpy(result.fixed[i][0..left_count], left.fixed[i]);
        @memcpy(result.fixed[i][left_count..], right.fixed[i]);
        if (drain) {
            left.allocator.free(left.fixed[i]);
            right.allocator.free(right.fixed[i]);
            left.fixed[i] = &.{};
            right.fixed[i] = &.{};
        }
        if (i >= 2 or shared == null) {
            result.main[i] = try a.alloc(Column, Air.PHYSICAL_MAIN_COLUMN_COUNT);
            for (result.main[i]) |*column| column.* = .{ .log_size = log, .values = &.{} };
            var first: usize = 0;
            while (first < result.main[i].len) {
                const end = if (drain) @min(first + COLUMN_BATCH, result.main[i].len) else result.main[i].len;
                for (result.main[i][first..end]) |*column| column.values = try a.alloc(M, @as(usize, 1) << @intCast(log));
                copyColumns(left.main[i][first..end], right.main[i][first..end], left_count, count, result.main[i][first..end]);
                if (drain) {
                    for (left.main[i][first..end]) |*column| {
                        left.allocator.free(column.values);
                        column.values = &.{};
                    }
                    for (right.main[i][first..end]) |*column| {
                        right.allocator.free(column.values);
                        column.values = &.{};
                    }
                }
                first = end;
            }
        }
    }
    if (shared) |owner| {
        result.main[0] = owner.main[0];
        result.main[1] = owner.main[1];
        owner.main = @splat(&.{});
    }
    return result;
}
pub fn validateColumns(parent: anytype) !void {
    inline for (storage.Airs, 0..) |Air, i| {
        const count = parent.fixed[i].len;
        if (count > (1 << 30) or parent.main[i].len != Air.PHYSICAL_MAIN_COLUMN_COUNT) return error.InvalidParentJoinColumns;
        const log: u32 = if (count < 2) 1 else std.math.log2_int_ceil(usize, count);
        for (parent.main[i]) |column| {
            const base = storage.rowBase(parent, i);
            const shared_hash = @hasField(@TypeOf(parent.*), "first") and i < 2;
            if ((!shared_hash and column.log_size != log) or column.log_size > 30 or column.values.len != @as(usize, 1) << @intCast(column.log_size) or base > column.values.len or count > column.values.len - base) return error.InvalidParentJoinColumns;
        }
    }
}

/// Bounded destination-order emission. Compute the permutation once per tile,
/// reuse it across columns, and write each output (including padding) only once.
fn copyColumns(left: []const Column, right: []const Column, left_count: usize, count: usize, output: []Column) void {
    if (output.len == 0) return;
    const log = output[0].log_size;
    const left_size = left[0].values.len;
    const padding = std.math.maxInt(usize);
    var indices: [1024]usize = undefined;
    var first: usize = 0;
    while (first < output[0].values.len) {
        const size = @min(indices.len, output[0].values.len - first);
        for (indices[0..size], 0..) |*index, offset| {
            const logical = core.utils.circleDomainIndexToCosetIndex(core.utils.bitReverseIndex(first + offset, log), log);
            index.* = if (logical < left_count)
                committed(logical, left[0].log_size)
            else if (logical < count)
                left_size + committed(logical - left_count, right[0].log_size)
            else
                padding;
        }
        for (output, left, right) |column, l, r| {
            for (@constCast(column.values)[first..][0..size], indices[0..size]) |*value, index| {
                value.* = if (index == padding) M.zero() else if (index < left_size) l.values[index] else r.values[index - left_size];
            }
        }
        first += size;
    }
}
