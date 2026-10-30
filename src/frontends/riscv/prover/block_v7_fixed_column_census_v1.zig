//! Diagnostic only: count exact repeated fixed columns in resident source PCS
//! trees. Hashes accelerate comparisons; exact field bytes decide equality.
//! This is neither a fixed-column admission rule nor a deduplicating prover.
const std = @import("std");
const Column = @import("stwo_prover_engine").pcs.ColumnEvaluation;
pub const Source = struct { columns: []const Column };
pub const Counts = struct {
    columns: u64 = 0,
    unique_columns: u64 = 0,
    repeated_within_source: u64 = 0,
    repeated_across_sources: u64 = 0,
    lde_cells: u64 = 0,
    unique_lde_cells: u64 = 0,
};
const Seen = struct { digest: [32]u8, column: Column, source: usize };
pub const Owned = struct {
    allocator: std.mem.Allocator,
    total: Counts,
    sources: []Counts,
    /// Source-concatenated original column index -> exact first representative.
    /// This map is diagnostic output and is never accepted as key authority.
    representatives: []usize,
    pub fn deinit(self: *Owned) void {
        self.allocator.free(self.representatives);
        self.allocator.free(self.sources);
        self.* = undefined;
    }
};
pub fn measure(a: std.mem.Allocator, sources: []const Source, max_columns: usize) !Owned {
    if (sources.len == 0 or sources.len > 256 or max_columns == 0 or max_columns > 65536) return error.InvalidFixedColumnCensusLimit;
    var count: usize = 0;
    for (sources) |source| {
        count = try std.math.add(usize, count, source.columns.len);
        if (count > max_columns) return error.FixedColumnCensusLimit;
    }
    var out = Owned{ .allocator = a, .total = .{}, .sources = try a.alloc(Counts, sources.len), .representatives = &.{} };
    errdefer out.deinit();
    @memset(out.sources, .{});
    out.representatives = try a.alloc(usize, count);
    const seen = try a.alloc(Seen, count);
    defer a.free(seen);
    var at: usize = 0;
    for (sources, out.sources, 0..) |source, *stats, source_index| {
        for (source.columns) |column| {
            try column.validate();
            const bytes = std.mem.sliceAsBytes(column.values);
            var digest: [32]u8 = undefined;
            std.crypto.hash.Blake3.hash(bytes, &digest, .{});
            var representative = at;
            for (seen[0..at], 0..) |prior, i| {
                if (prior.column.log_size == column.log_size and std.mem.eql(u8, &prior.digest, &digest) and std.mem.eql(u8, std.mem.sliceAsBytes(prior.column.values), bytes)) {
                    representative = i;
                    break;
                }
            }
            stats.columns += 1;
            stats.lde_cells = try std.math.add(u64, stats.lde_cells, column.values.len);
            if (representative == at) {
                stats.unique_columns += 1;
                stats.unique_lde_cells = try std.math.add(u64, stats.unique_lde_cells, column.values.len);
            } else if (seen[representative].source == source_index) {
                stats.repeated_within_source += 1;
            } else stats.repeated_across_sources += 1;
            seen[at] = .{ .digest = digest, .column = column, .source = source_index };
            out.representatives[at] = representative;
            at += 1;
        }
        inline for (@typeInfo(Counts).@"struct".fields) |field| @field(out.total, field.name) = try std.math.add(u64, @field(out.total, field.name), @field(stats, field.name));
    }
    return out;
}

test "union fixed census distinguishes exact columns and cross-source duplicates" {
    const M = @import("stwo_core").fields.m31.M31;
    const zero = [_]M{M.zero()} ** 4;
    const one = [_]M{M.one()} ** 4;
    const longer = [_]M{M.zero()} ** 8;
    const source0 = [_]Column{ .{ .log_size = 2, .values = &zero }, .{ .log_size = 2, .values = &zero }, .{ .log_size = 2, .values = &one } };
    const source1 = [_]Column{ .{ .log_size = 2, .values = &one }, .{ .log_size = 3, .values = &longer } };
    var result = try measure(std.testing.allocator, &.{ .{ .columns = &source0 }, .{ .columns = &source1 } }, 5);
    defer result.deinit();
    try std.testing.expectEqualDeep(Counts{ .columns = 5, .unique_columns = 3, .repeated_within_source = 1, .repeated_across_sources = 1, .lde_cells = 24, .unique_lde_cells = 16 }, result.total);
    try std.testing.expectEqualSlices(usize, &.{ 0, 0, 2, 2, 4 }, result.representatives);
    try std.testing.expectError(error.FixedColumnCensusLimit, measure(std.testing.allocator, &.{ .{ .columns = &source0 }, .{ .columns = &source1 } }, 4));
    try std.testing.expectError(error.InvalidColumnLength, measure(std.testing.allocator, &.{.{ .columns = &.{.{ .log_size = 3, .values = &zero }} }}, 1));
}
