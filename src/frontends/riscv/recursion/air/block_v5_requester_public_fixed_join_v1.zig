//! Exact PUBLIC21 child-then-tuple fixed join and original final G partition.
//! There are no MAIN placeholders. Namespace admission precedes this copy.
const std = @import("std");
const Storage = @import("blake3_parent_row_storage.zig");
const Partition = @import("blake3_g_partition.zig");
const Direct = @import("blake3_direct_cohort_columns_v1.zig");
pub fn empty() Storage.FixedTuple(false) {
    var result: Storage.FixedTuple(false) = undefined;
    inline for (0..Storage.Airs.len) |i| result[i] = &.{};
    return result;
}
pub fn deinit(a: std.mem.Allocator, fixed: *Storage.FixedTuple(false)) void {
    inline for (0..Storage.Airs.len) |i| a.free(fixed.*[i]);
    fixed.* = empty();
}
pub fn join(a: std.mem.Allocator, child: Storage.FixedTuple(false), tuple: Storage.FixedTuple(false), max_rows: usize) !Storage.FixedTuple(false) {
    @setEvalBranchQuota(10_000);
    if (max_rows == 0 or max_rows > 1 << 24) return error.RequesterPublicFixedResourceLimit;
    // Validate all counts before allocating any output.
    inline for (0..Storage.Airs.len) |i| {
        const count = try std.math.add(usize, child[i].len, tuple[i].len);
        if (count > max_rows) return error.RequesterPublicFixedResourceLimit;
        _ = try Direct.rowLog(count);
    }
    var result = empty();
    errdefer deinit(a, &result);
    inline for (Storage.Airs, 0..) |Air, i| {
        result[i] = try a.alloc(Storage.FixedRow(Air), child[i].len + tuple[i].len);
        @memcpy(result[i][0..child[i].len], child[i]);
        @memcpy(result[i][child[i].len..], tuple[i]);
    }
    try partition(a, &result);
    return result;
}
/// Same conditional as original partitionHashRows at final key derivation.
/// Already partitioned children keep their original physical joined geometry.
pub fn partition(a: std.mem.Allocator, fixed: *Storage.FixedTuple(false)) !void {
    if (fixed.*[0].len <= 1 << 20) return;
    inline for (Partition.SHARDS[1..]) |i| if (fixed.*[i].len != 0) return;
    const geometry = try Partition.geometry(fixed.*[0].len);
    var next: [Partition.SHARDS.len][]Storage.FixedRow(Storage.Airs[0]) = @splat(&.{});
    errdefer for (next) |rows| a.free(rows);
    var first: usize = 0;
    for (geometry.counts, 0..) |count, i| {
        next[i] = try a.dupe(Storage.FixedRow(Storage.Airs[0]), fixed.*[0][first..][0..count]);
        first += count;
    }
    inline for (Partition.SHARDS, 0..) |slot, i| {
        a.free(fixed.*[slot]);
        fixed.*[slot] = next[i];
    }
}
