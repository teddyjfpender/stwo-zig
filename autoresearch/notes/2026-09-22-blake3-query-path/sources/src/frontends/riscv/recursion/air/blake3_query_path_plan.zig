//! Canonical mapping from authenticated public raw query coordinates to paths.
//! The enclosing proof must constrain raw values and use this same plan for paths.
const std = @import("std");
const core = @import("stwo_core");
pub const Plan = struct {
    allocator: std.mem.Allocator,
    queries: core.queries.Queries,
    raw_to_unique: []usize,
    pub fn deinit(self: *Plan) void {
        self.queries.deinit(self.allocator);
        self.allocator.free(self.raw_to_unique);
        self.* = undefined;
    }
    pub fn admit(self: *const Plan, positions: []const usize) !void {
        if (!std.mem.eql(usize, self.queries.positions, positions)) return error.InvalidBlake3QueryPaths;
    }
};
pub fn build(a: std.mem.Allocator, raw: []const u32, log_domain_size: u32, folds: u32) !Plan {
    if (log_domain_size > 31 or folds > log_domain_size) return error.InvalidBlake3QueryPaths;
    const values = try a.alloc(usize, raw.len);
    defer a.free(values);
    for (values, raw) |*value, word| {
        if (@as(u64, word) >= @as(u64, 1) << @as(u6, @intCast(log_domain_size))) return error.InvalidBlake3QueryPaths;
        value.* = word;
    }
    var normalized = try core.queries.Queries.init(a, values, log_domain_size);
    defer normalized.deinit(a);
    var folded = try normalized.fold(a, folds);
    errdefer folded.deinit(a);
    const mapping = try a.alloc(usize, raw.len);
    errdefer a.free(mapping);
    for (mapping, raw) |*slot, word| {
        const wanted = @as(usize, word) >> @as(u6, @intCast(folds));
        var lo: usize = 0;
        var hi = folded.positions.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            if (folded.positions[mid] < wanted) lo = mid + 1 else hi = mid;
        }
        if (lo == folded.positions.len or folded.positions[lo] != wanted) return error.InvalidBlake3QueryPaths;
        slot.* = lo;
    }
    return .{ .allocator = a, .queries = folded, .raw_to_unique = mapping };
}
test "BLAKE3 query path admission preserves duplicates folding and exact path order" {
    const a = std.testing.allocator;
    const raw = [_]u32{ 7, 0, 3, 7, 2, 1, 6, 0 };
    for (0..4) |fold| {
        var plan = try build(a, &raw, 3, @intCast(fold));
        defer plan.deinit();
        for (raw, plan.raw_to_unique) |word, slot| try std.testing.expectEqual(@as(usize, word) >> @as(u6, @intCast(fold)), plan.queries.positions[slot]);
        try plan.admit(plan.queries.positions);
        try std.testing.expectError(error.InvalidBlake3QueryPaths, plan.admit(plan.queries.positions[0 .. plan.queries.positions.len - 1]));
        const changed = try a.dupe(usize, plan.queries.positions);
        defer a.free(changed);
        changed[0] += 1;
        try std.testing.expectError(error.InvalidBlake3QueryPaths, plan.admit(changed));
        if (changed.len > 1) {
            @memcpy(changed, plan.queries.positions);
            std.mem.swap(usize, &changed[0], &changed[1]);
            try std.testing.expectError(error.InvalidBlake3QueryPaths, plan.admit(changed));
        }
    }
    var edge = try build(a, &.{0x7fffffff}, 31, 31);
    defer edge.deinit();
    try edge.admit(&.{0});
    var empty = try build(a, &.{}, 0, 0);
    defer empty.deinit();
    try empty.admit(&.{});
    try std.testing.expectError(error.InvalidBlake3QueryPaths, build(a, &.{8}, 3, 0));
    try std.testing.expectError(error.InvalidBlake3QueryPaths, build(a, &.{0}, 3, 4));
    try std.testing.checkAllAllocationFailures(a, allocationCase, .{});
}
fn allocationCase(a: std.mem.Allocator) !void {
    var plan = try build(a, &.{ 7, 0, 3, 7 }, 3, 1);
    defer plan.deinit();
}
