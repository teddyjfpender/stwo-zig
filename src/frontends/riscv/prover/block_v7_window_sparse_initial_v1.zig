//! Public address selection narrows the initialization table. Values always
//! come from the independently admitted complete incoming state. Unselected
//! addresses are forbidden, so omission cannot authorize a first touch.
const std = @import("std");
const Initial = @import("block_v7_initial_intervals_v1.zig");
pub const VERSION: u32 = 1;
pub const Selection = struct {
    a: std.mem.Allocator,
    addresses: []u32,
    intervals: []Initial.Interval,
    pub fn deinit(self: *Selection) void {
        self.a.free(self.addresses);
        self.a.free(self.intervals);
        self.* = undefined;
    }
};
pub fn derive(a: std.mem.Allocator, source: *const Initial.Owned, requested: []const u32, limits: Initial.Limits) !Selection {
    try Initial.validatePartition(source.intervals);
    if (requested.len == 0 or requested.len > limits.max_initialized_words) return error.V7InitializationResourceLimit;
    const addresses = try a.dupe(u32, requested);
    defer a.free(addresses);
    std.mem.sort(u32, addresses, {}, std.sort.asc(u32));
    var n: usize = 0;
    for (addresses) |address| {
        if (address & 3 != 0) return error.UnalignedV7InitializationAddress;
        if (n != 0 and addresses[n - 1] == address) continue;
        const original = try source.find(address);
        if (!original.allowed or original.private) return error.UntrustedV7SparseInitialization;
        addresses[n] = address;
        n += 1;
    }
    const selected = try a.dupe(u32, addresses[0..n]);
    errdefer a.free(selected);
    const intervals = try compile(a, source, selected, limits.max_intervals);
    return .{ .a = a, .addresses = selected, .intervals = intervals };
}
pub fn compile(a: std.mem.Allocator, source: *const Initial.Owned, addresses: []const u32, max_intervals: usize) ![]Initial.Interval {
    const maximum = try std.math.add(usize, try std.math.mul(usize, addresses.len, 2), 1);
    if (maximum > max_intervals) return error.V7InitializationResourceLimit;
    var rows: std.ArrayList(Initial.Interval) = .empty;
    errdefer rows.deinit(a);
    try rows.ensureTotalCapacity(a, maximum);
    var iterator = Iterator{ .source = source, .addresses = addresses };
    while (try iterator.next()) |row| rows.appendAssumeCapacity(row);
    try Initial.validatePartition(rows.items);
    return rows.toOwnedSlice(a);
}
/// Reconstruct expected rows from the admitted source and public selection;
/// raw cached sparse interval values are never the authority for this check.
pub fn require(source: *const Initial.Owned, addresses: []const u32, rows: []const Initial.Interval) !void {
    try Initial.validatePartition(source.intervals);
    var iterator = Iterator{ .source = source, .addresses = addresses };
    var index: usize = 0;
    while (try iterator.next()) |expected| {
        if (index >= rows.len or !std.meta.eql(rows[index], expected)) return error.UntrustedV7SparseInitialization;
        index += 1;
    }
    if (index != rows.len) return error.UntrustedV7SparseInitialization;
}
const Iterator = struct {
    source: *const Initial.Owned,
    addresses: []const u32,
    index: usize = 0,
    lower: u32 = 0,
    finished: bool = false,
    fn next(self: *Iterator) !?Initial.Interval {
        if (self.finished) return null;
        if (self.addresses.len == 0) return error.UntrustedV7SparseInitialization;
        if (self.index == self.addresses.len) {
            self.finished = true;
            if (self.lower == Initial.WORD_LIMIT) return null;
            return .{ .lower = self.lower, .upper = Initial.WORD_LIMIT, .allowed = false, .private = false, .value = 0 };
        }
        const address = self.addresses[self.index];
        if (address & 3 != 0 or (self.index != 0 and self.addresses[self.index - 1] >= address)) return error.UntrustedV7SparseInitialization;
        const word = address / 4;
        if (self.lower > word) return error.UntrustedV7SparseInitialization;
        if (self.lower < word) {
            const result: Initial.Interval = .{ .lower = self.lower, .upper = word, .allowed = false, .private = false, .value = 0 };
            self.lower = word;
            return result;
        }
        const original = try self.source.find(address);
        if (!original.allowed or original.private) return error.UntrustedV7SparseInitialization;
        self.index += 1;
        self.lower = word + 1;
        return .{ .lower = word, .upper = word + 1, .allowed = true, .private = false, .value = original.value };
    }
};
