const std = @import("std");

pub const UPPER_BOUND_QUERY_BYTES: usize = 4;

/// Draws `n_queries` values in `[0, 2^log_domain_size)` from the channel.
///
/// The channel is expected to expose `drawU32s() -> [N]u32`.
pub fn drawQueries(
    channel: anytype,
    allocator: std.mem.Allocator,
    log_domain_size: u32,
    n_queries: usize,
) ![]usize {
    const out = try allocator.alloc(usize, n_queries);
    errdefer allocator.free(out);

    const query_mask: u32 = (@as(u32, 1) << @intCast(log_domain_size)) - 1;
    var produced: usize = 0;
    while (produced < n_queries) {
        const words = channel.drawU32s();
        for (words) |word| {
            out[produced] = @as(usize, word & query_mask);
            produced += 1;
            if (produced == n_queries) break;
        }
    }
    return out;
}

/// An ordered set of query positions.
pub const Queries = struct {
    positions: []usize,
    log_domain_size: u32,

    pub fn init(
        allocator: std.mem.Allocator,
        raw_positions: []const usize,
        log_domain_size: u32,
    ) !Queries {
        var tmp = try allocator.alloc(usize, raw_positions.len);
        defer allocator.free(tmp);
        @memcpy(tmp, raw_positions);
        std.sort.heap(usize, tmp, {}, lessThanUsize);

        // In-place dedup on sorted positions.
        var unique_len: usize = 0;
        for (tmp) |p| {
            if (unique_len == 0 or tmp[unique_len - 1] != p) {
                tmp[unique_len] = p;
                unique_len += 1;
            }
        }

        const positions = try allocator.alloc(usize, unique_len);
        @memcpy(positions, tmp[0..unique_len]);
        return .{
            .positions = positions,
            .log_domain_size = log_domain_size,
        };
    }

    pub fn deinit(self: *Queries, allocator: std.mem.Allocator) void {
        allocator.free(self.positions);
        self.* = undefined;
    }

    pub fn fold(self: Queries, allocator: std.mem.Allocator, n_folds: u32) !Queries {
        std.debug.assert(n_folds <= self.log_domain_size);
        const folded_log_size = self.log_domain_size - n_folds;

        if (self.positions.len == 0) {
            return .{
                .positions = try allocator.alloc(usize, 0),
                .log_domain_size = folded_log_size,
            };
        }

        var tmp = try allocator.alloc(usize, self.positions.len);
        defer allocator.free(tmp);

        var unique_len: usize = 0;
        for (self.positions) |q| {
            const folded = q >> @intCast(n_folds);
            if (unique_len == 0 or tmp[unique_len - 1] != folded) {
                tmp[unique_len] = folded;
                unique_len += 1;
            }
        }

        const positions = try allocator.alloc(usize, unique_len);
        @memcpy(positions, tmp[0..unique_len]);
        return .{
            .positions = positions,
            .log_domain_size = folded_log_size,
        };
    }
};

fn lessThanUsize(_: void, lhs: usize, rhs: usize) bool {
    return lhs < rhs;
}

test "queries: draw and normalize" {
    const blake2s = @import("channel/blake2s.zig");
    var channel = blake2s.Blake2sChannel{};

    const raw = try drawQueries(&channel, std.testing.allocator, 31, 100);
    defer std.testing.allocator.free(raw);
    var queries = try Queries.init(std.testing.allocator, raw, 31);
    defer queries.deinit(std.testing.allocator);

    try std.testing.expect(queries.positions.len == 100);
    try std.testing.expect(std.sort.isSorted(usize, queries.positions, {}, lessThanUsize));
    try std.testing.expect(queries.positions[queries.positions.len - 1] < (@as(usize, 1) << 31));
}

test "queries: fold dedups sorted positions" {
    const raw = [_]usize{ 15, 7, 7, 3, 2, 8, 1, 0 };
    var queries = try Queries.init(std.testing.allocator, raw[0..], 4);
    defer queries.deinit(std.testing.allocator);
    try std.testing.expectEqualSlices(usize, &[_]usize{ 0, 1, 2, 3, 7, 8, 15 }, queries.positions);

    var folded1 = try queries.fold(std.testing.allocator, 1);
    defer folded1.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u32, 3), folded1.log_domain_size);
    try std.testing.expectEqualSlices(usize, &[_]usize{ 0, 1, 3, 4, 7 }, folded1.positions);

    var folded2 = try queries.fold(std.testing.allocator, 2);
    defer folded2.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u32, 2), folded2.log_domain_size);
    try std.testing.expectEqualSlices(usize, &[_]usize{ 0, 1, 2, 3 }, folded2.positions);
}
