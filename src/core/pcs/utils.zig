const std = @import("std");

/// Container that holds one value per commitment tree.
pub fn TreeVec(comptime T: type) type {
    return struct {
        items: []T,

        const Self = @This();

        pub inline fn initOwned(items: []T) Self {
            return .{ .items = items };
        }

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            allocator.free(self.items);
            self.* = undefined;
        }

        /// Frees nested slices (when `T` is a slice type) and the outer storage.
        pub fn deinitDeep(self: *Self, allocator: std.mem.Allocator) void {
            deepFree(T, allocator, self.items);
            self.* = undefined;
        }

        pub inline fn len(self: Self) usize {
            return self.items.len;
        }

        pub inline fn get(self: Self, idx: usize) T {
            return self.items[idx];
        }

        pub fn map(self: Self, comptime U: type, allocator: std.mem.Allocator, f: fn (T) U) !TreeVec(U) {
            const out = try allocator.alloc(U, self.items.len);
            errdefer allocator.free(out);
            for (self.items, 0..) |v, i| out[i] = f(v);
            return TreeVec(U).initOwned(out);
        }
    };
}

fn deepFree(comptime T: type, allocator: std.mem.Allocator, slice: []T) void {
    const ti = @typeInfo(T);
    if (ti == .pointer and ti.pointer.size == .slice) {
        const Child = ti.pointer.child;
        for (slice) |inner| {
            deepFree(Child, allocator, inner);
        }
    }
    allocator.free(slice);
}

fn cloneValue(comptime T: type, allocator: std.mem.Allocator, value: T) !T {
    const ti = @typeInfo(T);
    if (ti == .pointer and ti.pointer.size == .slice) {
        const Child = ti.pointer.child;
        const out = try allocator.alloc(Child, value.len);
        var i: usize = 0;
        while (i < value.len) : (i += 1) {
            out[i] = try cloneValue(Child, allocator, value[i]);
        }
        return out;
    }
    return value;
}

fn freeValue(comptime T: type, allocator: std.mem.Allocator, value: T) void {
    const ti = @typeInfo(T);
    if (ti == .pointer and ti.pointer.size == .slice) {
        deepFree(ti.pointer.child, allocator, value);
    }
}

/// Concatenates tree column vectors by tree index.
///
/// Input type: `[]const TreeVec([]T)`.
pub fn concatCols(comptime T: type, allocator: std.mem.Allocator, trees: []const TreeVec([]T)) !TreeVec([]T) {
    var n_trees: usize = 0;
    for (trees) |tv| n_trees = @max(n_trees, tv.items.len);

    var builders = try allocator.alloc(std.ArrayList(T), n_trees);
    defer allocator.free(builders);
    for (builders) |*b| b.* = std.ArrayList(T).init(allocator);
    defer {
        for (builders) |*b| {
            for (b.items) |item| freeValue(T, allocator, item);
            b.deinit();
        }
    }

    for (trees) |tree| {
        for (tree.items, 0..) |cols, tree_index| {
            for (cols) |col| {
                try builders[tree_index].append(try cloneValue(T, allocator, col));
            }
        }
    }

    const out = try allocator.alloc([]T, n_trees);
    errdefer allocator.free(out);
    for (builders, 0..) |*b, i| {
        out[i] = try b.toOwnedSlice();
    }
    return TreeVec([]T).initOwned(out);
}

/// Appends columns of `other` into `self` by tree index.
pub fn appendCols(comptime T: type, allocator: std.mem.Allocator, self: *TreeVec([]T), other: TreeVec([]T)) !void {
    const n_trees = @max(self.items.len, other.items.len);

    var builders = try allocator.alloc(std.ArrayList(T), n_trees);
    defer allocator.free(builders);
    for (builders) |*b| b.* = std.ArrayList(T).init(allocator);
    defer {
        for (builders) |*b| {
            for (b.items) |item| freeValue(T, allocator, item);
            b.deinit();
        }
    }

    var i: usize = 0;
    while (i < self.items.len) : (i += 1) {
        for (self.items[i]) |item| {
            try builders[i].append(try cloneValue(T, allocator, item));
        }
    }
    i = 0;
    while (i < other.items.len) : (i += 1) {
        for (other.items[i]) |item| {
            try builders[i].append(try cloneValue(T, allocator, item));
        }
    }

    self.deinitDeep(allocator);
    const out = try allocator.alloc([]T, n_trees);
    for (builders, 0..) |*b, idx| {
        out[idx] = try b.toOwnedSlice();
    }
    self.* = TreeVec([]T).initOwned(out);
}

/// Flattens a `TreeVec([]T)` into one slice.
pub fn flatten(comptime T: type, allocator: std.mem.Allocator, tv: TreeVec([]T)) ![]T {
    var total: usize = 0;
    for (tv.items) |cols| total += cols.len;
    const out = try allocator.alloc(T, total);
    var at: usize = 0;
    for (tv.items) |cols| {
        @memcpy(out[at .. at + cols.len], cols);
        at += cols.len;
    }
    return out;
}

/// Converts max-query positions to preprocessed-query positions.
pub fn preparePreprocessedQueryPositions(
    allocator: std.mem.Allocator,
    query_positions: []const usize,
    max_log_size: u32,
    pp_max_log_size: u32,
) ![]usize {
    if (pp_max_log_size == 0) {
        return allocator.alloc(usize, 0);
    }

    const out = try allocator.alloc(usize, query_positions.len);
    if (max_log_size < pp_max_log_size) {
        for (query_positions, 0..) |pos, i| {
            out[i] = (pos >> 1 << @intCast(pp_max_log_size - max_log_size + 1)) + (pos & 1);
        }
        return out;
    }

    for (query_positions, 0..) |pos, i| {
        out[i] = (pos >> @intCast(max_log_size - pp_max_log_size + 1) << 1) + (pos & 1);
    }
    return out;
}

test "pcs utils: concat cols" {
    const alloc = std.testing.allocator;

    const a0 = try alloc.dupe(u32, &[_]u32{ 1, 2 });
    const a1 = try alloc.dupe(u32, &[_]u32{3});
    const b0 = try alloc.dupe(u32, &[_]u32{4});
    const b1 = try alloc.dupe(u32, &[_]u32{ 5, 6 });
    const b2 = try alloc.dupe(u32, &[_]u32{7});

    var t0 = TreeVec([]u32).initOwned(try alloc.dupe([]u32, &[_][]u32{ a0, a1 }));
    defer t0.deinitDeep(alloc);
    var t1 = TreeVec([]u32).initOwned(try alloc.dupe([]u32, &[_][]u32{ b0, b1, b2 }));
    defer t1.deinitDeep(alloc);

    var out = try concatCols(u32, alloc, &[_]TreeVec([]u32){ t0, t1 });
    defer out.deinitDeep(alloc);

    try std.testing.expectEqual(@as(usize, 3), out.items.len);
    try std.testing.expectEqualSlices(u32, &[_]u32{ 1, 2, 4 }, out.items[0]);
    try std.testing.expectEqualSlices(u32, &[_]u32{ 3, 5, 6 }, out.items[1]);
    try std.testing.expectEqualSlices(u32, &[_]u32{7}, out.items[2]);
}

test "pcs utils: prepare preprocessed query positions" {
    const alloc = std.testing.allocator;
    const q = [_]usize{ 3, 7, 11, 15 };

    const a = try preparePreprocessedQueryPositions(alloc, q[0..], 8, 6);
    defer alloc.free(a);
    try std.testing.expectEqualSlices(usize, &[_]usize{ 1, 1, 1, 1 }, a);

    const b = try preparePreprocessedQueryPositions(alloc, q[0..], 6, 8);
    defer alloc.free(b);
    try std.testing.expectEqualSlices(usize, &[_]usize{ 12, 28, 44, 60 }, b);
}
