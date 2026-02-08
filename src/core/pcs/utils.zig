const std = @import("std");

pub const TreeVecOpError = error{
    ShapeMismatch,
    DuplicateTreeIndex,
    InvalidSubTreeSpan,
};

pub fn Pair(comptime A: type, comptime B: type) type {
    return struct {
        first: A,
        second: B,
    };
}

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

        /// Zips two tree vectors by index, truncating to the shorter input.
        pub fn zip(
            self: Self,
            comptime U: type,
            allocator: std.mem.Allocator,
            other: TreeVec(U),
        ) !TreeVec(Pair(T, U)) {
            const out_len = @min(self.items.len, other.items.len);
            const out = try allocator.alloc(Pair(T, U), out_len);
            errdefer allocator.free(out);
            for (0..out_len) |i| {
                out[i] = .{
                    .first = self.items[i],
                    .second = other.items[i],
                };
            }
            return TreeVec(Pair(T, U)).initOwned(out);
        }

        /// Zips two tree vectors by index, requiring equal length.
        pub fn zipEq(
            self: Self,
            comptime U: type,
            allocator: std.mem.Allocator,
            other: TreeVec(U),
        ) (std.mem.Allocator.Error || TreeVecOpError)!TreeVec(Pair(T, U)) {
            if (self.items.len != other.items.len) return TreeVecOpError.ShapeMismatch;
            return self.zip(U, allocator, other);
        }
    };
}

fn deepFree(comptime T: type, allocator: std.mem.Allocator, slice: []const T) void {
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
    for (builders) |*b| b.* = .empty;
    defer {
        for (builders) |*b| {
            for (b.items) |item| freeValue(T, allocator, item);
            b.deinit(allocator);
        }
    }

    for (trees) |tree| {
        for (tree.items, 0..) |cols, tree_index| {
            for (cols) |col| {
                try builders[tree_index].append(allocator, try cloneValue(T, allocator, col));
            }
        }
    }

    const out = try allocator.alloc([]T, n_trees);
    errdefer allocator.free(out);
    for (builders, 0..) |*b, i| {
        out[i] = try b.toOwnedSlice(allocator);
    }
    return TreeVec([]T).initOwned(out);
}

/// Appends columns of `other` into `self` by tree index.
pub fn appendCols(comptime T: type, allocator: std.mem.Allocator, self: *TreeVec([]T), other: TreeVec([]T)) !void {
    const n_trees = @max(self.items.len, other.items.len);

    var builders = try allocator.alloc(std.ArrayList(T), n_trees);
    defer allocator.free(builders);
    for (builders) |*b| b.* = .empty;
    defer {
        for (builders) |*b| {
            for (b.items) |item| freeValue(T, allocator, item);
            b.deinit(allocator);
        }
    }

    var i: usize = 0;
    while (i < self.items.len) : (i += 1) {
        for (self.items[i]) |item| {
            try builders[i].append(allocator, try cloneValue(T, allocator, item));
        }
    }
    i = 0;
    while (i < other.items.len) : (i += 1) {
        for (other.items[i]) |item| {
            try builders[i].append(allocator, try cloneValue(T, allocator, item));
        }
    }

    self.deinitDeep(allocator);
    const out = try allocator.alloc([]T, n_trees);
    for (builders, 0..) |*b, idx| {
        out[idx] = try b.toOwnedSlice(allocator);
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

/// Zips two `TreeVec([]T)` values, requiring the same tree and per-tree column counts.
pub fn zipCols(
    comptime A: type,
    comptime B: type,
    allocator: std.mem.Allocator,
    lhs: TreeVec([]A),
    rhs: TreeVec([]B),
) (std.mem.Allocator.Error || TreeVecOpError)!TreeVec([]Pair(A, B)) {
    if (lhs.items.len != rhs.items.len) return TreeVecOpError.ShapeMismatch;

    const out = try allocator.alloc([]Pair(A, B), lhs.items.len);
    errdefer allocator.free(out);

    var initialized: usize = 0;
    errdefer {
        for (out[0..initialized]) |tree| allocator.free(tree);
    }

    for (lhs.items, rhs.items, 0..) |lhs_tree, rhs_tree, i| {
        if (lhs_tree.len != rhs_tree.len) return TreeVecOpError.ShapeMismatch;
        out[i] = try allocator.alloc(Pair(A, B), lhs_tree.len);
        initialized += 1;
        for (lhs_tree, rhs_tree, 0..) |lhs_value, rhs_value, j| {
            out[i][j] = .{
                .first = lhs_value,
                .second = rhs_value,
            };
        }
    }
    return TreeVec([]Pair(A, B)).initOwned(out);
}

/// Flattens a `TreeVec([][]T)` into one contiguous vector.
pub fn flattenCols(comptime T: type, allocator: std.mem.Allocator, tv: TreeVec([][]T)) ![]T {
    var total: usize = 0;
    for (tv.items) |tree| {
        for (tree) |col| total += col.len;
    }

    const out = try allocator.alloc(T, total);
    var at: usize = 0;
    for (tv.items) |tree| {
        for (tree) |col| {
            @memcpy(out[at .. at + col.len], col);
            at += col.len;
        }
    }
    return out;
}

/// Extracts sub-slices from each tree by tree index.
///
/// `Span` must provide fields `tree_index`, `col_start`, and `col_end`.
/// Duplicate `tree_index` entries are rejected.
pub fn subTree(
    comptime T: type,
    comptime Span: type,
    allocator: std.mem.Allocator,
    tv: TreeVec([]T),
    locations: []const Span,
) (std.mem.Allocator.Error || TreeVecOpError)!TreeVec([]const T) {
    for (locations, 0..) |location, i| {
        _ = location.tree_index;
        _ = location.col_start;
        _ = location.col_end;
        var j: usize = 0;
        while (j < i) : (j += 1) {
            if (locations[j].tree_index == location.tree_index) {
                return TreeVecOpError.DuplicateTreeIndex;
            }
        }
    }

    var max_tree_index: usize = 0;
    for (locations) |location| max_tree_index = @max(max_tree_index, location.tree_index);
    const out_len = if (locations.len == 0) 1 else max_tree_index + 1;

    const out = try allocator.alloc([]const T, out_len);
    errdefer allocator.free(out);
    for (out) |*tree| tree.* = &[_]T{};

    for (locations) |location| {
        if (location.tree_index >= tv.items.len) return TreeVecOpError.InvalidSubTreeSpan;
        if (location.col_start > location.col_end) return TreeVecOpError.InvalidSubTreeSpan;

        const tree = tv.items[location.tree_index];
        if (location.col_end > tree.len) return TreeVecOpError.InvalidSubTreeSpan;
        out[location.tree_index] = tree[location.col_start..location.col_end];
    }

    return TreeVec([]const T).initOwned(out);
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
    try std.testing.expectEqualSlices(usize, &[_]usize{ 1, 1, 3, 3 }, a);

    const b = try preparePreprocessedQueryPositions(alloc, q[0..], 6, 8);
    defer alloc.free(b);
    try std.testing.expectEqualSlices(usize, &[_]usize{ 9, 25, 41, 57 }, b);
}

test "pcs utils: treevec zip and zipEq" {
    const alloc = std.testing.allocator;

    var lhs = TreeVec(u32).initOwned(try alloc.dupe(u32, &[_]u32{ 3, 5, 7 }));
    defer lhs.deinit(alloc);
    var rhs_short = TreeVec(u8).initOwned(try alloc.dupe(u8, &[_]u8{ 11, 13 }));
    defer rhs_short.deinit(alloc);
    var rhs_eq = TreeVec(u8).initOwned(try alloc.dupe(u8, &[_]u8{ 11, 13, 17 }));
    defer rhs_eq.deinit(alloc);

    var zipped = try lhs.zip(u8, alloc, rhs_short);
    defer zipped.deinit(alloc);
    try std.testing.expectEqual(@as(usize, 2), zipped.items.len);
    try std.testing.expectEqual(@as(u32, 3), zipped.items[0].first);
    try std.testing.expectEqual(@as(u8, 11), zipped.items[0].second);
    try std.testing.expectEqual(@as(u32, 5), zipped.items[1].first);
    try std.testing.expectEqual(@as(u8, 13), zipped.items[1].second);

    try std.testing.expectError(
        TreeVecOpError.ShapeMismatch,
        lhs.zipEq(u8, alloc, rhs_short),
    );

    var zipped_eq = try lhs.zipEq(u8, alloc, rhs_eq);
    defer zipped_eq.deinit(alloc);
    try std.testing.expectEqual(@as(usize, 3), zipped_eq.items.len);
    try std.testing.expectEqual(@as(u32, 7), zipped_eq.items[2].first);
    try std.testing.expectEqual(@as(u8, 17), zipped_eq.items[2].second);
}

test "pcs utils: zip cols and flatten cols" {
    const alloc = std.testing.allocator;

    const lhs_t0 = try alloc.dupe(u32, &[_]u32{ 1, 2 });
    const lhs_t1 = try alloc.dupe(u32, &[_]u32{3});
    var lhs = TreeVec([]u32).initOwned(try alloc.dupe([]u32, &[_][]u32{ lhs_t0, lhs_t1 }));
    defer lhs.deinitDeep(alloc);

    const rhs_t0 = try alloc.dupe(u8, &[_]u8{ 10, 20 });
    const rhs_t1 = try alloc.dupe(u8, &[_]u8{30});
    var rhs = TreeVec([]u8).initOwned(try alloc.dupe([]u8, &[_][]u8{ rhs_t0, rhs_t1 }));
    defer rhs.deinitDeep(alloc);

    var zipped = try zipCols(u32, u8, alloc, lhs, rhs);
    defer zipped.deinitDeep(alloc);
    try std.testing.expectEqual(@as(usize, 2), zipped.items.len);
    try std.testing.expectEqual(@as(usize, 2), zipped.items[0].len);
    try std.testing.expectEqual(@as(u32, 2), zipped.items[0][1].first);
    try std.testing.expectEqual(@as(u8, 20), zipped.items[0][1].second);
    try std.testing.expectEqual(@as(u32, 3), zipped.items[1][0].first);
    try std.testing.expectEqual(@as(u8, 30), zipped.items[1][0].second);

    const nested_a0 = try alloc.dupe(u32, &[_]u32{ 4, 5 });
    const nested_a1 = try alloc.dupe(u32, &[_]u32{6});
    const nested_b0 = try alloc.dupe(u32, &[_]u32{ 7, 8, 9 });
    const nested_t0 = try alloc.dupe([]u32, &[_][]u32{ nested_a0, nested_a1 });
    const nested_t1 = try alloc.dupe([]u32, &[_][]u32{nested_b0});
    var nested = TreeVec([][]u32).initOwned(try alloc.dupe([][]u32, &[_][][]u32{ nested_t0, nested_t1 }));
    defer nested.deinitDeep(alloc);

    const flat = try flattenCols(u32, alloc, nested);
    defer alloc.free(flat);
    try std.testing.expectEqualSlices(u32, &[_]u32{ 4, 5, 6, 7, 8, 9 }, flat);
}

test "pcs utils: zip cols shape mismatch fails" {
    const alloc = std.testing.allocator;

    const lhs_t0 = try alloc.dupe(u32, &[_]u32{ 1, 2 });
    var lhs = TreeVec([]u32).initOwned(try alloc.dupe([]u32, &[_][]u32{lhs_t0}));
    defer lhs.deinitDeep(alloc);

    const rhs_t0 = try alloc.dupe(u8, &[_]u8{ 10, 20 });
    const rhs_t1 = try alloc.dupe(u8, &[_]u8{30});
    var rhs = TreeVec([]u8).initOwned(try alloc.dupe([]u8, &[_][]u8{ rhs_t0, rhs_t1 }));
    defer rhs.deinitDeep(alloc);

    try std.testing.expectError(
        TreeVecOpError.ShapeMismatch,
        zipCols(u32, u8, alloc, lhs, rhs),
    );

    const rhs_one = try alloc.dupe(u8, &[_]u8{10});
    var rhs_same_trees = TreeVec([]u8).initOwned(try alloc.dupe([]u8, &[_][]u8{rhs_one}));
    defer rhs_same_trees.deinitDeep(alloc);
    try std.testing.expectError(
        TreeVecOpError.ShapeMismatch,
        zipCols(u32, u8, alloc, lhs, rhs_same_trees),
    );
}

test "pcs utils: sub tree" {
    const alloc = std.testing.allocator;
    const Span = struct {
        tree_index: usize,
        col_start: usize,
        col_end: usize,
    };

    const tree0 = try alloc.dupe(u32, &[_]u32{ 1, 2, 3 });
    const tree1 = try alloc.dupe(u32, &[_]u32{ 7, 8, 9, 10 });
    var tv = TreeVec([]u32).initOwned(try alloc.dupe([]u32, &[_][]u32{ tree0, tree1 }));
    defer tv.deinitDeep(alloc);

    const spans = [_]Span{
        .{ .tree_index = 1, .col_start = 1, .col_end = 3 },
        .{ .tree_index = 0, .col_start = 0, .col_end = 2 },
    };
    var out = try subTree(u32, Span, alloc, tv, spans[0..]);
    defer out.deinit(alloc);
    try std.testing.expectEqual(@as(usize, 2), out.items.len);
    try std.testing.expectEqualSlices(u32, &[_]u32{ 1, 2 }, out.items[0]);
    try std.testing.expectEqualSlices(u32, &[_]u32{ 8, 9 }, out.items[1]);

    const empty_spans = [_]Span{};
    var empty_out = try subTree(u32, Span, alloc, tv, empty_spans[0..]);
    defer empty_out.deinit(alloc);
    try std.testing.expectEqual(@as(usize, 1), empty_out.items.len);
    try std.testing.expectEqual(@as(usize, 0), empty_out.items[0].len);
}

test "pcs utils: sub tree duplicate or invalid span fails" {
    const alloc = std.testing.allocator;
    const Span = struct {
        tree_index: usize,
        col_start: usize,
        col_end: usize,
    };

    const tree0 = try alloc.dupe(u32, &[_]u32{ 1, 2, 3 });
    var tv = TreeVec([]u32).initOwned(try alloc.dupe([]u32, &[_][]u32{tree0}));
    defer tv.deinitDeep(alloc);

    const duplicate_spans = [_]Span{
        .{ .tree_index = 0, .col_start = 0, .col_end = 1 },
        .{ .tree_index = 0, .col_start = 1, .col_end = 2 },
    };
    try std.testing.expectError(
        TreeVecOpError.DuplicateTreeIndex,
        subTree(u32, Span, alloc, tv, duplicate_spans[0..]),
    );

    const invalid_spans = [_]Span{
        .{ .tree_index = 0, .col_start = 1, .col_end = 4 },
    };
    try std.testing.expectError(
        TreeVecOpError.InvalidSubTreeSpan,
        subTree(u32, Span, alloc, tv, invalid_spans[0..]),
    );
}
