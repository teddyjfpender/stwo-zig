//! Official stable-sort and row-major query transport.

const std = @import("std");
const composition = @import("../../witness/composition_bundle.zig");
const layout = @import("../layout.zig");
const felt_json = @import("felt_json.zig");

const OrderedColumn = struct {
    log_size: u32,
    index: usize,
};

pub fn write(
    allocator: std.mem.Allocator,
    writer: anytype,
    state: *felt_json.State,
    queried_values: anytype,
    bundle: *const composition.Bundle,
) !void {
    const trees = queried_values.items;
    if (trees.len != 4) return error.InvalidQueriedValueTrees;
    const n_queries = try queryCount(trees);

    try felt_json.write(writer, state, trees.len);
    try writeRowMajor(writer, state, trees[0], n_queries);
    try writeSortedTree(
        allocator,
        writer,
        state,
        trees[1],
        n_queries,
        try layout.treeLogs(allocator, bundle, 1, trees[1].len),
    );
    try writeSortedTree(
        allocator,
        writer,
        state,
        trees[2],
        n_queries,
        try layout.treeLogs(allocator, bundle, 2, trees[2].len),
    );
    try writeRowMajor(writer, state, trees[3], n_queries);
}

fn writeSortedTree(
    allocator: std.mem.Allocator,
    writer: anytype,
    state: *felt_json.State,
    columns: anytype,
    n_queries: usize,
    logs: []u32,
) !void {
    defer allocator.free(logs);
    if (logs.len != columns.len) return error.InvalidQueriedValueShape;
    const order = try allocator.alloc(OrderedColumn, columns.len);
    defer allocator.free(order);
    for (logs, order, 0..) |log_size, *entry, index|
        entry.* = .{ .log_size = log_size, .index = index };
    std.mem.sort(OrderedColumn, order, {}, lessThan);

    try felt_json.write(
        writer,
        state,
        std.math.mul(usize, columns.len, n_queries) catch
            return error.QueriedValueCountOverflow,
    );
    for (0..n_queries) |row| {
        for (order) |entry|
            try felt_json.write(writer, state, columns[entry.index][row].toU32());
    }
}

fn writeRowMajor(
    writer: anytype,
    state: *felt_json.State,
    columns: anytype,
    n_queries: usize,
) !void {
    try felt_json.write(
        writer,
        state,
        std.math.mul(usize, columns.len, n_queries) catch
            return error.QueriedValueCountOverflow,
    );
    for (0..n_queries) |row|
        for (columns) |column|
            try felt_json.write(writer, state, column[row].toU32());
}

fn queryCount(trees: anytype) !usize {
    var count: ?usize = null;
    for (trees) |columns| {
        if (columns.len == 0) return error.InvalidQueriedValueShape;
        for (columns) |column| {
            if (count == null) count = column.len;
            if (column.len != count.? or column.len == 0)
                return error.InvalidQueriedValueShape;
        }
    }
    return count orelse error.InvalidQueriedValueShape;
}

fn lessThan(_: void, lhs: OrderedColumn, rhs: OrderedColumn) bool {
    return lhs.log_size < rhs.log_size or
        (lhs.log_size == rhs.log_size and lhs.index < rhs.index);
}
