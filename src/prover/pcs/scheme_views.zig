//! Borrowed trace views and query-position geometry for a PCS scheme.

const std = @import("std");
const pcs = @import("stwo_core").pcs;
const pcs_utils = pcs.utils;
const verifier_types = @import("stwo_core").verifier_types;
const component_prover = @import("../air/component_prover.zig");
const prover_circle = @import("../poly/circle/mod.zig");

const TreeVec = pcs.TreeVec;

pub fn roots(comptime H: type, scheme: anytype, allocator: std.mem.Allocator) !TreeVec(H.Hash) {
    const out = try allocator.alloc(H.Hash, scheme.trees.items.len);
    for (scheme.trees.items, 0..) |tree, index| out[index] = tree.root();
    return TreeVec(H.Hash).initOwned(out);
}

pub fn polynomials(scheme: anytype, allocator: std.mem.Allocator) !TreeVec([]const component_prover.Poly) {
    const out = try allocator.alloc([]const component_prover.Poly, scheme.trees.items.len);
    errdefer allocator.free(out);
    var initialized: usize = 0;
    errdefer for (out[0..initialized]) |tree_polys| allocator.free(tree_polys);

    for (scheme.trees.items, 0..) |tree, tree_index| {
        const polys = try allocator.alloc(component_prover.Poly, tree.columns.len);
        out[tree_index] = polys;
        initialized += 1;
        for (tree.columns, 0..) |column, column_index| {
            polys[column_index] = .{
                .log_size = column.log_size,
                .values = column.values,
                .coefficients = if (tree.coefficients) |coefficients|
                    try prover_circle.CircleCoefficients.initBorrowed(
                        coefficients[column_index].coefficients(),
                    )
                else
                    null,
            };
        }
    }
    return TreeVec([]const component_prover.Poly).initOwned(out);
}

pub fn trace(scheme: anytype, allocator: std.mem.Allocator) !component_prover.Trace {
    return .{ .polys = try polynomials(scheme, allocator) };
}

/// Returns one borrowed backend resource handle per commitment tree. Keeping
/// tree indices intact lets AIR capabilities select their exact proof-session
/// input without runtime-wide discovery.
pub fn backendResidencyHandles(
    comptime B: type,
    comptime H: type,
    scheme: anytype,
    allocator: std.mem.Allocator,
) ![]?*anyopaque {
    const handles = try allocator.alloc(?*anyopaque, scheme.trees.items.len);
    for (scheme.trees.items, handles) |tree, *handle| {
        handle.* = if (comptime B != void and @hasDecl(B, "quotientResidencyHandle"))
            B.quotientResidencyHandle(H, tree.commitment)
        else
            null;
    }
    return handles;
}

pub fn columnLogSizes(scheme: anytype, allocator: std.mem.Allocator) !TreeVec([]u32) {
    const out = try allocator.alloc([]u32, scheme.trees.items.len);
    errdefer allocator.free(out);
    var initialized: usize = 0;
    errdefer for (out[0..initialized]) |tree_sizes| allocator.free(tree_sizes);
    for (scheme.trees.items, 0..) |tree, index| {
        out[index] = try tree.columnLogSizes(allocator);
        initialized += 1;
    }
    return TreeVec([]u32).initOwned(out);
}

pub fn buildQueryPositionsTree(
    scheme: anytype,
    allocator: std.mem.Allocator,
    query_positions: []const usize,
    lifting_log_size: u32,
) !TreeVec([]usize) {
    const out = try allocator.alloc([]usize, scheme.trees.items.len);
    errdefer allocator.free(out);
    var initialized: usize = 0;
    errdefer for (out[0..initialized]) |positions| allocator.free(positions);

    for (scheme.trees.items, 0..) |tree, tree_index| {
        const tree_log_size: ?u32 = if (tree.columns.len == 0) null else blk: {
            var max_log_size: u32 = 0;
            for (tree.columns) |column| {
                max_log_size = @max(max_log_size, column.log_size);
            }
            break :blk max_log_size;
        };
        out[tree_index] = try pcs_utils.prepareTreeQueryPositions(
            allocator,
            query_positions,
            lifting_log_size,
            tree_log_size,
        );
        initialized += 1;
    }
    return TreeVec([]usize).initOwned(out);
}

fn checkHeterogeneousQueryTreeAllocationFailures(allocator: std.mem.Allocator) !void {
    const Column = struct { log_size: u32 };
    const Tree = struct { columns: []const Column };
    const Trees = struct { items: []const Tree };
    const small = [_]Column{.{ .log_size = 1 }};
    const large = [_]Column{.{ .log_size = 3 }};
    const trees = [_]Tree{
        .{ .columns = &small },
        .{ .columns = &large },
        .{ .columns = &.{} },
    };
    const scheme = .{ .trees = Trees{ .items = &trees } };
    const query_positions = [_]usize{ 0, 1, 5, 6 };
    var result = try buildQueryPositionsTree(scheme, allocator, &query_positions, 4);
    defer result.deinitDeep(allocator);
    try std.testing.expectEqual(@as(usize, 3), result.items.len);
    try std.testing.expectEqual(@as(usize, 0), result.items[2].len);
}

test "prover pcs views: heterogeneous query tree cleans up every allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        checkHeterogeneousQueryTreeAllocationFailures,
        .{},
    );
}
