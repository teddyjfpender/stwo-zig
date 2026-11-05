//! Borrowed trace views and query-position geometry for a PCS scheme.

const std = @import("std");
const pcs = @import("stwo_core").pcs;
const pcs_utils = pcs.utils;
const verifier_types = @import("stwo_core").verifier_types;
const component_prover = @import("../air/component_prover.zig");
const prover_circle = @import("../poly/circle/mod.zig");

const TreeVec = pcs.TreeVec;

/// Logical trace slots include externally owned device commitments.
pub fn traceTreeCount(scheme: anytype) usize {
    var count = scheme.trees.items.len;
    for (scheme.device_om31_trace_trees) |tree| count += @intFromBool(tree != null);
    return count;
}

pub fn roots(comptime H: type, scheme: anytype, allocator: std.mem.Allocator) !TreeVec(H.Hash) {
    const out = try allocator.alloc(H.Hash, traceTreeCount(scheme));
    var host: usize = 0;
    for (out, 0..) |*root, index| {
        if (index < 3) if (scheme.device_om31_trace_trees[index]) |tree| {
            root.* = tree.root;
            continue;
        };
        root.* = scheme.trees.items[host].root();
        host += 1;
    }
    return TreeVec(H.Hash).initOwned(out);
}

pub fn polynomials(scheme: anytype, allocator: std.mem.Allocator) !TreeVec([]const component_prover.Poly) {
    const out = try allocator.alloc([]const component_prover.Poly, traceTreeCount(scheme));
    errdefer allocator.free(out);
    var initialized: usize = 0;
    errdefer for (out[0..initialized]) |tree_polys| allocator.free(tree_polys);

    var host: usize = 0;
    for (out, 0..) |*entry, tree_index| {
        if (tree_index < 3) if (scheme.device_om31_trace_trees[tree_index]) |device| {
            const polys = try allocator.alloc(component_prover.Poly, device.columns.len);
            entry.* = polys;
            initialized += 1;
            for (device.columns, polys) |column, *poly| poly.* = .{ .log_size = column.log_size + scheme.config.fri_config.log_blowup_factor, .values = &.{}, .device = column.device };
            continue;
        };
        const tree = scheme.trees.items[host];
        host += 1;
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
    return .{
        .polys = try polynomials(scheme, allocator),
        .partition_coefficient_composition = scheme.compact_polynomial_storage,
        .quotient_values_allocator = scheme.quotient_values_allocator,
    };
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
    const out = try allocator.alloc([]u32, traceTreeCount(scheme));
    errdefer allocator.free(out);
    var initialized: usize = 0;
    errdefer for (out[0..initialized]) |tree_sizes| allocator.free(tree_sizes);
    var host: usize = 0;
    for (out, 0..) |*entry, index| {
        if (index < 3) if (scheme.device_om31_trace_trees[index]) |tree| {
            entry.* = try allocator.alloc(u32, tree.columns.len);
            initialized += 1;
            for (entry.*, tree.columns) |*log, column| log.* = column.log_size + scheme.config.fri_config.log_blowup_factor;
            continue;
        };
        entry.* = try scheme.trees.items[host].columnLogSizes(allocator);
        initialized += 1;
        host += 1;
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

    // A revision scheme may commit a tree above its largest column; queries
    // then address its committed height (`revision_lifting`).
    const committed_heights = comptime @hasField(@TypeOf(scheme), "revision_config");
    for (scheme.trees.items, 0..) |tree, tree_index| {
        const tree_log_size: ?u32 = if (tree.columns.len == 0) null else blk: {
            if (committed_heights) {
                if (scheme.revision_config != null) break :blk tree.commitment.maxLogSize();
            }
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

test "resident MAIN and INTER retain logical trace slots without host trees" {
    const a = std.testing.allocator;
    const D = @import("stwo_prover_api").device_pcs;
    const M = @import("stwo_core").fields.m31.M31;
    const Host = struct {
        columns: []const struct { log_size: u32, values: []const M },
        coefficients: ?[]const prover_circle.CircleCoefficients = null,
        fn root(_: @This()) [32]u8 {
            return @splat(1);
        }
        fn columnLogSizes(self: @This(), allocator: std.mem.Allocator) ![]u32 {
            const logs = try allocator.alloc(u32, self.columns.len);
            for (logs, self.columns) |*log, column| log.* = column.log_size;
            return logs;
        }
    };
    const hosts = [_]Host{.{ .columns = &.{} }};
    const main = [_]D.Column{.{ .log_size = 5, .device = .{ .words = @ptrFromInt(4096), .count = 32, .context_token = 1, .generation = 2 } }};
    const inter = [_]D.Column{.{ .log_size = 6, .device = .{ .words = @ptrFromInt(8192), .count = 64, .context_token = 1, .generation = 3 } }};
    const scheme = .{
        .trees = .{ .items = &hosts },
        .device_om31_trace_trees = [3]?D.Tree{ null, .{ .root = @splat(2), .columns = &main }, .{ .root = @splat(3), .columns = &inter } },
        .config = .{ .fri_config = .{ .log_blowup_factor = @as(u32, 1) } },
        .compact_polynomial_storage = true,
        .quotient_values_allocator = @as(?std.mem.Allocator, null),
    };
    var committed = try roots(struct {
        pub const Hash = [32]u8;
    }, scheme, a);
    defer committed.deinit(a);
    try std.testing.expectEqual(@as(usize, 3), committed.items.len);
    try std.testing.expectEqual(@as(u8, 2), committed.items[1][0]);
    try std.testing.expectEqual(@as(u8, 3), committed.items[2][0]);
    var logs = try columnLogSizes(scheme, a);
    defer logs.deinitDeep(a);
    try std.testing.expectEqual(@as(u32, 6), logs.items[1][0]);
    try std.testing.expectEqual(@as(u32, 7), logs.items[2][0]);
    var borrowed = try trace(scheme, a);
    defer borrowed.polys.deinitDeep(a);
    try std.testing.expectEqual(@as(usize, 0), borrowed.polys.items[1][0].values.len);
    try std.testing.expect(borrowed.polys.items[1][0].coefficients == null);
    try borrowed.polys.items[1][0].validate();
    try std.testing.expectError(error.DeviceColumnRequiresBackend, borrowed.polys.items[1][0].valueAtLiftingPosition(7, 0));
}
