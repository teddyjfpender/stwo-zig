//! Independent normalization and replay oracle for compatibility-lowering tests.
//!
//! Linear interning is intentional: this code must not share the production
//! lowerer's hash-consing implementation or its behavior under hash-table
//! growth. It is test support and is never exported by `air/lang/mod.zig`.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const prover_component = @import("stwo_prover_engine").air.component_prover;
const symbolic = @import("../extract/symbolic.zig");

const no_node = std.math.maxInt(u32);

pub const Normalized = struct {
    allocator: std.mem.Allocator,
    nodes: []symbolic.Node,
    roots: []u32,

    pub fn deinit(self: *Normalized) void {
        self.allocator.free(self.roots);
        self.allocator.free(self.nodes);
        self.* = undefined;
    }
};

pub fn normalizeBase(
    allocator: std.mem.Allocator,
    production: *const prover_component.OwnedBasePolynomialProgram,
) !Normalized {
    try production.validate();
    return normalize(
        allocator,
        production.nodes,
        production.roots,
        production.column_count,
    );
}

pub fn normalizeLookup(
    allocator: std.mem.Allocator,
    production: *const prover_component.OwnedLookupPolynomialProgram,
) !Normalized {
    try production.validate();
    var root_count: usize = 0;
    for (production.entries) |entry| {
        root_count = std.math.add(usize, root_count, 1 + entry.arity) catch
            return error.InvalidProductionNode;
    }
    const roots = try allocator.alloc(u32, root_count);
    defer allocator.free(roots);
    var cursor: usize = 0;
    for (production.entries) |entry| {
        roots[cursor] = entry.numerator;
        cursor += 1;
        @memcpy(roots[cursor .. cursor + entry.arity], entry.values[0..entry.arity]);
        cursor += entry.arity;
    }
    std.debug.assert(cursor == roots.len);
    return normalize(
        allocator,
        production.nodes,
        roots,
        production.column_count,
    );
}

pub fn replayBase(
    production: *const prover_component.OwnedBasePolynomialProgram,
    columns: []const M31,
    values: []M31,
) !void {
    try production.validate();
    return replayNodes(
        production.nodes,
        production.column_count,
        columns,
        values,
    );
}

pub fn replayLookup(
    production: *const prover_component.OwnedLookupPolynomialProgram,
    columns: []const M31,
    values: []M31,
) !void {
    try production.validate();
    return replayNodes(
        production.nodes,
        production.column_count,
        columns,
        values,
    );
}

fn normalize(
    allocator: std.mem.Allocator,
    production_nodes: []const prover_component.BasePolynomialNode,
    production_roots: []const u32,
    column_count: usize,
) !Normalized {
    const reachable = try allocator.alloc(bool, production_nodes.len);
    defer allocator.free(reachable);
    @memset(reachable, false);
    for (production_roots) |root| {
        if (root >= production_nodes.len) return error.InvalidProductionNode;
        reachable[root] = true;
    }
    var reverse = production_nodes.len;
    while (reverse > 0) {
        reverse -= 1;
        if (!reachable[reverse]) continue;
        const node = production_nodes[reverse];
        switch (node.op) {
            .constant, .column => {},
            .add, .sub, .mul => {
                if (node.lhs >= reverse or node.rhs >= reverse)
                    return error.InvalidProductionNode;
                reachable[node.lhs] = true;
                reachable[node.rhs] = true;
            },
            .neg => {
                if (node.lhs >= reverse) return error.InvalidProductionNode;
                reachable[node.lhs] = true;
            },
        }
    }

    const mapped = try allocator.alloc(u32, production_nodes.len);
    defer allocator.free(mapped);
    @memset(mapped, no_node);
    var nodes: std.ArrayList(symbolic.Node) = .empty;
    defer nodes.deinit(allocator);
    for (0..column_count) |column| {
        _ = try intern(&nodes, allocator, .{
            .op = .column,
            .value = @intCast(column),
        });
    }
    for (production_nodes, 0..) |node, index| {
        if (node.op == .column) {
            if (node.value >= column_count)
                return error.InvalidProductionNode;
            mapped[index] = node.value;
            continue;
        }
        if (!reachable[index]) continue;
        mapped[index] = switch (node.op) {
            .constant => try intern(&nodes, allocator, .{
                .op = .constant,
                .value = node.value,
            }),
            .column => unreachable,
            .add, .sub, .mul => try binary(
                &nodes,
                allocator,
                @enumFromInt(@intFromEnum(node.op)),
                try operand(mapped, node.lhs),
                try operand(mapped, node.rhs),
            ),
            .neg => try intern(&nodes, allocator, .{
                .op = .neg,
                .lhs = try operand(mapped, node.lhs),
            }),
        };
    }
    const roots = try allocator.alloc(u32, production_roots.len);
    var roots_owned = true;
    errdefer if (roots_owned) allocator.free(roots);
    for (production_roots, roots) |root, *normalized_root|
        normalized_root.* = try operand(mapped, root);
    const normalized_nodes = try nodes.toOwnedSlice(allocator);
    var nodes_owned = true;
    errdefer if (nodes_owned) allocator.free(normalized_nodes);
    var result = Normalized{
        .allocator = allocator,
        .nodes = normalized_nodes,
        .roots = roots,
    };
    roots_owned = false;
    nodes_owned = false;
    errdefer result.deinit();
    try canonicalize(&result, column_count);
    return result;
}

const OrderedNode = struct {
    source: u32,
    node: symbolic.Node,
};

/// Independent implementation of the canonical topological relabeling used
/// by the compatibility contract.
fn canonicalize(result: *Normalized, column_count: usize) !void {
    const allocator = result.allocator;
    const depth = try allocator.alloc(u32, result.nodes.len);
    defer allocator.free(depth);
    var deepest: u32 = 0;
    for (result.nodes, 0..) |node, index| {
        depth[index] = switch (node.op) {
            .constant, .column => 0,
            .add, .sub, .mul => try std.math.add(
                u32,
                @max(depth[node.lhs], depth[node.rhs]),
                1,
            ),
            .neg => try std.math.add(u32, depth[node.lhs], 1),
        };
        deepest = @max(deepest, depth[index]);
    }

    const translation = try allocator.alloc(u32, result.nodes.len);
    defer allocator.free(translation);
    @memset(translation, no_node);
    const ordered = try allocator.alloc(OrderedNode, result.nodes.len);
    defer allocator.free(ordered);
    var output: std.ArrayList(symbolic.Node) = .empty;
    defer output.deinit(allocator);
    try output.ensureTotalCapacity(allocator, result.nodes.len);
    for (result.nodes[0..column_count], 0..) |node, index| {
        output.appendAssumeCapacity(node);
        translation[index] = @intCast(index);
    }

    var current_depth: u32 = 0;
    while (true) : (current_depth += 1) {
        var count: usize = 0;
        for (result.nodes[column_count..], column_count..) |source_node, source_index| {
            if (depth[source_index] != current_depth) continue;
            var node = source_node;
            switch (node.op) {
                .constant => {},
                .column => return error.InvalidProductionNode,
                .add, .sub, .mul => {
                    node.lhs = try translated(translation, node.lhs);
                    node.rhs = try translated(translation, node.rhs);
                    if ((node.op == .add or node.op == .mul) and node.rhs < node.lhs)
                        std.mem.swap(u32, &node.lhs, &node.rhs);
                },
                .neg => node.lhs = try translated(translation, node.lhs),
            }
            ordered[count] = .{ .source = @intCast(source_index), .node = node };
            count += 1;
        }
        std.mem.sort(OrderedNode, ordered[0..count], {}, orderedNodeLessThan);
        for (ordered[0..count]) |item| {
            if (output.items.len > column_count and
                std.meta.eql(output.items[output.items.len - 1], item.node))
            {
                translation[item.source] = @intCast(output.items.len - 1);
            } else {
                translation[item.source] = @intCast(output.items.len);
                output.appendAssumeCapacity(item.node);
            }
        }
        if (current_depth == deepest) break;
    }
    for (result.roots) |*root| root.* = try translated(translation, root.*);
    const replacement = try output.toOwnedSlice(allocator);
    allocator.free(result.nodes);
    result.nodes = replacement;
}

fn translated(mapping: []const u32, source: u32) !u32 {
    if (source >= mapping.len or mapping[source] == no_node)
        return error.InvalidProductionNode;
    return mapping[source];
}

fn orderedNodeLessThan(_: void, lhs: OrderedNode, rhs: OrderedNode) bool {
    const lhs_tag = @intFromEnum(lhs.node.op);
    const rhs_tag = @intFromEnum(rhs.node.op);
    if (lhs_tag != rhs_tag) return lhs_tag < rhs_tag;
    if (lhs.node.value != rhs.node.value) return lhs.node.value < rhs.node.value;
    if (lhs.node.lhs != rhs.node.lhs) return lhs.node.lhs < rhs.node.lhs;
    if (lhs.node.rhs != rhs.node.rhs) return lhs.node.rhs < rhs.node.rhs;
    return lhs.source < rhs.source;
}

fn intern(
    nodes: *std.ArrayList(symbolic.Node),
    allocator: std.mem.Allocator,
    node: symbolic.Node,
) !u32 {
    for (nodes.items, 0..) |existing, index| {
        if (std.meta.eql(existing, node)) return @intCast(index);
    }
    const id = std.math.cast(u32, nodes.items.len) orelse
        return error.InvalidProductionNode;
    try nodes.append(allocator, node);
    return id;
}

fn binary(
    nodes: *std.ArrayList(symbolic.Node),
    allocator: std.mem.Allocator,
    op: symbolic.Op,
    lhs: u32,
    rhs: u32,
) !u32 {
    var node = symbolic.Node{ .op = op, .lhs = lhs, .rhs = rhs };
    if ((op == .add or op == .mul) and node.rhs < node.lhs)
        std.mem.swap(u32, &node.lhs, &node.rhs);
    return intern(nodes, allocator, node);
}

fn operand(mapped: []const u32, source_node: u32) !u32 {
    if (source_node >= mapped.len or mapped[source_node] == no_node)
        return error.InvalidProductionNode;
    return mapped[source_node];
}

fn replayNodes(
    nodes: []const prover_component.BasePolynomialNode,
    column_count: usize,
    columns: []const M31,
    values: []M31,
) !void {
    if (columns.len != column_count or values.len != nodes.len)
        return error.InvalidProductionReplay;
    for (nodes, values, 0..) |node, *value, index| {
        value.* = switch (node.op) {
            .constant => M31.fromCanonical(node.value),
            .column => if (node.value < columns.len)
                columns[node.value]
            else
                return error.InvalidProductionReplay,
            .add => if (node.lhs < index and node.rhs < index)
                values[node.lhs].add(values[node.rhs])
            else
                return error.InvalidProductionReplay,
            .sub => if (node.lhs < index and node.rhs < index)
                values[node.lhs].sub(values[node.rhs])
            else
                return error.InvalidProductionReplay,
            .mul => if (node.lhs < index and node.rhs < index)
                values[node.lhs].mul(values[node.rhs])
            else
                return error.InvalidProductionReplay,
            .neg => if (node.lhs < index)
                values[node.lhs].neg()
            else
                return error.InvalidProductionReplay,
        };
    }
}
