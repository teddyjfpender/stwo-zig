//! Bounded typed hash emission for a caller-derived sparse topology. Every
//! computed digest has one authenticated parent; only roots retain public sinks.
const std = @import("std");
const core = @import("stwo_core");
const tree = @import("../air/memory_commitment/blake3_state_tree.zig");
const topology = @import("blake3_shared_path_topology.zig");
const leaf = @import("../recursion/air/blake3_memory_leaf.zig");
const frame = @import("../recursion/air/blake3_frame_witness.zig");
const hash_plan = @import("../recursion/air/blake3_hash_plan.zig");
const private = @import("../recursion/air/blake3_private_word.zig");
const bridge = @import("../recursion/air/blake3_input_bridge.zig");
const route = @import("../recursion/air/blake3_byte_route.zig");
const g = @import("../recursion/air/blake3_g_call.zig");
const xor = @import("../recursion/air/blake3_xor_call.zig");
const boundary = @import("../recursion/air/blake3_boundary.zig");
const M = core.fields.m31.M31;
pub const Input = struct { address: u32, caller: leaf.Caller, constant_zero: bool = false };
const zero = tree.Digest{ .bytes = @splat(0) };
pub fn valueAt(leaves: []const tree.Leaf, address: u32) u32 {
    var lo: usize = 0;
    var hi = leaves.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        if (leaves[mid].index < address) lo = mid + 1 else hi = mid;
    }
    return if (lo < leaves.len and leaves[lo].index == address) leaves[lo].value else 0;
}
const SharedFrontier = struct { namespace: u32, produce: bool };

/// Both roots use the same admitted address topology and the same frontier
/// producers. A private subtree outside the selected addresses therefore cannot
/// change between the two roots without violating the authenticated wire bus.
pub fn emitPair(a: std.mem.Allocator, inputs: [2][]const Input, namespace: u32, roots: [2]tree.Digest, leaves: [2]?[]const tree.Leaf, sink: anytype) !u32 {
    if (inputs[0].len != inputs[1].len or (leaves[0] == null) != (leaves[1] == null)) return error.InvalidPairedMemoryPaths;
    if (inputs[0].len == 0) {
        if (!std.meta.eql(roots[0], roots[1])) return error.UnchangedMemoryRootMismatch;
        return namespace;
    }
    const addresses = try a.alloc(u32, inputs[0].len);
    defer a.free(addresses);
    for (inputs[0], inputs[1], addresses) |left, right, *address| {
        if (left.address != right.address) return error.InvalidPairedMemoryPaths;
        address.* = left.address;
    }
    var graph = try topology.Graph.init(a, addresses);
    defer graph.deinit();
    const frontier_namespace = try std.math.add(u32, namespace, std.math.cast(u32, graph.nodes.len) orelse return error.SharedPathNamespaceOverflow);
    if (leaves[0]) |initial| {
        const before = try a.alloc(tree.Digest, graph.frontier.len);
        defer a.free(before);
        const after = try a.alloc(tree.Digest, graph.frontier.len);
        defer a.free(after);
        const hasher = tree.TreeHasher.init(.memory);
        try hasher.subtreeRoots(initial, graph.frontier, before);
        try hasher.subtreeRoots(leaves[1].?, graph.frontier, after);
        for (before, after) |lhs, rhs| if (!std.meta.eql(lhs, rhs)) return error.UnchangedMemorySubtreeMismatch;
    }
    const middle = try emitMode(a, inputs[0], namespace, .memory, roots[0], leaves[0], .{ .namespace = frontier_namespace, .produce = true }, false, null, sink);
    return emitMode(a, inputs[1], middle, .memory, roots[1], leaves[1], .{ .namespace = frontier_namespace, .produce = false }, false, null, sink);
}
pub fn emit(a: std.mem.Allocator, inputs: []const Input, namespace: u32, kind: tree.Kind, root: tree.Digest, leaves: ?[]const tree.Leaf, sink: anytype) !u32 {
    return emitMode(a, inputs, namespace, kind, root, leaves, null, false, null, sink);
}
/// A complete selected-leaf roster has no unknown frontier siblings. Their
/// digest rows are fixed, verifier-reconstructible defaults in the AIR. A
/// hidden nonzero leaf changes one of these subtrees and is rejected.
pub fn emitCompleteSparse(a: std.mem.Allocator, inputs: []const Input, namespace: u32, kind: tree.Kind, root: tree.Digest, leaves: ?[]const tree.Leaf, sink: anytype) !u32 {
    return emitMode(a, inputs, namespace, kind, root, leaves, null, true, null, sink);
}
pub fn emitCompleteSparseSubtree(a: std.mem.Allocator, inputs: []const Input, namespace: u32, kind: tree.Kind, root: tree.Digest, leaves: ?[]const tree.Leaf, coordinate: tree.Coordinate, sink: anytype) !u32 {
    return emitMode(a, inputs, namespace, kind, root, leaves, null, true, coordinate, sink);
}
fn emitMode(a: std.mem.Allocator, inputs: []const Input, namespace: u32, kind: tree.Kind, root: tree.Digest, leaves: ?[]const tree.Leaf, sharing: ?SharedFrontier, complete_sparse: bool, subtree: ?tree.Coordinate, sink: anytype) !u32 {
    if (inputs.len == 0) return namespace;
    const addresses = try a.alloc(u32, inputs.len);
    defer a.free(addresses);
    for (inputs, addresses) |input, *address| {
        if (input.caller.circuit >= namespace) return error.SharedPathCallerOverlap;
        address.* = input.address;
    }
    var graph = if (subtree) |coordinate|
        try topology.Graph.initSubtree(a, addresses, coordinate.level, coordinate.index)
    else
        try topology.Graph.init(a, addresses);
    defer graph.deinit();
    const end = try std.math.add(usize, namespace, try std.math.add(usize, graph.nodes.len, graph.frontier.len));
    if (end >= core.fields.m31.Modulus) return error.SharedPathNamespaceOverflow;
    const hasher = tree.TreeHasher.init(kind);
    if (leaves) |source| {
        const observed = if (subtree) |coordinate| blk: {
            var out: [1]tree.Digest = undefined;
            try hasher.subtreeRoots(source, &.{coordinate}, &out);
            break :blk out[0];
        } else try hasher.root(source);
        if (!std.meta.eql(root, observed)) return error.SharedPathRootMismatch;
    }
    const repeat_openings = !complete_sparse and std.process.hasEnvVarConstant("STWO_RISCV_REPEAT_FRONTIER_OPENINGS");
    const frontier_digests = try a.alloc(tree.Digest, if (leaves != null and !repeat_openings) graph.frontier.len else 0);
    defer a.free(frontier_digests);
    if (leaves) |source| if (!repeat_openings) try hasher.subtreeRoots(source, graph.frontier, frontier_digests);
    if (complete_sparse and leaves != null) {
        for (graph.frontier, frontier_digests) |coordinate, digest| {
            if (!std.meta.eql(digest, hasher.defaults[tree.DEPTH - coordinate.level])) return error.IncompleteSparseMemoryRoster;
        }
    }
    var leaf_shape = try hash_plan.build(a, 48);
    defer leaf_shape.deinit();
    var node_shape = try hash_plan.build(a, 108);
    defer node_shape.deinit();
    // Source use counts depend on canonical frame routing, not child values.
    var sample = try frame.trustedDigestFrame(a, namespace + @as(u32, @intCast(graph.nodes.len)), tree.Frame{ .node = .{ .kind = kind, .left = zero, .right = zero } }, &.{
        .{ .role = .left, .caller = .{ .circuit = namespace, .first_wire = leaf_shape.output[0] } },
        .{ .role = .right, .caller = .{ .circuit = namespace + 1, .first_wire = leaf_shape.output[0] } },
    }, zero.bytes);
    const child_uses = sample.source_uses;
    const node_counts = [4]usize{ sample.rows.g_rows.len, sample.rows.xor_rows.len, sample.rows.boundary_rows.len, sample.route_rows.len };
    sample.deinit();
    const known = try a.alloc(bool, graph.nodes.len);
    defer a.free(known);
    for (graph.nodes, 0..) |node, index| {
        known[index] = switch (node.source) {
            .leaf => |i| inputs[i].constant_zero,
            // Never fold across a frontier. Both paths must keep consuming
            // every shared frontier producer with the admitted doubled fanout.
            .children => |children| blk: {
                for (children) |child| switch (child) {
                    .frontier => break :blk false,
                    .computed => |i| if (!known[i]) break :blk false,
                };
                break :blk true;
            },
        };
    }
    if (known[known.len - 1] and !std.meta.eql(root, hasher.defaults[tree.DEPTH - graph.nodes[known.len - 1].coordinate.level])) return error.SharedPathRootMismatch;
    const uses = try a.alloc([8]u32, graph.nodes.len);
    defer a.free(uses);
    @memset(uses, @splat(0));
    for (graph.nodes, 0..) |node, parent_index| {
        if (known[parent_index]) continue;
        switch (node.source) {
            .leaf => {},
            .children => |children| for (children, 0..) |child, side| switch (child) {
                .computed => |index| uses[index] = child_uses[side],
                .frontier => {},
            },
        }
    }
    for (inputs) |input| if (input.constant_zero) {
        if (leaves) |values| if (valueAt(values, input.address) != 0) return error.InvalidExcludedMemoryLeaf;
    };
    if (comptime @hasDecl(@TypeOf(sink.*), "appendCount")) {
        if (leaves != null) return error.InvalidSharedPathCensus;
        // Derive counts from canonical leaf/node preparations, not a duplicate
        // model of hash rounds or frame routing. Only final root sinks remain.
        var prototype = try leaf.buildWithPlan(a, kind, inputs[0].caller, namespace, null, zero, &leaf_shape);
        defer prototype.deinit();
        for (graph.nodes, 0..) |node, index| {
            if (known[index]) {
                for (uses[index]) |fanout| if (fanout != 0) {
                    try sink.appendCount(boundary, 1);
                };
                continue;
            }
            const removed: usize = if (index + 1 == graph.nodes.len) 0 else 8;
            switch (node.source) {
                .leaf => {
                    try sink.appendCount(g, prototype.rows.g_rows.len);
                    try sink.appendCount(xor, prototype.rows.xor_rows.len);
                    try sink.appendCount(boundary, prototype.rows.boundary_rows.len - removed);
                    try sink.appendCount(bridge, 1);
                },
                .children => |children| {
                    try sink.appendCount(g, node_counts[0]);
                    try sink.appendCount(xor, node_counts[1]);
                    try sink.appendCount(boundary, node_counts[2] - removed);
                    try sink.appendCount(route, node_counts[3]);
                    for (children) |child| switch (child) {
                        .computed => {},
                        .frontier => |frontier| {
                            if (sharing != null and !sharing.?.produce) continue;
                            const coordinate = graph.frontier[frontier];
                            if (complete_sparse or tree.outsideIndexRange(kind, coordinate.level, coordinate.index))
                                try sink.appendCount(boundary, child_uses[0].len)
                            else
                                try sink.appendCount(private, child_uses[0].len);
                        },
                    };
                },
            }
        }
        return @intCast(end);
    }
    const digests = try a.alloc(tree.Digest, graph.nodes.len);
    defer a.free(digests);
    @memset(digests, zero);
    for (graph.nodes, 0..) |node, index| {
        const circuit = namespace + @as(u32, @intCast(index));
        const is_root = index + 1 == graph.nodes.len;
        const claim = if (is_root) root else zero;
        if (known[index]) {
            const digest = hasher.defaults[tree.DEPTH - node.coordinate.level];
            digests[index] = digest;
            if (is_root and !std.meta.eql(root, digest)) return error.SharedPathRootMismatch;
            const output = if (node.coordinate.level == 0) leaf_shape.output else node_shape.output;
            for (uses[index], 0..) |fanout, word| {
                if (fanout == 0) continue;
                const value = std.mem.readInt(u32, digest.bytes[word * 4 ..][0..4], .little);
                try sink.append(boundary, &.{try boundary.logicalRow(circuit, output[word], M.fromCanonical(fanout), value)});
            }
            continue;
        }
        switch (node.source) {
            .leaf => |source_index| {
                const input = inputs[source_index];
                var prepared = try leaf.buildWithPlan(a, kind, input.caller, circuit, if (leaves) |source| valueAt(source, input.address) else null, claim, &leaf_shape);
                defer prepared.deinit();
                try publish(&prepared.rows, &leaf_shape.output, uses[index], is_root, sink);
                try sink.append(bridge, &.{prepared.input});
                if (prepared.digest) |digest| digests[index] = .{ .bytes = digest };
            },
            .children => |children| {
                var bindings: [2]frame.Binding = undefined;
                var values: [2]tree.Digest = @splat(zero);
                for (children, 0..) |child, side| {
                    const caller: leaf.Caller = switch (child) {
                        .computed => |previous| blk: {
                            values[side] = digests[previous];
                            break :blk .{ .circuit = namespace + @as(u32, @intCast(previous)), .wire = if (graph.nodes[previous].coordinate.level == 0) leaf_shape.output[0] else node_shape.output[0] };
                        },
                        .frontier => |frontier| blk: {
                            const coordinate = graph.frontier[frontier];
                            const fixed_empty = complete_sparse or tree.outsideIndexRange(kind, coordinate.level, coordinate.index);
                            if (fixed_empty) {
                                values[side] = hasher.defaults[tree.DEPTH - coordinate.level];
                            } else if (leaves) |source| {
                                if (repeat_openings) {
                                    const opposite = (coordinate.index ^ 1) << @as(u5, @intCast(coordinate.level));
                                    const opening = try hasher.opening(source, opposite);
                                    values[side] = opening.siblings[coordinate.level];
                                } else values[side] = frontier_digests[frontier];
                            }
                            const sibling_circuit = if (sharing) |shared| shared.namespace + @as(u32, @intCast(frontier)) else namespace + @as(u32, @intCast(graph.nodes.len + frontier));
                            if (sharing == null or sharing.?.produce) for (child_uses[side], 0..) |uses_count, word| {
                                const fanout = try std.math.mul(u32, uses_count, if (sharing != null) 2 else 1);
                                const value = std.mem.readInt(u32, values[side].bytes[word * 4 ..][0..4], .little);
                                if (fixed_empty) {
                                    try sink.append(boundary, &.{try boundary.logicalRow(sibling_circuit, @intCast(word), M.fromCanonical(fanout), value)});
                                } else try sink.append(private, &.{try private.logicalRow(sibling_circuit, @intCast(word), fanout, value)});
                            };
                            break :blk .{ .circuit = sibling_circuit, .wire = 0 };
                        },
                    };
                    bindings[side] = .{ .role = if (side == 0) .left else .right, .caller = .{ .circuit = caller.circuit, .first_wire = caller.wire } };
                }
                const bytes = tree.Frame{ .node = .{ .kind = kind, .left = values[0], .right = values[1] } };
                var prepared = try frame.digestFrameWithPlan(a, circuit, bytes, &bindings, claim.bytes, leaves != null, &node_shape);
                defer prepared.deinit();
                if (!std.meta.eql(child_uses, prepared.source_uses)) return error.SharedPathFanoutMismatch;
                try publish(&prepared.rows, &node_shape.output, uses[index], is_root, sink);
                try sink.append(route, prepared.route_rows);
                if (prepared.digest) |digest| digests[index] = .{ .bytes = digest };
            },
        }
    }
    if (leaves != null and !std.meta.eql(digests[digests.len - 1], root)) return error.SharedPathRootMismatch;
    return @intCast(end);
}
fn publish(rows: anytype, output: *const [8]u32, uses: [8]u32, is_root: bool, sink: anytype) !void {
    if (!is_root) for (uses, 0..) |fanout, i| {
        const row = &rows.xor_rows[rows.xor_rows.len - 16 + i];
        if (row[16].toU32() != output[i] or fanout == 0) return error.InvalidSharedPathOutput;
        row[17] = M.fromCanonical(fanout);
    };
    try sink.append(g, rows.g_rows);
    try sink.append(xor, rows.xor_rows);
    try sink.append(boundary, rows.boundary_rows[0 .. rows.boundary_rows.len - if (is_root) @as(usize, 0) else 8]);
}
