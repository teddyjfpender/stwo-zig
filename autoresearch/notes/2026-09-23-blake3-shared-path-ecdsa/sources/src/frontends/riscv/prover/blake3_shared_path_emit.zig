//! Bounded typed hash emission for a caller-derived sparse topology. Every
//! computed digest has one authenticated parent; only roots retain public sinks.
const std = @import("std");
const core = @import("stwo_core");
const tree = @import("../air/memory_commitment/blake3_byte_tree.zig");
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
pub const Input = struct { address: u32, caller: leaf.Caller };
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
pub fn emit(a: std.mem.Allocator, inputs: []const Input, namespace: u32, kind: tree.Kind, root: tree.Digest, leaves: ?[]const tree.Leaf, sink: anytype) !u32 {
    if (inputs.len == 0) return namespace;
    const addresses = try a.alloc(u32, inputs.len);
    defer a.free(addresses);
    for (inputs, addresses) |input, *address| {
        if (input.caller.circuit >= namespace) return error.SharedPathCallerOverlap;
        address.* = input.address;
    }
    var graph = try topology.Graph.init(a, addresses);
    defer graph.deinit();
    const end = try std.math.add(usize, namespace, try std.math.add(usize, graph.nodes.len, graph.frontier.len));
    if (end >= core.fields.m31.Modulus) return error.SharedPathNamespaceOverflow;
    const hasher = tree.TreeHasher.init(kind);
    if (leaves) |source| if (!std.meta.eql(root, try hasher.root(source))) return error.SharedPathRootMismatch;
    var leaf_shape = try hash_plan.build(a, if (kind == .program) 48 else 45);
    defer leaf_shape.deinit();
    var node_shape = try hash_plan.build(a, 108);
    defer node_shape.deinit();
    const digests = try a.alloc(tree.Digest, graph.nodes.len);
    defer a.free(digests);
    @memset(digests, zero);
    const uses = try a.alloc([8]u32, graph.nodes.len);
    defer a.free(uses);
    @memset(uses, @splat(0));
    // Source use counts depend on canonical frame routing, not child values.
    var sample = try frame.trustedDigestFrame(a, namespace + @as(u32, @intCast(graph.nodes.len)), tree.Frame{ .node = .{ .kind = kind, .left = zero, .right = zero } }, &.{
        .{ .role = .left, .caller = .{ .circuit = namespace, .first_wire = leaf_shape.output[0] } },
        .{ .role = .right, .caller = .{ .circuit = namespace + 1, .first_wire = leaf_shape.output[0] } },
    }, zero.bytes);
    const child_uses = sample.source_uses;
    sample.deinit();
    for (graph.nodes) |node| switch (node.source) {
        .leaf => {},
        .children => |children| for (children, 0..) |child, side| switch (child) {
            .computed => |index| uses[index] = child_uses[side],
            .frontier => {},
        },
    };
    for (graph.nodes, 0..) |node, index| {
        const circuit = namespace + @as(u32, @intCast(index));
        const is_root = index + 1 == graph.nodes.len;
        const claim = if (is_root) root else zero;
        switch (node.source) {
            .leaf => |source_index| {
                const input = inputs[source_index];
                var prepared = if (leaves) |source| try leaf.prepare(a, kind, input.caller, circuit, valueAt(source, input.address), claim) else try leaf.trusted(a, kind, input.caller, circuit, claim);
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
                            if (leaves) |source| {
                                const opposite = (coordinate.index ^ 1) << @as(u5, @intCast(coordinate.level));
                                const opening = try hasher.opening(source, opposite);
                                values[side] = opening.siblings[coordinate.level];
                            }
                            const sibling_circuit = namespace + @as(u32, @intCast(graph.nodes.len + frontier));
                            for (child_uses[side], 0..) |fanout, word| {
                                const value = std.mem.readInt(u32, values[side].bytes[word * 4 ..][0..4], .little);
                                try sink.append(private, &.{try private.logicalRow(sibling_circuit, @intCast(word), fanout, value)});
                            }
                            break :blk .{ .circuit = sibling_circuit, .wire = 0 };
                        },
                    };
                    bindings[side] = .{ .role = if (side == 0) .left else .right, .caller = .{ .circuit = caller.circuit, .first_wire = caller.wire } };
                }
                const bytes = tree.Frame{ .node = .{ .kind = kind, .left = values[0], .right = values[1] } };
                var prepared = if (leaves != null) try frame.prepareDigestFrame(a, circuit, bytes, &bindings, claim.bytes) else try frame.trustedDigestFrame(a, circuit, bytes, &bindings, claim.bytes);
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
