//! Fixed query-ordinal sharing. No private query position selects this schedule.
const std = @import("std");
const core = @import("stwo_core");
const Caller = @import("blake3_frame_route.zig").Caller;
pub const Sharing = struct { first_namespace: u32, query_index: u32, queries: u32 };
pub const Plan = struct {
    inputs: [2]Caller,
    output: Caller,
    queries: u32,
    owner: bool,
};
pub fn derive(s: anytype, output_wire: u32) !?Plan {
    const sharing = s.shared_root orelse return null;
    const fail = error.InvalidSharedBlake3Root;
    if (s.depth == 0 or s.directions == null or s.root_source == null or sharing.queries < 2 or sharing.query_index >= sharing.queries or sharing.queries >= core.fields.m31.Modulus) return fail;
    const nodes = try std.math.sub(u64, try std.math.mul(u64, s.leaf_count, 2), 1);
    const span = nodes + @as(u64, s.depth) * 3;
    const expected = @as(u64, sharing.first_namespace) + span * sharing.query_index;
    if (expected != s.namespace or @as(u64, sharing.first_namespace) + span * sharing.queries > core.fields.m31.Modulus) return fail;
    const selected: u32 = @intCast(@as(u64, sharing.first_namespace) + nodes + 3 * (@as(u64, s.depth) - 1) + 1);
    return .{ .inputs = .{ .{ .circuit = selected, .first_wire = 0 }, .{ .circuit = selected, .first_wire = 8 } }, .output = .{ .circuit = selected + 1, .first_wire = output_wire }, .queries = sharing.queries, .owner = sharing.query_index == 0 };
}

pub const HashCounts = struct { g: usize, xor: usize };
pub const HashShape = struct { leaf: HashCounts, node: HashCounts, total: HashCounts };
pub fn hashShape(s: anytype, plans: @import("blake3_merkle_plan_cache.zig").Pair) !HashShape {
    const leaf_shape = HashCounts{ .g = plans.leaf.g.len, .xor = plans.leaf.xor.len };
    const node_shape = HashCounts{ .g = plans.node.g.len, .xor = plans.node.xor.len };
    const full_merges = try std.math.add(usize, s.leaf_count - 1, s.depth);
    const borrowed = if (s.shared_root) |plan| plan.query_index > 0 else false;
    const merges = if (borrowed) try std.math.sub(usize, full_merges, 1) else full_merges;
    return .{ .leaf = leaf_shape, .node = node_shape, .total = .{
        .g = try std.math.add(usize, try std.math.mul(usize, s.leaf_count, leaf_shape.g), try std.math.mul(usize, merges, node_shape.g)),
        .xor = try std.math.add(usize, try std.math.mul(usize, s.leaf_count, leaf_shape.xor), try std.math.mul(usize, merges, node_shape.xor)),
    } };
}
