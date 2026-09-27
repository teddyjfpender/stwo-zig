//! Native witness discovery only. Fixed topology and query equalities are proved
//! by the frontier AIR rows; host agreement never replaces those constraints.
const std = @import("std");
const core = @import("stwo_core");
const frontier = @import("blake3_two_level_frontier.zig");
const Digest = [32]u8;
pub const Opening = struct {
    leaves: u32,
    words: u32,
    index: u32,
    values: []const core.fields.m31.M31,
    siblings: []const Digest,
    directions: []const @import("blake3_path_select.zig").Endpoint,
};
fn node(pair: [2]Digest) Digest {
    return (core.channel.blake3.Frame{ .node = .{ .left = pair[0], .right = pair[1] } }).hash();
}
pub fn collect(a: std.mem.Allocator, plan: frontier.Plan, openings: []const Opening, root: Digest) !frontier.Context {
    try plan.validate();
    if (openings.len != plan.queries or openings[0].leaves == 0 or !std.math.isPowerOfTwo(openings[0].leaves)) return error.InvalidFrontierCapture;
    const hashes = try a.alloc(Digest, openings[0].leaves);
    defer a.free(hashes);
    var witness = frontier.empty_witness;
    var seen = false;
    const depth = openings[0].siblings.len;
    if (depth < 2 or depth > 31) return error.InvalidFrontierCapture;
    for (openings) |opening| {
        if (opening.leaves != hashes.len or opening.siblings.len != depth or opening.directions.len != depth or opening.words == 0 or opening.index >= @as(u32, 1) << @intCast(depth) or opening.values.len != try std.math.mul(usize, opening.leaves, opening.words)) return error.InvalidFrontierCapture;
        for (hashes, 0..) |*hash, i| hash.* = (core.channel.blake3.Frame{ .leaf = opening.values[i * opening.words ..][0..opening.words] }).hash();
        var count = hashes.len;
        while (count > 1) : (count /= 2) for (0..count / 2) |i| {
            hashes[i] = node(.{ hashes[2 * i], hashes[2 * i + 1] });
        };
        var current = hashes[0];
        for (opening.siblings[0 .. depth - 2], 0..) |sibling, level| {
            const side: usize = (opening.index >> @intCast(level)) & 1;
            var pair: [2]Digest = undefined;
            pair[side] = current;
            pair[side ^ 1] = sibling;
            current = node(pair);
        }
        const side: usize = (opening.index >> @intCast(depth - 2)) & 1;
        var inputs: [2]Digest = undefined;
        inputs[side] = current;
        inputs[side ^ 1] = opening.siblings[depth - 2];
        const branch: usize = (opening.index >> @intCast(depth - 1)) & 1;
        var upper: [2]Digest = undefined;
        upper[branch] = node(inputs);
        upper[branch ^ 1] = opening.siblings[depth - 1];
        if (!std.mem.eql(u8, &node(upper), &root) or (seen and !std.meta.eql(upper, witness.opaque_digests))) return error.InvalidFrontierCapture;
        if (witness.active[branch] == 1 and !std.meta.eql(inputs, witness.inputs[branch])) return error.InvalidFrontierCapture;
        witness.inputs[branch] = inputs;
        witness.active[branch] = 1;
        witness.opaque_digests = upper;
        seen = true;
    }
    return .{ .plan = plan, .witness = witness };
}
