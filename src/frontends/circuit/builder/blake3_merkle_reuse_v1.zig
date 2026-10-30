//! Native experimental-v1 BLAKE3 Merkle kernels. No fixed four-tree assumption.
//! Expanded paths are untrusted witness data and receive full circuit checks.
//! The caller must bind query/root wires to the exact transcript/statement.
//! This does not admit a PCS proof, a compressed-proof codec, or a leaf key.
const std = @import("std");
const core = @import("stwo_core");
const b = @import("mod.zig");
const channel = @import("blake3_channel_reuse_v1.zig");
const primitive = @import("blake3_reuse_v1.zig");
const W = b.wrappers.U32Wrapper(b.Var);
const M = b.wrappers.M31Wrapper(b.Var);
pub const Digest = primitive.Digest;
pub const production_active = false;
pub const MAX_HEIGHT: u32 = 30;
pub const Layout = struct {
    column_logs: []const u32,
    height: u32,
    pub fn validate(self: Layout) !void {
        if (self.height > MAX_HEIGHT or self.column_logs.len == 0 or self.column_logs.len > channel.MAX_FRAME_WORDS - 7) return error.InvalidBlake3MerkleLayout;
        for (self.column_logs) |log| if (log > self.height) return error.InvalidBlake3MerkleLayout;
    }
};
fn less(logs: []const u32, left: usize, right: usize) bool {
    return logs[left] < logs[right] or (logs[left] == logs[right] and left < right);
}
/// Native lifted verifier hashes queried columns in ascending (log,index) order.
/// Only independently admitted layout metadata may determine this permutation.
pub fn hashLeaf(comptime V: type, ctx: *b.Context(V), layout: Layout, values: []const M) !Digest {
    try layout.validate();
    if (values.len != layout.column_logs.len) return error.InvalidBlake3MerkleLeafWidth;
    const order = try ctx.scratch().alloc(usize, values.len);
    for (order, 0..) |*index, i| index.* = i;
    std.sort.heap(usize, order, layout.column_logs, less);
    const words = try ctx.scratch().alloc(W, 7 + values.len);
    const prefix = core.channel.blake3.PROTOCOL_ID ++ [_]u8{@intFromEnum(core.channel.blake3.Domain.leaf)};
    comptime std.debug.assert(prefix.len == 28);
    for (words[0..7], 0..) |*word, i| word.* = try b.wrappers.constU32(V, ctx, std.mem.readInt(u32, prefix[i * 4 ..][0..4], .little));
    for (words[7..], order) |*word, i| word.* = try b.blake.m31ToU32(V, ctx, values[i].get());
    return channel.hashWords(V, ctx, words);
}
/// Native drawQueries consumes raw U32 blocks (NO field-sampler rejection),
/// masks low domain bits and preserves draw order/duplicates. Outputs are
/// authenticated wires derived from the same channel that absorbed the roots.
pub fn drawQueries(comptime V: type, ctx: *b.Context(V), transcript: *channel.Channel(V), global_log: u32, count: usize) ![]M {
    if (global_log > MAX_HEIGHT or count > channel.MAX_FRAME_WORDS) return error.InvalidBlake3MerkleInventory;
    const queries = try ctx.scratch().alloc(M, count);
    var produced: usize = 0;
    while (produced < count) {
        const raw = try transcript.drawU32s(ctx);
        for (raw, 0..) |word, raw_index| {
            const packed_word = [1]b.Var{word.get()};
            const bits = try b.extract_bits.extractBits(V, ctx, b.simd.Simd.fromPacked(&packed_word, 2), 16);
            var query = ctx.zero();
            for (0..global_log) |i| {
                const bit = try b.simd.unpackIdx(V, ctx, bits[i % 16], i / 16);
                const power = try ctx.constant(core.fields.qm31.QM31.fromU32Unchecked(@as(u32, 1) << @intCast(i), 0, 0, 0));
                query = try ctx.add(query, try ctx.mul(bit, power));
            }
            queries[produced] = .newUnsafe(query);
            produced += 1;
            if (produced == count) {
                for (raw[raw_index + 1 ..]) |spare| try ctx.markAsUnused(spare.get());
                break;
            }
        }
    }
    return queries;
}

/// Range-check the global query, then reproduce prepareTreeQueryPositions.
/// Circle-domain pair bit0 survives every projection; coset bits are shifted.
/// A zero-height nonempty tree always opens its single leaf.
pub fn queryDirections(comptime V: type, ctx: *b.Context(V), query: M, global_log: u32, tree_height: u32) ![]b.Var {
    if (global_log > MAX_HEIGHT or tree_height > MAX_HEIGHT) return error.InvalidBlake3MerkleLayout;
    const global_bits = try ctx.scratch().alloc(b.Var, global_log);
    if (global_log == 0) {
        try ctx.eq(query.get(), ctx.zero());
    } else {
        const packed_query = [1]b.Var{query.get()};
        const decomposed = try b.extract_bits.extractBits(V, ctx, b.simd.Simd.fromPacked(&packed_query, 1), global_log);
        for (global_bits, decomposed) |*bit, value| bit.* = value.data[0];
    }
    const directions = try ctx.scratch().alloc(b.Var, tree_height);
    @memset(directions, ctx.zero());
    if (tree_height == 0 or global_log == 0) return directions;
    directions[0] = global_bits[0];
    if (global_log >= tree_height) {
        for (1..tree_height) |i| directions[i] = global_bits[i + global_log - tree_height];
    } else {
        const shift = tree_height - global_log;
        for (1..global_log) |i| directions[i + shift] = global_bits[i];
    }
    return directions;
}
fn path(comptime V: type, ctx: *b.Context(V), leaf: Digest, bits: []const b.Var, siblings: []const Digest, root: Digest) !void {
    if (bits.len != siblings.len) return error.InvalidBlake3MerklePathLength;
    var current = leaf;
    for (bits, siblings) |bit, sibling| {
        var left: Digest = undefined;
        var right: Digest = undefined;
        for (current, sibling, &left, &right) |word, other, *l, *r| {
            const selected = try b.ops.condFlipU32(V, ctx, bit, word, other);
            l.* = selected[0];
            r.* = selected[1];
        }
        current = try primitive.protocolNode(V, ctx, left, right);
    }
    for (current, root) |actual, expected| try ctx.eq(actual.get(), expected.get());
}
/// Query directions are derived inside this API; no unconstrained host bits.
/// The global query wire must be supplied by a public binding/FS query circuit.
pub fn verifyOpening(comptime V: type, ctx: *b.Context(V), layout: Layout, global_query: M, global_log: u32, values: []const M, siblings: []const Digest, root: Digest) !void {
    try layout.validate();
    if (siblings.len != layout.height) return error.InvalidBlake3MerklePathLength;
    const bits = try queryDirections(V, ctx, global_query, global_log, layout.height);
    try path(V, ctx, try hashLeaf(V, ctx, layout, values), bits, siblings, root);
}
/// A finite physical roster can contain Local11, Mixed14 or widened Group trees.
/// Empty trees have no openings and must be omitted by the independently
/// reconstructed PCS roster, rather than silently authenticated here.
pub const Opening = struct { layout: Layout, values: []const M, siblings: []const Digest, root: Digest };
pub fn verifyForest(comptime V: type, ctx: *b.Context(V), global_query: M, global_log: u32, openings: []const Opening) !void {
    if (openings.len == 0 or openings.len > 256) return error.InvalidBlake3MerkleInventory;
    for (openings) |opening| try verifyOpening(V, ctx, opening.layout, global_query, global_log, opening.values, opening.siblings, opening.root);
}

test {
    _ = @import("blake3_merkle_reuse_v1_test.zig");
}
