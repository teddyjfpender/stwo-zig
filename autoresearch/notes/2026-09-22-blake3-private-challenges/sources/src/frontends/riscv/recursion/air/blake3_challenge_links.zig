//! Semantic transcript output bindings, independent of challenge values.
const std = @import("std");
const t = @import("blake3_transcript_witness.zig");
const deep = @import("pcs_deep_circuit.zig");
const fri = @import("fri_verifier_circuit.zig");
pub const CIRCUIT: u32 = 5_000_003;
pub const Sources = struct { sample_start: u32, claim_start: u32, composition: u32, oods: u32, universal_start: u32 };
pub const Scalar = struct { lane: usize, nodes: [4]u32 };
pub const Link = struct { source: t.Caller, composition: ?u32 = null, scalar: ?Scalar = null };
const missing = std.math.maxInt(u32);

/// Returned storage belongs to a. Every expected draw and coordinate is mandatory.
pub fn build(a: std.mem.Allocator, outputs: []const t.DrawOutput, sources: Sources, dg: *const deep.Circuit, fg: *const fri.Circuit, universal_count: usize, layer_count: usize) ![]const Link {
    var seed: [4]u32 = @splat(missing);
    var randomness: [4]u32 = @splat(missing);
    const alphas = try a.alloc([4]u32, layer_count);
    defer a.free(alphas);
    @memset(alphas, @splat(missing));
    for (dg.bindings) |binding| switch (binding.source) {
        .oods_seed_word => |word| try coordinate(&seed, word, binding.node_id),
        .deep_randomness_word => |word| try coordinate(&randomness, word, binding.node_id),
        else => {},
    };
    for (fg.bindings) |binding| switch (binding.source) {
        .fri_alpha_word => |source| {
            if (source.layer >= alphas.len) return error.InvalidParentChallengeLink;
            try coordinate(&alphas[source.layer], source.word, binding.node_id);
        },
        else => {},
    };
    try complete(seed);
    try complete(randomness);
    for (alphas) |nodes| try complete(nodes);
    const count = try std.math.add(usize, try std.math.mul(usize, universal_count, 2), try std.math.add(usize, layer_count, 3));
    const result = try a.alloc(Link, count);
    errdefer a.free(result);
    const seen = try a.alloc(bool, count);
    defer a.free(seen);
    @memset(seen, false);
    const base = universal_count * 2;
    for (outputs) |output| {
        const index: usize = switch (output.role) {
            .universal => |i| blk: {
                if (i >= universal_count or output.words != 8) return error.InvalidParentChallengeLink;
                break :blk i * 2;
            },
            .composition => base,
            .oods => base + 1,
            .deep => base + 2,
            .fri => |i| blk: {
                if (i >= layer_count) return error.InvalidParentChallengeLink;
                break :blk base + 3 + i;
            },
        };
        if (output.role != .universal and output.words != 4) return error.InvalidParentChallengeLink;
        for (0..output.words / 4) |half| {
            const slot = index + half;
            if (seen[slot]) return error.InvalidParentChallengeLink;
            seen[slot] = true;
            result[slot] = .{ .source = .{ .circuit = output.source.circuit, .first_wire = try std.math.add(u32, output.source.first_wire, @intCast(4 * half)) } };
            switch (output.role) {
                .universal => result[slot].composition = try std.math.add(u32, sources.universal_start, @intCast(slot)),
                .composition => result[slot].composition = sources.composition,
                .oods => {
                    result[slot].composition = sources.oods;
                    result[slot].scalar = .{ .lane = 1, .nodes = seed };
                },
                .deep => result[slot].scalar = .{ .lane = 1, .nodes = randomness },
                .fri => |i| result[slot].scalar = .{ .lane = 2, .nodes = alphas[i] },
            }
        }
    }
    for (seen) |present| if (!present) return error.InvalidParentChallengeLink;
    return result;
}
fn coordinate(nodes: *[4]u32, word: u32, node: u32) !void {
    if (word >= 4 or node == missing or nodes[word] != missing) return error.InvalidParentChallengeLink;
    nodes[word] = node;
}
fn complete(nodes: [4]u32) !void {
    for (nodes) |node| if (node == missing) return error.InvalidParentChallengeLink;
}
