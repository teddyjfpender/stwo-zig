//! Ordered native query outputs and canonical DEEP/FRI input bindings.
const std = @import("std");
const t = @import("blake3_transcript_witness.zig");
const deep = @import("pcs_deep_circuit.zig");
const fri = @import("fri_verifier_circuit.zig");
const Endpoint = @import("blake3_byte_route.zig").Endpoint;
const missing = std.math.maxInt(u32);
pub const Bit = struct { deep: u32 = missing, fri: u32 = missing };
pub const Query = struct { source: Endpoint, position: u32 = missing, bits: [31]Bit = @splat(.{}), path_uses: [31]u32 = @splat(0) };
pub const Prepared = struct {
    arena: std.heap.ArenaAllocator,
    queries: []Query,
    fri_derived: []u32,
    pub fn deinit(self: *Prepared) void {
        self.arena.deinit();
    }
    /// Directions are consecutive bits in the original, unshifted query.
    pub fn directions(self: *Prepared, a: std.mem.Allocator, query: usize, first: u32, count: u32) ![]const Endpoint {
        return self.mappedDirections(a, query, first, count, false);
    }
    /// Lifted trace projection keeps raw bit zero and shifts only higher bits.
    pub fn traceDirections(self: *Prepared, a: std.mem.Allocator, query: usize, lifting: u32, tree_log: u32) ![]const Endpoint {
        if (tree_log > lifting) return error.InvalidParentQueryLink;
        return self.mappedDirections(a, query, lifting - tree_log, tree_log, true);
    }
    pub fn addPathUses(self: *Prepared, query: usize, bit: usize, extra: u32) !void {
        if (query >= self.queries.len or bit >= 31 or self.queries[query].bits[bit].deep == missing) return error.InvalidParentQueryLink;
        const uses = try std.math.add(u32, self.queries[query].path_uses[bit], extra);
        if (uses >= @import("stwo_core").fields.m31.Modulus) return error.InvalidParentQueryLink;
        self.queries[query].path_uses[bit] = uses;
    }
    fn mappedDirections(self: *Prepared, a: std.mem.Allocator, query: usize, first: u32, count: u32, preserve_parity: bool) ![]const Endpoint {
        if (query >= self.queries.len or @as(u64, first) + count > 31) return error.InvalidParentQueryLink;
        const out = try a.alloc(Endpoint, count);
        errdefer a.free(out);
        for (out, 0..) |*endpoint, i| {
            const bit = if (preserve_parity and i == 0) 0 else first + i;
            const q = &self.queries[query];
            q.path_uses[bit] = try std.math.add(u32, q.path_uses[bit], 8);
            endpoint.* = .{ .circuit = 1502, .wire = q.bits[bit].deep };
        }
        return out;
    }
};
pub fn build(backing: std.mem.Allocator, outputs: []const t.QueryOutput, dg: *const deep.Circuit, fg: *const fri.Circuit, queries: usize, layers: usize) !Prepared {
    if (outputs.len != queries) return error.InvalidParentQueryLink;
    var arena = std.heap.ArenaAllocator.init(backing);
    errdefer arena.deinit();
    const a = arena.allocator();
    const result = try a.alloc(Query, queries);
    for (outputs, result, 0..) |output, *query, i| {
        if (output.query != i or (i > 0 and output.operation != outputs[0].operation)) return error.InvalidParentQueryLink;
        query.* = .{ .source = output.source };
    }
    const derived = try a.alloc(u32, try std.math.mul(usize, queries, try std.math.add(usize, try std.math.mul(usize, layers, 2), 1)));
    @memset(derived, missing);
    for (dg.bindings) |binding| switch (binding.source) {
        .query_position => |q| {
            if (q >= queries) return error.InvalidParentQueryLink;
            try assign(&result[q].position, binding.node_id);
        },
        .query_bit => |s| {
            if (s.query >= queries or s.bit >= 31) return error.InvalidParentQueryLink;
            try assign(&result[s.query].bits[s.bit].deep, binding.node_id);
        },
        else => {},
    };
    for (fg.bindings) |binding| switch (binding.source) {
        .query_bit => |s| {
            if (s.query >= queries or s.bit >= 31) return error.InvalidParentQueryLink;
            try assign(&result[s.query].bits[s.bit].fri, binding.node_id);
        },
        .fri_position => |s| {
            if (s.query >= queries or s.layer >= layers) return error.InvalidParentQueryLink;
            try assign(&derived[s.layer * queries * 2 + s.query], binding.node_id);
        },
        .fri_offset => |s| {
            if (s.query >= queries or s.layer >= layers) return error.InvalidParentQueryLink;
            try assign(&derived[s.layer * queries * 2 + queries + s.query], binding.node_id);
        },
        .last_layer_position => |s| {
            if (s.query >= queries) return error.InvalidParentQueryLink;
            try assign(&derived[layers * queries * 2 + s.query], binding.node_id);
        },
        else => {},
    };
    for (result) |query| {
        if (query.position == missing) return error.InvalidParentQueryLink;
        for (query.bits) |bit| if (bit.deep == missing or bit.fri == missing) return error.InvalidParentQueryLink;
    }
    for (derived) |node| if (node == missing) return error.InvalidParentQueryLink;
    return .{ .arena = arena, .queries = result, .fri_derived = derived };
}
fn assign(destination: *u32, node: u32) !void {
    if (node == missing or destination.* != missing) return error.InvalidParentQueryLink;
    destination.* = node;
}
