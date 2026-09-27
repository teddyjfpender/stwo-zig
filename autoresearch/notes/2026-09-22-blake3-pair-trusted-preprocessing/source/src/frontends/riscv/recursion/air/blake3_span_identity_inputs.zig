//! Canonical scalar-to-byte preparation for Span identity hashing.
//! Source node IDs and circuit IDs are verifier-owned. The caller must add
//! source_uses to its authenticated scalar emissions; this is not a source proof.
const std = @import("std");
const core = @import("stwo_core");
const identity = @import("../span_identity_blake3.zig");
const routing = @import("blake3_span_identity_route.zig");
const pack = @import("qm31_pack_wire.zig");
const encoding = @import("blake3_field_bytes.zig");
const N = @typeInfo(identity.StatementWords).array.len;
const GROUPS = (N + 3) / 4;
pub const Circuits = struct { scalar: u32, packing: u32, bytes: u32, hash: u32 };
pub const Plan = struct {
    routes: routing.Plan,
    packing: [GROUPS]pack.Schedule,
    encoding: [GROUPS]encoding.Schedule,
    source_uses: [N]u32,
    pub fn deinit(self: *Plan) void {
        self.routes.deinit();
        self.* = undefined;
    }
};
pub const Rows = struct {
    packing: [GROUPS]pack.Row,
    encoding: [GROUPS]encoding.Row,
};

pub fn build(a: std.mem.Allocator, purpose: identity.Purpose, circuits: Circuits, nodes: *const [N]u32) !Plan {
    const ids = [_]u32{ circuits.scalar, circuits.packing, circuits.bytes, circuits.hash };
    for (ids, 0..) |id, i| {
        if (id >= core.fields.m31.Modulus) return error.InvalidSpanIdentityCircuits;
        for (ids[0..i]) |earlier| if (earlier == id) return error.InvalidSpanIdentityCircuits;
    }
    // Duplicate scalar node assignments would erase statement-position binding.
    for (nodes, 0..) |node, i| {
        if (node >= core.fields.m31.Modulus) return error.InvalidSpanIdentityNodes;
        for (nodes[0..i]) |earlier| if (earlier == node) return error.InvalidSpanIdentityNodes;
    }
    var result: Plan = undefined;
    result.routes = try routing.build(a, purpose, .{ .circuit = circuits.bytes, .first_wire = 0 }, circuits.hash);
    errdefer result.routes.deinit();
    result.source_uses = @splat(0);
    for (0..GROUPS) |group| {
        var source_nodes: [4]u32 = undefined;
        var uses: [4]u32 = @splat(0);
        for (0..4) |coordinate| {
            const index = @min(group * 4 + coordinate, N - 1);
            source_nodes[coordinate] = nodes[index];
            result.source_uses[index] += 1;
            if (group * 4 + coordinate < N) uses[coordinate] = result.routes.statement_uses[index];
        }
        result.packing[group] = .{ .source_circuit = circuits.scalar, .source_nodes = source_nodes, .destination_circuit = circuits.packing, .destination_wire = @intCast(group) };
        result.encoding[group] = .{ .source_circuit = circuits.packing, .source_wire = @intCast(group), .destination_circuit = circuits.bytes, .destination_first = @intCast(group * 4), .uses = uses };
        _ = try pack.fixedRow(result.packing[group]);
        _ = try encoding.fixedRow(result.encoding[group]);
    }
    return result;
}

/// Last-group padding repeats the last authenticated scalar, with zero byte
/// fanout. Its extra scalar consumes are explicitly included in source_uses.
pub fn prepare(plan: *const Plan, words: *const identity.StatementWords) !Rows {
    var result: Rows = undefined;
    for (0..GROUPS) |group| {
        var coordinates: [4]core.fields.m31.M31 = undefined;
        for (&coordinates, 0..) |*coordinate, i| coordinate.* = words[@min(group * 4 + i, N - 1)];
        const value = core.fields.qm31.QM31.fromM31Array(coordinates);
        result.packing[group] = try pack.logicalRow(plan.packing[group], value);
        result.encoding[group] = try encoding.logicalRow(plan.encoding[group], value);
    }
    return result;
}

/// Fixed schedules only: no native field serialization or private inverses.
pub fn trusted(plan: *const Plan) !Rows {
    var rows: Rows = undefined;
    for (0..GROUPS) |group| {
        rows.packing[group] = try pack.fixedRow(plan.packing[group]);
        rows.encoding[group] = try encoding.fixedRow(plan.encoding[group]);
    }
    return rows;
}
