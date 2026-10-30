//! Exact endpoint root rebinding, CPU chain and late-global algebraic closure.
const std = @import("std");
const core = @import("stwo_core");
const G = @import("air/composition_graph_recorder.zig");
const P = @import("block_v8_endpoint_group_join_public_v1.zig");
const Scope = @import("block_v5_heterogeneous_scoped_public_bus_v1.zig");
pub const Owned = struct {
    allocator: std.mem.Allocator,
    circuit: G.Circuit,
    sources: []Scope.Wire,
    pub fn deinit(v: *Owned) void {
        v.circuit.deinit();
        v.allocator.free(v.sources);
    }
    pub fn compile(a: std.mem.Allocator, values: P.Values, n: usize) !Owned {
        if (values.children.len != 3 or n == 0 or n > 32 or values.children[0].public.len < 416 * n or values.children[0].roots_count != 2 * n + 4 or values.extra.len != 264) return error.InvalidEndpointJoinGraph;
        var b = G.Builder.init(a);
        defer b.deinit();
        var sources: std.ArrayList(Scope.Wire) = .empty;
        defer sources.deinit(a);
        var sums: std.ArrayList(G.Scalar) = .empty;
        defer sums.deinit(a);
        const bridge = 1;
        const global = 2;
        try sums.append(a, try input(a, &b, &sources, global, .child_term, 0));
        for (0..n) |i| try sums.append(a, try input(a, &b, &sources, bridge, .child_term, i));
        // Each digest word is four exact byte limbs in a QM31 cell; equality is exact.
        var pairs: std.ArrayList([2]G.Scalar) = .empty;
        defer pairs.deinit(a);
        for (0..n) |i| for (0..8) |word| try pairs.append(a, .{ try input(a, &b, &sources, 0, .child_cell, 8 * (n + 1 + i) + word), try input(a, &b, &sources, bridge, .child_cell, 8 * (1 + i) + word) });
        for (0..n) |i| {
            const base = values.children[0].public.len - 416 * n + 416 * i;
            const next_base = base + 416;
            for (0..4) |byte| {
                if (i == 0) try pairs.append(a, .{ try input(a, &b, &sources, 0, .child_term, base + byte), try input(a, &b, &sources, 3, .child_term, byte) });
                try pairs.append(a, .{ try input(a, &b, &sources, 0, .child_term, base + 4 + byte), try input(a, &b, &sources, if (i + 1 < n) @as(usize, 0) else 3, .child_term, if (i + 1 < n) next_base + byte else 132 + byte) });
            }
            for (0..32) |reg| for (0..4) |byte| {
                if (i == 0) try pairs.append(a, .{ try input(a, &b, &sources, 0, .child_term, base + 4 * (3 + reg) + byte), try input(a, &b, &sources, 3, .child_term, 4 * (1 + reg) + byte) });
                try pairs.append(a, .{ try input(a, &b, &sources, 0, .child_term, base + 4 * (35 + reg) + byte), try input(a, &b, &sources, if (i + 1 < n) @as(usize, 0) else 3, .child_term, if (i + 1 < n) next_base + 4 * (3 + reg) + byte else 132 + 4 * (1 + reg) + byte) });
            };
        }
        try b.activate();
        defer if (b.active) b.deactivate();
        var sum = G.Scalar.zero();
        for (sums.items) |v| sum = sum.add(v);
        try b.constrainZero(sum);
        for (pairs.items) |pair| try b.constrainZero(pair[0].sub(pair[1]));
        b.deactivate();
        return .{ .allocator = a, .circuit = try b.finish(), .sources = try sources.toOwnedSlice(a) };
    }
};
fn input(a: std.mem.Allocator, b: *G.Builder, out: *std.ArrayList(Scope.Wire), child: usize, kind: Scope.Kind, coordinate: usize) !G.Scalar {
    const v = try b.input();
    try out.append(a, .{ .circuit = 0, .wire = 0, .uses = 1, .child = @intCast(child), .kind = kind, .coordinate = @intCast(coordinate) });
    return v.value;
}
