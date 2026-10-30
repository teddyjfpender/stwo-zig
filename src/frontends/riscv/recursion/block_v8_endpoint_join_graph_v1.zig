//! Exact endpoint root rebinding, CPU chain and late-global algebraic closure.
const std = @import("std");
const core = @import("stwo_core");
const G = @import("air/composition_graph_recorder.zig");
const P = @import("block_v8_endpoint_join_public_v1.zig");
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
        if (values.children.len != n + 2 or n == 0 or values.extra.len != 264) return error.InvalidEndpointJoinGraph;
        var b = G.Builder.init(a);
        defer b.deinit();
        var sources: std.ArrayList(Scope.Wire) = .empty;
        defer sources.deinit(a);
        var sums: std.ArrayList(G.Scalar) = .empty;
        defer sums.deinit(a);
        const bridge = n;
        const global = n + 1;
        try sums.append(a, try input(a, &b, &sources, global, .child_term, 0));
        for (0..n) |i| try sums.append(a, try input(a, &b, &sources, bridge, .child_term, i));
        // Each digest word is four exact byte limbs in a QM31 cell; equality is exact.
        var pairs: std.ArrayList([2]G.Scalar) = .empty;
        defer pairs.deinit(a);
        for (0..n) |i| for (0..8) |word| try pairs.append(a, .{ try input(a, &b, &sources, i, .child_cell, 16 + word), try input(a, &b, &sources, bridge, .child_cell, 8 * (1 + i) + word) });
        for (0..n) |i| {
            const base = values.children[i].public.len - 416;
            const next_base = if (i + 1 < n) values.children[i + 1].public.len - 416 else 0;
            for (0..4) |byte| {
                if (i == 0) try pairs.append(a, .{ try input(a, &b, &sources, i, .child_term, base + byte), try input(a, &b, &sources, n + 2, .child_term, byte) });
                try pairs.append(a, .{ try input(a, &b, &sources, i, .child_term, base + 4 + byte), try input(a, &b, &sources, if (i + 1 < n) i + 1 else n + 2, .child_term, if (i + 1 < n) next_base + byte else 132 + byte) });
            }
            for (0..32) |reg| for (0..4) |byte| {
                if (i == 0) try pairs.append(a, .{ try input(a, &b, &sources, i, .child_term, base + 4 * (3 + reg) + byte), try input(a, &b, &sources, n + 2, .child_term, 4 * (1 + reg) + byte) });
                try pairs.append(a, .{ try input(a, &b, &sources, i, .child_term, base + 4 * (35 + reg) + byte), try input(a, &b, &sources, if (i + 1 < n) i + 1 else n + 2, .child_term, if (i + 1 < n) next_base + 4 * (3 + reg) + byte else 132 + 4 * (1 + reg) + byte) });
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
