//! Upper adjacency/coverage constraints. All coordinates are routed from exact
//! child verifier machines or the independently selected aggregate statement.
const std = @import("std");
const G = @import("air/composition_graph_recorder.zig");
const P = @import("block_v8_window_root_public_v1.zig");
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
        if (n < 2 or n > 4 or values.children.len != n or values.extra.len != 110) return error.InvalidB8FoldGraph;
        var b = G.Builder.init(a);
        defer b.deinit();
        var sources: std.ArrayList(Scope.Wire) = .empty;
        defer sources.deinit(a);
        const child = try a.alloc([110]G.Scalar, n);
        defer a.free(child);
        for (child, 0..) |*words, i| {
            for (words, 0..) |*v, j| v.* = try input(a, &b, &sources, i, j);
        }
        var out: [110]G.Scalar = undefined;
        for (&out, 0..) |*v, j| v.* = try input(a, &b, &sources, n, j);
        try b.activate();
        defer if (b.active) b.deactivate();
        var sum = G.Scalar.zero();
        for (child, 0..) |words, i| {
            sum = sum.add(words[1]);
            for (2..10) |j| try b.constrainZero(words[j].sub(out[j]));
            if (i != 0) {
                const prev = child[i - 1];
                try b.constrainZero(prev[0].add(prev[1]).sub(words[0]));
                for (0..8) |j| try b.constrainZero(prev[18 + j].sub(words[10 + j]));
                for (0..33) |j| try b.constrainZero(prev[59 + j].sub(words[26 + j]));
                try b.constrainZero(prev[101]); // no terminal policy before last
                try b.constrainZero(words[92]); // no new initialization in middle
            }
        }
        try b.constrainZero(sum.sub(out[1]));
        try b.constrainZero(child[0][0].sub(out[0]));
        for (10..18) |j| try b.constrainZero(child[0][j].sub(out[j]));
        for (26..59) |j| try b.constrainZero(child[0][j].sub(out[j]));
        for (92..101) |j| try b.constrainZero(child[0][j].sub(out[j]));
        const last = child[n - 1];
        for (18..26) |j| try b.constrainZero(last[j].sub(out[j]));
        for (59..92) |j| try b.constrainZero(last[j].sub(out[j]));
        for (101..110) |j| try b.constrainZero(last[j].sub(out[j]));
        b.deactivate();
        return .{ .allocator = a, .circuit = try b.finish(), .sources = try sources.toOwnedSlice(a) };
    }
};
fn input(a: std.mem.Allocator, b: *G.Builder, s: *std.ArrayList(Scope.Wire), child: usize, coordinate: usize) !G.Scalar {
    const v = try b.input();
    try s.append(a, .{ .circuit = 0, .wire = 0, .uses = 1, .child = @intCast(child), .kind = .child_term, .coordinate = @intCast(coordinate) });
    return v.value;
}
