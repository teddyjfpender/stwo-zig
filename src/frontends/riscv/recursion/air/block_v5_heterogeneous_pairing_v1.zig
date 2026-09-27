//! Pairing equations select cells from the ORIGINAL authenticated transcript.
//! No copied root field/classifier matrix. This graph must be routed by the
//! enclosing parent arithmetic/public supply before it conveys proof authority.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const r = @import("composition_graph_recorder.zig");
const Policy = @import("../block_v5_heterogeneous_policy_v1.zig").Policy;
const Frames = @import("../block_v5_heterogeneous_child_frames_v1.zig");
pub const Source = struct { child: u32, cell: u32, part: u2 };
pub const Pair = struct { left: u32, right: u32, left_cell: u32, right_cell: u32 };
pub const Prepared = struct {
    allocator: std.mem.Allocator,
    circuit: r.Circuit,
    inputs: []Q,
    sources: []Source,
    values: []Q,
    pub fn deinit(self: *Prepared) void {
        self.circuit.deinit();
        self.allocator.free(self.inputs);
        self.allocator.free(self.sources);
        self.allocator.free(self.values);
        self.* = undefined;
    }
};
pub fn pairs(a: std.mem.Allocator, policy: Policy) ![]Pair {
    try policy.validate();
    var out: std.ArrayList(Pair) = .empty;
    errdefer out.deinit(a);
    for (policy.children, 0..) |*child, right| if (child.link) |link| {
        if (child.physical.kind == .native_arithmetic) continue;
        const left_child = try policy.find(if (child.physical.kind == .native_fused or child.physical.kind == .caller_arithmetic) .native_arithmetic else .caller_arithmetic, child.physical.index);
        const left = (@intFromPtr(left_child) - @intFromPtr(policy.children.ptr)) / @sizeOf(Frames.Child);
        try addRoot(a, &out, policy.children, @intCast(left), @intCast(right), link.execution);
        try addRoot(a, &out, policy.children, @intCast(left), @intCast(right), child.source_seal);
        if (child.physical.kind != .caller_arithmetic) {
            for (link.roots) |root| try addRoot(a, &out, policy.children, @intCast(left), @intCast(right), root);
            if (link.caller_key) |root| try addRoot(a, &out, policy.children, @intCast(left), @intCast(right), root);
            if (link.caller_instance) |root| try addRoot(a, &out, policy.children, @intCast(left), @intCast(right), root);
        }
    };
    return out.toOwnedSlice(a);
}
fn addRoot(a: std.mem.Allocator, out: *std.ArrayList(Pair), children: []const Frames.Child, left: u32, right: u32, root: [32]u8) !void {
    try out.append(a, .{ .left = left, .right = right, .left_cell = try children[left].rootCells(root), .right_cell = try children[right].rootCells(root) });
}
pub fn prepare(a: std.mem.Allocator, policy: Policy) !Prepared {
    const selected = try pairs(a, policy);
    defer a.free(selected);
    return preparePairs(a, policy.children, selected);
}
fn preparePairs(a: std.mem.Allocator, children: []const Frames.Child, selected: []const Pair) !Prepared {
    var builder = r.Builder.init(a);
    defer builder.deinit();
    const count = try std.math.mul(usize, selected.len, 64);
    const inputs = try a.alloc(Q, count);
    errdefer a.free(inputs);
    const sources = try a.alloc(Source, count);
    errdefer a.free(sources);
    const symbolic = try a.alloc(r.Scalar, count);
    defer a.free(symbolic);
    var at: usize = 0;
    for (selected) |pair| {
        if (pair.left >= children.len or pair.right >= children.len or children[pair.left].cells.len < 8 or children[pair.right].cells.len < 8 or pair.left_cell > children[pair.left].cells.len - 8 or pair.right_cell > children[pair.right].cells.len - 8) return error.InvalidHeterogeneousPairing;
        for (0..8) |word| for (0..4) |part| {
            for ([_]u32{ pair.left, pair.right }, [_]u32{ pair.left_cell, pair.right_cell }) |child, cell| {
                const value = children[child].cells[cell + word][part];
                if (value.v >= core.fields.m31.Modulus) return error.NoncanonicalHeterogeneousChild;
                inputs[at] = Q.fromBase(value);
                sources[at] = .{ .child = child, .cell = cell + @as(u32, @intCast(word)), .part = @intCast(part) };
                symbolic[at] = (try builder.input()).value;
                at += 1;
            }
        };
    }
    try builder.activate();
    defer if (builder.active) builder.deactivate();
    var i: usize = 0;
    while (i < symbolic.len) : (i += 2) try builder.constrainZero(symbolic[i].sub(symbolic[i + 1]));
    if (symbolic.len == 0) try builder.constrainZero(r.Scalar.zero());
    builder.deactivate();
    var circuit = try builder.finish();
    errdefer circuit.deinit();
    const values = try a.alloc(Q, circuit.nodes.len);
    errdefer a.free(values);
    try circuit.evaluateInto(inputs, values);
    return .{ .allocator = a, .circuit = circuit, .inputs = inputs, .sources = sources, .values = values };
}
pub const testing = if (@import("builtin").is_test) struct {
    pub const record = preparePairs;
} else struct {};
