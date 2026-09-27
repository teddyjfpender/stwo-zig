//! Full-width span equation kernel. Inputs are original authenticated bytes;
//! every carry is Boolean and every limb equation is below M31's modulus.
//! This alone provides no source/leaf authority and does not widen old grammar.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const R = @import("composition_graph_recorder.zig");
pub const Bytes = [8]u8;
pub fn encode(value: u64) Bytes {
    var result: Bytes = undefined;
    std.mem.writeInt(u64, &result, value, .little);
    return result;
}
fn limbs(comptime S: type, bytes: [8]S) [4]S {
    var result: [4]S = undefined;
    for (&result, 0..) |*value, i| value.* = bytes[2 * i].add(bytes[2 * i + 1].mul(S.fromBase(M.fromCanonical(256))));
    return result;
}
/// No full u32/u64 is converted to a base-field element. A 16-bit limb plus
/// carry lies in [-65536,65536], making each field equality an integer equality
/// given the independently authenticated canonical byte inputs.
pub fn increment(comptime S: type, sink: anytype, left: [8]S, right: [8]S, carry_values: [4]S) !void {
    const a = limbs(S, left);
    const b = limbs(S, right);
    var previous = S.one();
    for (a, b, carry_values) |lower, upper, carry| {
        try sink.zero(carry.mul(carry.sub(S.one())), error.NonbooleanRecursiveCycleCarry);
        try sink.zero(lower.add(previous).sub(upper).sub(carry.mul(S.fromBase(M.fromCanonical(65536)))), error.UnclosedRecursiveCycleAdjacency);
        previous = carry;
    }
    try sink.zero(previous, error.RecursiveCycleOverflow);
}
pub fn equal(comptime S: type, sink: anytype, left: [8]S, right: [8]S) !void {
    for (left, right) |a, b| try sink.zero(a.sub(b), error.UnclosedRecursiveCycleBoundary);
}
pub fn carries(value: u64) ![4]u8 {
    if (value == std.math.maxInt(u64)) return error.RecursiveCycleOverflow;
    var result: [4]u8 = undefined;
    var previous: u32 = 1;
    for (&result, 0..) |*carry, i| {
        const limb: u32 = @intCast((value >> @as(u6, @intCast(16 * i))) & 65535);
        previous = (limb + previous) >> 16;
        carry.* = @intCast(previous);
    }
    return result;
}
const ScalarSink = struct {
    builder: *R.Builder,
    pub fn zero(self: *@This(), value: R.Scalar, _: anyerror) !void {
        try self.builder.constrainZero(value);
    }
};
pub const Graph = struct {
    a: std.mem.Allocator,
    circuit: R.Circuit,
    inputs: [20]Q,
    values: []Q,
    pub const source_authority_pending = true;
    pub fn deinit(self: *Graph) void {
        self.circuit.deinit();
        self.a.free(self.values);
        self.* = undefined;
    }
};
/// A recorder/source adapter must attach the first 16 inputs to actual lower
/// public bytes and the four carry inputs to constrained witness columns.
/// This graph is never itself a Verified capture or a whole-span receipt.
pub fn record(a: std.mem.Allocator, left: Bytes, right: Bytes, proposed_carries: [4]u8) !Graph {
    var builder = R.Builder.init(a);
    defer builder.deinit();
    var inputs: [20]Q = undefined;
    var symbols: [20]R.Scalar = undefined;
    for (&inputs, &symbols, 0..) |*value, *symbol, i| {
        const byte = if (i < 8) left[i] else if (i < 16) right[i - 8] else proposed_carries[i - 16];
        value.* = Q.fromBase(M.fromCanonical(byte));
        symbol.* = (try builder.input()).value;
    }
    try builder.activate();
    defer if (builder.active) builder.deactivate();
    var sink = ScalarSink{ .builder = &builder };
    try increment(R.Scalar, &sink, symbols[0..8].*, symbols[8..16].*, symbols[16..20].*);
    builder.deactivate();
    var circuit = try builder.finish();
    errdefer circuit.deinit();
    const values = try a.alloc(Q, circuit.nodes.len);
    errdefer a.free(values);
    try circuit.evaluateInto(&inputs, values);
    return .{ .a = a, .circuit = circuit, .inputs = inputs, .values = values };
}
