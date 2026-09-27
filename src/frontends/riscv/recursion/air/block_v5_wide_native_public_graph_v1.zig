//! Same-parent original B5PD byte equality and full-width count/span equations.
//! Exact source cells belong to the NEW enclosing public grammar. Original
//! child channel replay remains unchanged. Source/block completeness is OPEN.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const R = @import("composition_graph_recorder.zig");
const Wide = @import("block_v5_recursive_u64_span_v1.zig");
const Public = @import("../block_v5_wide_native_public_values_v1.zig");
pub const Source = struct { cell: u32, part: u2 };
pub const INPUT_COUNT: usize = 96;
pub const Parts = struct { original_digest: [32]u8, expected_digest: [32]u8, first: [8]u8, last: [8]u8, clock: [4]u8, steps: [4]u8, add_carries: [4]u8, increment_carries: [4]u8 };
fn limbs(comptime S: type, input: [8]S) [4]S {
    var out: [4]S = undefined;
    for (&out, 0..) |*value, index| value.* = input[2 * index].add(input[2 * index + 1].mul(S.fromBase(M.fromCanonical(256))));
    return out;
}
pub fn add(comptime S: type, sink: anytype, left: [8]S, right: [8]S, result: [8]S, carry_values: [4]S) !void {
    const a = limbs(S, left);
    const b = limbs(S, right);
    const output = limbs(S, result);
    var previous = S.zero();
    for (a, b, output, carry_values) |x, y, z, carry| {
        try sink.zero(carry.mul(carry.sub(S.one())), error.NonbooleanWideNativeCarry);
        try sink.zero(x.add(y).add(previous).sub(z).sub(carry.mul(S.fromBase(M.fromCanonical(65536)))), error.UnclosedWideNativeSpan);
        previous = carry;
    }
    try sink.zero(previous, error.WideNativeSpanOverflow);
}
const Sink = struct {
    builder: *R.Builder,
    pub fn zero(self: *@This(), value: R.Scalar, _: anyerror) !void {
        try self.builder.check();
        try self.builder.constrainZero(value);
    }
};
pub const Prepared = struct {
    allocator: std.mem.Allocator,
    circuit: R.Circuit,
    inputs: [INPUT_COUNT]Q,
    values: []Q,
    sources: [INPUT_COUNT]Source,
    pub const complete_source_authority = false;
    pub const requires_new_parent_key = true;
    pub fn deinit(self: *Prepared) void {
        self.circuit.deinit();
        self.allocator.free(self.values);
        self.* = undefined;
    }
    pub fn validate(self: *const Prepared, public: anytype) !void {
        try public.validate();
        try self.circuit.validate();
        if (self.circuit.input_count != INPUT_COUNT or self.values.len != self.circuit.nodes.len) return error.InvalidWideNativeGraph;
        // Equal byte values at unrelated coordinates do not establish source
        // authority. Reconstruct the normative recipe and every descriptor.
        var expected = try prepare(self.allocator, public);
        defer expected.deinit();
        if (!std.meta.eql(self.sources, expected.sources) or !std.meta.eql(self.circuit.identity_digest, expected.circuit.identity_digest)) return error.UntrustedWideNativeGraphInput;
        for (self.inputs, self.sources) |value, source| if (!value.eql(Q.fromBase((try public.cell(source.cell))[source.part]))) return error.UntrustedWideNativeGraphInput;
        const checked = try self.allocator.alloc(Q, self.values.len);
        defer self.allocator.free(checked);
        try self.circuit.evaluateInto(&self.inputs, checked);
        for (checked, self.values) |actual, retained| if (!actual.eql(retained)) return error.MutatedWideNativeGraph;
    }
};
/// Recorder helper only, no receipt/child admission. The production prepare
/// below independently derives all fields and exact public source descriptors.
pub fn record(a: std.mem.Allocator, parts: Parts, sources: [INPUT_COUNT]Source) !Prepared {
    var builder = R.Builder.init(a);
    defer builder.deinit();
    const all = parts.original_digest ++ parts.expected_digest ++ parts.first ++ parts.last ++ parts.clock ++ parts.steps ++ parts.add_carries ++ parts.increment_carries;
    var inputs: [INPUT_COUNT]Q = undefined;
    var symbols: [INPUT_COUNT]R.Scalar = undefined;
    for (all, &inputs, &symbols) |byte, *value, *symbol| {
        value.* = Q.fromBase(M.fromCanonical(byte));
        symbol.* = (try builder.input()).value;
    }
    try builder.activate();
    defer if (builder.active) builder.deactivate();
    var sink = Sink{ .builder = &builder };
    for (symbols[0..32], symbols[32..64]) |original, expected| try sink.zero(original.sub(expected), error.UntrustedWideNativeDigestSource);
    const first = symbols[64..72].*;
    const last = symbols[72..80].*;
    var clock: [8]R.Scalar = @splat(R.Scalar.zero());
    var steps: [8]R.Scalar = @splat(R.Scalar.zero());
    @memcpy(clock[0..4], symbols[80..84]);
    @memcpy(steps[0..4], symbols[84..88]);
    try Wide.increment(R.Scalar, &sink, steps, clock, symbols[92..96].*);
    try add(R.Scalar, &sink, first, steps, last, symbols[88..92].*);
    builder.deactivate();
    var circuit = try builder.finish();
    errdefer circuit.deinit();
    const values = try a.alloc(Q, circuit.nodes.len);
    errdefer a.free(values);
    try circuit.evaluateInto(&inputs, values);
    return .{ .allocator = a, .circuit = circuit, .inputs = inputs, .values = values, .sources = sources };
}
fn take(public: anytype, coordinate: Public.Coordinate, out: []u8, sources: []Source) !void {
    if (out.len != sources.len or out.len != 4 * @as(usize, coordinate.word_count)) return error.InvalidWideNativeGraph;
    for (out, sources, 0..) |*byte, *source, index| {
        source.* = .{ .cell = coordinate.first_cell + @as(u32, @intCast(index / 4)), .part = @intCast(index % 4) };
        byte.* = @intCast((try public.cell(source.cell))[source.part].v);
    }
}
pub fn prepare(a: std.mem.Allocator, public: anytype) !Prepared {
    try public.validate();
    var parts: Parts = undefined;
    var sources: [INPUT_COUNT]Source = undefined;
    try take(public, try public.originalDigest(), &parts.original_digest, sources[0..32]);
    try take(public, try public.expectedDigest(), &parts.expected_digest, sources[32..64]);
    try take(public, try public.firstCycle(), &parts.first, sources[64..72]);
    try take(public, try public.lastCycle(), &parts.last, sources[72..80]);
    try take(public, try public.clock(), &parts.clock, sources[80..84]);
    const auxiliary = try public.auxFirst();
    try take(public, .{ .first_cell = auxiliary, .word_count = 1 }, &parts.steps, sources[84..88]);
    for (&parts.add_carries, &parts.increment_carries, 0..) |*carry, *increment, index| {
        sources[88 + index] = .{ .cell = auxiliary + 1 + @as(u32, @intCast(index)), .part = 0 };
        carry.* = @intCast((try public.cell(sources[88 + index].cell))[0].v);
        sources[92 + index] = .{ .cell = auxiliary + 5 + @as(u32, @intCast(index)), .part = 0 };
        increment.* = @intCast((try public.cell(sources[92 + index].cell))[0].v);
    }
    return record(a, parts, sources);
}
