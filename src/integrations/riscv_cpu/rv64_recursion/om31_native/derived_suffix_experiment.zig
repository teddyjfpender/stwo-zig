// Diagnostic-only exact copy of candidate derivation/build functions. Not a production mode.
//! Candidate generation-only constant suffix inferred from the original FULL
//! Circuit. No context hooks, alternate AIR or implicit tail-zero assumption.
const std = @import("std");
const Circuit = @import("stwo_circuit_frontend");
const Q = @import("stwo_core").fields.qm31.QM31;
const Schedule = Circuit.builder.witness_plan;
pub const Range = extern struct { first: u32 = 0, count: u32 = 0, value: u32 = 0, reserved: u32 = 0 };
pub const Tail = struct {
    full: u32,
    prefix: u32,
    add: usize,
    triple: usize,
    m31: usize,
    blake: usize,
    count: u32 = 0,
    ranges: [4]Range = @splat(.{}),
    pub fn build(self: Tail, a: std.mem.Allocator, ctx: *const Circuit.builder.Context(Q), metrics: ?*Schedule.BuildMetrics) !Schedule.Plan {
        var prefix = ctx.*;
        prefix.circuit.n_vars = self.prefix;
        prefix.circuit.add.items = prefix.circuit.add.items[0..self.add];
        prefix.circuit.triple_xor.items = prefix.circuit.triple_xor.items[0..self.triple];
        prefix.circuit.m31_to_u32.items = prefix.circuit.m31_to_u32.items[0..self.m31];
        prefix.circuit.blake_g_gate.items = prefix.circuit.blake_g_gate.items[0..self.blake];
        // Borrowed header only; NEVER deinit. Existing producer/input checks
        // reject references from retained arithmetic into the removed suffix.
        return Schedule.buildProfiled(a, &prefix, metrics);
    }
};
pub fn derive(ctx: *const Circuit.builder.Context(Q)) !Tail {
    if (!ctx.finalized or !ctx.record_gates or ctx.witness_metadata == null) return error.WitnessOriginsRequired;
    const zero = ctx.constants.get(Circuit.builder.context.constantKey(Q.zero())) orelse return error.InvalidSuffixConstants;
    const one = ctx.constants.get(Circuit.builder.context.constantKey(Q.one())) orelse return error.InvalidSuffixConstants;
    if (zero.idx != 0 or one.idx != 1) return error.InvalidSuffixConstants;
    const c = &ctx.circuit;
    var t = Tail{ .full = c.n_vars, .prefix = c.n_vars, .add = c.add.items.len, .triple = c.triple_xor.items.len, .m31 = c.m31_to_u32.items.len, .blake = c.blake_g_gate.items.len };
    const before_blake = t.prefix;
    while (t.blake != 0) {
        const gate = c.blake_g_gate.items[t.blake - 1];
        if (t.prefix < 7 or gate.out_base != t.prefix - 4 or !std.mem.allEqual(u32, &gate.inputs(), 0)) break;
        t.prefix -= 4;
        t.blake -= 1;
    }
    const before_m31 = t.prefix;
    while (t.m31 != 0) {
        const gate = c.m31_to_u32.items[t.m31 - 1];
        if (t.prefix <= 3 or gate.out != t.prefix - 1 or gate.input != 0) break;
        t.prefix -= 1;
        t.m31 -= 1;
    }
    const before_triple = t.prefix;
    while (t.triple != 0) {
        const gate = c.triple_xor.items[t.triple - 1];
        if (t.prefix <= 3 or gate.out != t.prefix - 1 or gate.input_a != 0 or gate.input_b != 0 or gate.input_c != 0) break;
        t.prefix -= 1;
        t.triple -= 1;
    }
    const before_add = t.prefix;
    while (t.add != 0) {
        const gate = c.add.items[t.add - 1];
        if (t.prefix <= 3 or gate.out != t.prefix - 1 or gate.in0 != 1 or gate.in1 != 1) break;
        t.prefix -= 1;
        t.add -= 1;
    }
    if (t.prefix < 3) return error.InvalidSuffixBounds;
    // Forward order is the original padding order. Coverage is exact, and
    // every removed writer was individually checked above.
    for ([_]Range{ .{ .first = t.prefix, .count = before_add - t.prefix, .value = 2 }, .{ .first = before_add, .count = before_triple - before_add }, .{ .first = before_triple, .count = before_m31 - before_triple }, .{ .first = before_m31, .count = before_blake - before_m31 } }) |range| {
        if (range.count != 0) {
            t.ranges[t.count] = range;
            t.count += 1;
        }
    }
    if (t.count == 0) return t;
    for (ctx.constants.values()) |v| if (v.idx >= t.prefix) return error.UnsafeSuffixReference;
    for (ctx.circuit.output.items) |v| if (v >= t.prefix) return error.UnsafeSuffixReference;
    for (ctx.circuit.eq.items) |gate| if (gate.in0 >= t.prefix or gate.in1 >= t.prefix) return error.UnsafeSuffixReference;
    for (ctx.circuit.permutation.inputs.items) |v| if (v >= t.prefix) return error.UnsafeSuffixReference;
    for (ctx.circuit.permutation.outputs.items) |v| if (v >= t.prefix) return error.UnsafeSuffixReference;
    for (ctx.witness_metadata.?.origins.items, 0..) |origin, index| {
        if (origin.out >= t.prefix) return error.UnsafeSuffixReference;
        if (origin.kind == .seed) continue;
        var buf: [6]u32 = undefined;
        for (Schedule.inputs(ctx, .{ .kind = .hint, .index = @intCast(index) }, &buf)) |v| if (v >= t.prefix) return error.UnsafeSuffixReference;
    }
    return t;
}
