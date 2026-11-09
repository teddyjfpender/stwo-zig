//! New-profile graph owner. Algebra remains the existing QM31 builder; each
//! Poseidon output has one dedicated producer, never a guessed self-producer.
const std = @import("std");
const Core = @import("stwo_core");
const B = @import("stwo_circuit_frontend").builder;
const P = Core.crypto.poseidon2_m31_w24;
const L = @import("layout.zig");
const M = Core.fields.m31.M31;
pub const Q = Core.fields.qm31.QM31;
pub const Var = B.Var;
pub const Algebra = B.Context(Q);
pub const Usage = struct {
    allocator: std.mem.Allocator,
    counts: []u32,
    total: u64,
    max_per_wire: u32,
    pub fn deinit(self: *@This()) void {
        self.allocator.free(self.counts);
        self.* = undefined;
    }
    pub fn source(self: *const @This()) L.SourceUsage {
        return .{ .counts = self.counts, .max_per_wire = self.max_per_wire, .max_total = self.total };
    }
};
pub const Context = struct {
    allocator: std.mem.Allocator,
    base: Algebra,
    calls: std.ArrayList(L.Gate) = .empty,
    native_mul_calls: std.ArrayList(@import("native_omul/row.zig").Gate) = .empty,
    usage: ?Usage = null,
    finalized: bool = false,
    poisoned: bool = false,
    mixed_census_only: bool = false,
    pub fn init(a: std.mem.Allocator, n_outputs: usize) !Context {
        return initMode(a, n_outputs, false);
    }
    pub fn initTraceOnly(a: std.mem.Allocator, n_outputs: usize) !Context {
        return initMode(a, n_outputs, true);
    }
    fn initMode(a: std.mem.Allocator, n_outputs: usize, trace_only: bool) !Context {
        return .{ .allocator = a, .base = if (trace_only) try Algebra.initTraceOnly(a, n_outputs) else try Algebra.init(a, n_outputs) };
    }
    pub fn algebra(self: *Context) *Algebra {
        return &self.base;
    }
    pub fn deinit(self: *Context) void {
        if (self.usage) |*u| u.deinit();
        self.calls.deinit(self.allocator);
        self.native_mul_calls.deinit(self.allocator);
        self.base.deinit();
        self.* = undefined;
    }
    pub fn permute(self: *Context, inputs: [24]Var) ![24]Var {
        if (self.poisoned or self.finalized) return error.PoseidonContextClosed;
        errdefer self.poisoned = true;
        var state: P.State = @splat(M.zero());
        for (inputs, 0..) |input, i| {
            if (input.idx >= self.base.circuit.n_vars) return error.InvalidPoseidonPortAddress;
            if (!self.base.trace_only) {
                const value = self.base.get(input).toM31Array();
                for (value[1..]) |coordinate| if (!coordinate.isZero()) return error.PoseidonInputNotM31;
                state[i] = value[0];
            }
        }
        if (!self.base.trace_only) P.permute(&state);
        var outputs: [24]Var = undefined;
        var gate: L.Gate = undefined;
        for (inputs, state, &outputs, 0..) |input, value, *output, i| {
            output.* = try self.base.newVar(Q.fromBase(value));
            gate.inputs[i] = input.idx;
            gate.outputs[i] = output.idx;
        }
        try self.calls.append(self.allocator, gate);
        return outputs;
    }
    /// Opt-in R6 product. Reserved outputs have exactly one sidecar producer;
    /// they are never guessed self-yields in the generic arithmetic table.
    pub fn nativeOmul(self: *Context, inputs: [4]Var) B.context.Error![2]Var {
        if (self.poisoned or self.finalized) return error.InvalidWitnessOrigin;
        errdefer self.poisoned = true;
        for (inputs) |input| if (input.idx >= self.base.circuit.n_vars) return error.InvalidWitnessOrigin;
        const O = Core.fields.om31.OM31;
        const a = O{ .c0 = if (self.base.trace_only) Q.zero() else self.base.get(inputs[0]), .c1 = if (self.base.trace_only) Q.zero() else self.base.get(inputs[1]) };
        const b = O{ .c0 = if (self.base.trace_only) Q.zero() else self.base.get(inputs[2]), .c1 = if (self.base.trace_only) Q.zero() else self.base.get(inputs[3]) };
        const product = a.mul(b);
        const outputs = [2]Var{ try self.base.newVar(product.c0), try self.base.newVar(product.c1) };
        try self.native_mul_calls.append(self.allocator, .{ .inputs = .{ inputs[0].idx, inputs[1].idx, inputs[2].idx, inputs[3].idx }, .outputs = .{ outputs[0].idx, outputs[1].idx } });
        return outputs;
    }
    pub fn sourceMultiplicities(self: *const Context, a: std.mem.Allocator) !B.circuit.Multiplicities {
        var counts = try self.base.circuit.computeMultiplicities(a);
        errdefer counts.deinit(a);
        for (self.calls.items) |gate| {
            for (gate.inputs) |input| {
                if (input >= counts.n_uses.len) return error.InvalidPoseidonPortAddress;
                counts.n_uses[input] = try std.math.add(u32, counts.n_uses[input], 1);
            }
            for (gate.outputs) |output| {
                if (output >= counts.n_yields.len or counts.n_yields[output] != 0) return error.PoseidonProducerConflict;
                counts.n_yields[output] = 1;
            }
        }
        for (self.native_mul_calls.items) |gate| {
            for (gate.inputs) |input| {
                if (input >= counts.n_uses.len) return error.InvalidPoseidonPortAddress;
                counts.n_uses[input] = try std.math.add(u32, counts.n_uses[input], 1);
            }
            for (gate.outputs) |output| {
                if (output >= counts.n_yields.len or counts.n_yields[output] != 0) return error.PoseidonProducerConflict;
                counts.n_yields[output] = 1;
            }
        }
        return counts;
    }
    pub fn setOutputs(self: *Context, outputs: []const Var) !void {
        if (self.poisoned or self.finalized) return error.PoseidonContextClosed;
        try self.base.setOutputs(outputs);
    }
    fn requireRoster(self: *const Context, mixed: bool) !void {
        const c = &self.base.circuit;
        if (!self.base.record_gates or (!mixed and (c.blake_g_gate.items.len != 0 or c.triple_xor.items.len != 0 or c.permutation.len() != 0))) return error.UnsupportedPoseidonRosterOperation;
        if (c.n_vars >= Core.fields.m31.Modulus) return error.InvalidPoseidonSourceUsage;
        // Bound before legacy u32 counters increment, so they cannot wrap.
        const binary = try std.math.add(u64, c.add.items.len + c.sub.items.len, c.mul.items.len + c.pointwise_mul.items.len);
        var total = try std.math.add(u64, try std.math.mul(u64, 2, binary + c.eq.items.len), c.m31_to_u32.items.len + c.output.items.len);
        total = try std.math.add(u64, total, try std.math.mul(u64, L.WIDTH, self.calls.items.len));
        if (mixed) total = try std.math.add(u64, total, 6 * c.blake_g_gate.items.len + 3 * c.triple_xor.items.len + c.permutation.nTerms());
        total = try std.math.add(u64, total, try std.math.mul(u64, 6, self.native_mul_calls.items.len));
        if (total >= Core.fields.m31.Modulus) return error.InvalidPoseidonSourceUsage;
    }
    pub fn finalize(self: *Context) !void {
        return self.finalizeMode(false);
    }
    /// Diagnostic twelve-roster graph only. Explicitly refused by the five-
    /// roster Authority and census; this does not create a mixed AIR prover.
    pub fn finalizeForMixedCensus(self: *Context) !void {
        return self.finalizeMode(true);
    }
    fn finalizeMode(self: *Context, mixed: bool) !void {
        if (self.poisoned or self.finalized) return error.PoseidonContextClosed;
        errdefer self.poisoned = true;
        try self.requireRoster(mixed);
        try self.base.finalize(false);
        try self.requireRoster(mixed);
        var counts = try self.sourceMultiplicities(self.allocator);
        defer counts.deinit(self.allocator);
        for (counts.n_yields) |count| if (count != 1) return error.PoseidonMissingProducer;
        const owned = try self.allocator.dupe(u32, counts.n_uses);
        errdefer self.allocator.free(owned);
        var total: u64 = 0;
        var maximum: u32 = 0;
        for (owned) |count| {
            total = try std.math.add(u64, total, count);
            maximum = @max(maximum, count);
        }
        if (total >= Core.fields.m31.Modulus) return error.InvalidPoseidonSourceUsage;
        self.usage = .{ .allocator = self.allocator, .counts = owned, .total = total, .max_per_wire = maximum };
        self.finalized = true;
        self.mixed_census_only = mixed;
    }
    pub fn fixedRows(self: *const Context, a: std.mem.Allocator) ![]L.Fixed {
        if (!self.finalized or self.poisoned or self.usage == null) return error.PoseidonContextNotFinalized;
        const rows = try a.alloc(L.Fixed, self.calls.items.len);
        errdefer a.free(rows);
        const checked = try L.validateUsage(self.usage.?.source());
        for (rows, self.calls.items) |*row, gate| row.* = try L.fixedForValidated(gate, checked);
        return rows;
    }
    pub fn rawCounts(self: *const Context) ![L.COMPONENTS]u64 {
        if (!self.finalized or self.poisoned) return error.PoseidonContextNotFinalized;
        if (self.mixed_census_only) return error.MixedPoseidonCensusRequiresFullRoster;
        const g = self.base.gate_counts;
        return .{ g.eq, g.qm31_ops, g.m31_to_u32, self.calls.items.len, 1 << 16 };
    }
    pub fn census(self: *const Context, poseidon_hybrid: bool) !L.Census {
        return L.census(try self.rawCounts(), poseidon_hybrid);
    }
    pub fn isCircuitValid(self: *const Context) !bool {
        if (!self.finalized or self.poisoned or self.base.trace_only) return error.PoseidonContextNotFinalized;
        if (!try self.base.isCircuitValid()) return false;
        for (self.calls.items) |gate| {
            var state: P.State = undefined;
            for (gate.inputs, 0..) |input, i| {
                const value = self.base.get(.{ .idx = input }).toM31Array();
                for (value[1..]) |coordinate| if (!coordinate.isZero()) return false;
                state[i] = value[0];
            }
            P.permute(&state);
            for (gate.outputs, state) |output, value| if (!self.base.get(.{ .idx = output }).eql(Q.fromBase(value))) return false;
        }
        for (self.native_mul_calls.items) |gate| {
            const O = Core.fields.om31.OM31;
            const a = O{ .c0 = self.base.get(.{ .idx = gate.inputs[0] }), .c1 = self.base.get(.{ .idx = gate.inputs[1] }) };
            const b = O{ .c0 = self.base.get(.{ .idx = gate.inputs[2] }), .c1 = self.base.get(.{ .idx = gate.inputs[3] }) };
            const product = a.mul(b);
            if (!self.base.get(.{ .idx = gate.outputs[0] }).eql(product.c0) or !self.base.get(.{ .idx = gate.outputs[1] }).eql(product.c1)) return false;
        }
        return true;
    }
};
test "new Poseidon graph has one producer per output and authenticated source fanout including repeated consumers" {
    const a = std.testing.allocator;
    var ctx = try Context.init(a, 1);
    defer ctx.deinit();
    var inputs: [24]Var = undefined;
    for (&inputs, 0..) |*value, i| value.* = try ctx.algebra().guess(Q.fromU32Unchecked(@intCast(i + 1), 0, 0, 0));
    const outputs = try ctx.permute(inputs);
    _ = try ctx.algebra().add(outputs[3], outputs[3]);
    try ctx.setOutputs(&.{outputs[3]});
    try ctx.finalize();
    try std.testing.expect(try ctx.isCircuitValid());
    const rows = try ctx.fixedRows(a);
    defer a.free(rows);
    try std.testing.expectEqual(@as(u32, 3), rows[0][L.OUTPUT_USES + 3].v);
    ctx.base.value_table.items[outputs[3].idx] = ctx.base.value_table.items[outputs[3].idx].add(Q.one());
    try std.testing.expect(!try ctx.isCircuitValid());
}
test "Poseidon graph trace-only topology matches value mode and rejects orphan and legacy hash operations" {
    const a = std.testing.allocator;
    var ctx = try Context.initTraceOnly(a, 0);
    defer ctx.deinit();
    const inputs = [_]Var{ctx.algebra().zero()} ** 24;
    _ = try ctx.permute(inputs);
    try ctx.finalize();
    const rows = try ctx.fixedRows(a);
    defer a.free(rows);
    try std.testing.expectEqual(@as(usize, 1), rows.len);
    var orphan = try Context.init(a, 0);
    defer orphan.deinit();
    _ = try orphan.algebra().newVar(Q.zero());
    try std.testing.expectError(error.PoseidonMissingProducer, orphan.finalize());
    var legacy = try Context.init(a, 0);
    defer legacy.deinit();
    _ = try B.blake.blake2s(Q, legacy.algebra(), &.{}, 0);
    try std.testing.expectError(error.UnsupportedPoseidonRosterOperation, legacy.finalize());
}
