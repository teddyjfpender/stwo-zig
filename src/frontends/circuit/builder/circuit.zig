//! The circuit: per-kind gate lists over QM31 variables.
//!
//! Port of `crates/circuits/src/circuit.rs` (https://github.com/starkware-libs/proving
//! at 5a7c5ede4299c91a61df19a07cba4f7502c14230). Semantics are upstream's;
//! only the representation differs:
//!
//! - variables are `u32` indices (upstream `usize`), and a circuit holds fewer
//!   than 2^31 of them so that addresses fit M31 columns;
//! - `BlakeGGate` keeps its four outputs as `out_base + {0,1,2,3}`, because
//!   the builder always allocates them as four consecutive variables
//!   (`crates/circuits/src/blake.rs:407-410`); `blake_g_gate` asserts this;
//! - the permutations share three flat lists (CSR form) instead of one pair of
//!   vectors per gate.
//!
//! Each kind keeps its gates in append order. `Circuit::all_gates` order
//! (add, sub, mul, pointwise_mul, eq, blake_g_gate, triple_xor, m31_to_u32,
//! permutation, output) is the order of `check` and of the `Debug` text.

const std = @import("std");
const stwo_core = @import("stwo_core");
const ivalue = @import("ivalue.zig");
const blake = @import("blake.zig");
const debug_format = @import("debug_format.zig");

const Allocator = std.mem.Allocator;
const QM31 = stwo_core.fields.qm31.QM31;

/// A circuit variable: an index into the circuit's value table.
pub const Var = packed struct(u32) {
    idx: u32,

    /// Upstream `Debug`: `[idx]`.
    pub fn format(self: Var, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try writer.print("[{d}]", .{self.idx});
    }
};

/// The exclusive bound on the number of variables of a circuit.
pub const max_vars: u32 = 1 << 31;

/// `[in0] op [in1] = [out]`: the layout of `Add`, `Sub`, `Mul` and `PointwiseMul`.
pub const BinaryGate = struct { in0: u32, in1: u32, out: u32 };

/// `[in0] = [in1]`.
pub const EqGate = struct { in0: u32, in1: u32 };

/// `[out] = a ^ b ^ c` over `(u16, u16, 0, 0)`-encoded `u32`s.
pub const TripleXorGate = struct { input_a: u32, input_b: u32, input_c: u32, out: u32 };

/// `[out] = (x & 0xFFFF, x >> 16, 0, 0)` for an M31 input `(x, 0, 0, 0)`.
pub const M31ToU32Gate = struct { input: u32, out: u32 };

/// `(a', b', c', d') = G(a, b, c, d, f0, f1)`; the outputs are
/// `out_base`, `out_base + 1`, `out_base + 2` and `out_base + 3`.
pub const BlakeGGate = struct {
    input_a: u32,
    input_b: u32,
    input_c: u32,
    input_d: u32,
    input_f0: u32,
    input_f1: u32,
    out_base: u32,

    pub fn inputs(self: BlakeGGate) [6]u32 {
        return .{ self.input_a, self.input_b, self.input_c, self.input_d, self.input_f0, self.input_f1 };
    }

    pub fn outputs(self: BlakeGGate) [4]u32 {
        return .{ self.out_base, self.out_base + 1, self.out_base + 2, self.out_base + 3 };
    }
};

/// One permutation gate: the multiset of `outputs` equals that of `inputs`.
pub const Permutation = struct { inputs: []const u32, outputs: []const u32 };

/// All permutation gates in CSR form: gate `g` owns
/// `inputs[ends[g-1]..ends[g]]` and the same range of `outputs`.
pub const Permutations = struct {
    ends: std.ArrayListUnmanaged(u32) = .empty,
    inputs: std.ArrayListUnmanaged(u32) = .empty,
    outputs: std.ArrayListUnmanaged(u32) = .empty,

    pub fn len(self: *const Permutations) usize {
        return self.ends.items.len;
    }

    pub fn get(self: *const Permutations, gate: usize) Permutation {
        const start: usize = if (gate == 0) 0 else self.ends.items[gate - 1];
        const end: usize = self.ends.items[gate];
        return .{ .inputs = self.inputs.items[start..end], .outputs = self.outputs.items[start..end] };
    }

    /// Appends one gate. `inputs` and `outputs` have the same length.
    pub fn append(self: *Permutations, gpa: Allocator, inputs: []const u32, outputs: []const u32) Allocator.Error!void {
        std.debug.assert(inputs.len == outputs.len);
        try self.inputs.appendSlice(gpa, inputs);
        try self.outputs.appendSlice(gpa, outputs);
        try self.ends.append(gpa, @intCast(self.inputs.items.len));
    }

    /// Total number of inputs plus outputs over all gates.
    pub fn nTerms(self: *const Permutations) usize {
        return self.inputs.items.len + self.outputs.items.len;
    }

    fn deinit(self: *Permutations, gpa: Allocator) void {
        self.ends.deinit(gpa);
        self.inputs.deinit(gpa);
        self.outputs.deinit(gpa);
    }
};

/// The first gate a value assignment violates, rendered like upstream's
/// `Circuit::check` error string.
pub const Violation = union(enum) {
    /// `check_eq(computed, stored)` failed.
    not_equal: struct { computed: QM31, stored: QM31 },
    triple_xor_input: struct { input: u8, value: QM31 },
    m31_to_u32_input: QM31,
    blake_g_input: struct { input: u8, value: QM31 },
    permutation,

    pub fn format(self: Violation, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        switch (self) {
            .not_equal => |v| {
                try debug_format.writeQm31(writer, v.computed);
                try writer.writeAll(" != ");
                try debug_format.writeQm31(writer, v.stored);
            },
            .triple_xor_input => |v| {
                try writer.print("TripleXor: input {d} is not of the form (u16, u16, 0, 0), got ", .{v.input});
                try debug_format.writeQm31(writer, v.value);
            },
            .m31_to_u32_input => |value| {
                try writer.writeAll("M31ToU32: input is not M31, got ");
                try debug_format.writeQm31(writer, value);
            },
            .blake_g_input => |v| {
                try writer.print("BlakeGGate: input {d} is not of the form (u16, u16, 0, 0), got ", .{v.input});
                try debug_format.writeQm31(writer, v.value);
            },
            .permutation => try writer.writeAll("Permutation is not valid"),
        }
    }
};

/// Per-variable use and yield counts (lookup-term multiplicities).
pub const Multiplicities = struct {
    n_uses: []u32,
    n_yields: []u32,

    pub fn deinit(self: *Multiplicities, gpa: Allocator) void {
        gpa.free(self.n_uses);
        gpa.free(self.n_yields);
        self.* = undefined;
    }
};

/// A variable yielded other than exactly once.
pub const YieldViolation = struct { var_idx: u32, n_yields: u32 };

pub const Circuit = struct {
    n_vars: u32 = 0,
    add: std.ArrayListUnmanaged(BinaryGate) = .empty,
    sub: std.ArrayListUnmanaged(BinaryGate) = .empty,
    mul: std.ArrayListUnmanaged(BinaryGate) = .empty,
    pointwise_mul: std.ArrayListUnmanaged(BinaryGate) = .empty,
    eq: std.ArrayListUnmanaged(EqGate) = .empty,
    triple_xor: std.ArrayListUnmanaged(TripleXorGate) = .empty,
    m31_to_u32: std.ArrayListUnmanaged(M31ToU32Gate) = .empty,
    blake_g_gate: std.ArrayListUnmanaged(BlakeGGate) = .empty,
    permutation: Permutations = .{},
    /// `Output` gates: the marked variable of each.
    output: std.ArrayListUnmanaged(u32) = .empty,

    pub fn deinit(self: *Circuit, gpa: Allocator) void {
        self.add.deinit(gpa);
        self.sub.deinit(gpa);
        self.mul.deinit(gpa);
        self.pointwise_mul.deinit(gpa);
        self.eq.deinit(gpa);
        self.triple_xor.deinit(gpa);
        self.m31_to_u32.deinit(gpa);
        self.blake_g_gate.deinit(gpa);
        self.permutation.deinit(gpa);
        self.output.deinit(gpa);
        self.* = undefined;
    }

    /// `n_qm31_ops_rows`: one QM31Ops row per arithmetic gate plus one per
    /// permutation input and output.
    pub fn nQm31OpsRows(self: *const Circuit) usize {
        return self.add.items.len + self.sub.items.len + self.mul.items.len +
            self.pointwise_mul.items.len + self.permutation.nTerms();
    }

    /// `Circuit::check`: the first gate, in `all_gates` order, that `values`
    /// violate, or null when every gate holds.
    pub fn check(self: *const Circuit, gpa: Allocator, values: []const QM31) Allocator.Error!?Violation {
        const binary = [_]struct { []const BinaryGate, *const fn (QM31, QM31) QM31 }{
            .{ self.add.items, qm31Add },
            .{ self.sub.items, qm31Sub },
            .{ self.mul.items, qm31Mul },
            .{ self.pointwise_mul.items, qm31PointwiseMul },
        };
        for (binary) |entry| for (entry[0]) |gate| {
            if (notEqual(entry[1](values[gate.in0], values[gate.in1]), values[gate.out])) |v| return v;
        };
        for (self.eq.items) |gate| if (notEqual(values[gate.in0], values[gate.in1])) |v| return v;
        for (self.blake_g_gate.items) |gate| if (checkBlakeG(gate, values)) |v| return v;
        for (self.triple_xor.items) |gate| if (checkTripleXor(gate, values)) |v| return v;
        for (self.m31_to_u32.items) |gate| if (checkM31ToU32(gate, values)) |v| return v;
        for (0..self.permutation.len()) |g| {
            if (!try isPermutation(gpa, self.permutation.get(g), values)) return .permutation;
        }
        return null;
    }

    /// `compute_multiplicities`: how often each variable is used and yielded.
    pub fn computeMultiplicities(self: *const Circuit, gpa: Allocator) Allocator.Error!Multiplicities {
        const n_uses = try gpa.alloc(u32, self.n_vars);
        errdefer gpa.free(n_uses);
        const n_yields = try gpa.alloc(u32, self.n_vars);
        @memset(n_uses, 0);
        @memset(n_yields, 0);
        const binary = [_][]const BinaryGate{ self.add.items, self.sub.items, self.mul.items, self.pointwise_mul.items };
        for (binary) |gates| for (gates) |gate| {
            n_uses[gate.in0] += 1;
            n_uses[gate.in1] += 1;
            n_yields[gate.out] += 1;
        };
        for (self.eq.items) |gate| {
            n_uses[gate.in0] += 1;
            n_uses[gate.in1] += 1;
        }
        for (self.blake_g_gate.items) |gate| {
            for (gate.inputs()) |input| n_uses[input] += 1;
            for (gate.outputs()) |out| n_yields[out] += 1;
        }
        for (self.triple_xor.items) |gate| {
            for ([_]u32{ gate.input_a, gate.input_b, gate.input_c }) |input| n_uses[input] += 1;
            n_yields[gate.out] += 1;
        }
        for (self.m31_to_u32.items) |gate| {
            n_uses[gate.input] += 1;
            n_yields[gate.out] += 1;
        }
        for (self.permutation.inputs.items) |input| n_uses[input] += 1;
        for (self.permutation.outputs.items) |out| n_yields[out] += 1;
        for (self.output.items) |in0| n_uses[in0] += 1;
        return .{ .n_uses = n_uses, .n_yields = n_yields };
    }

    /// `check_yields`: the first variable yielded other than exactly once.
    pub fn firstYieldViolation(self: *const Circuit, gpa: Allocator) Allocator.Error!?YieldViolation {
        var multiplicities = try self.computeMultiplicities(gpa);
        defer multiplicities.deinit(gpa);
        for (multiplicities.n_yields, 0..) |n_yields, idx| {
            if (n_yields != 1) return .{ .var_idx = @intCast(idx), .n_yields = n_yields };
        }
        return null;
    }
};

fn qm31Add(a: QM31, b: QM31) QM31 {
    return a.add(b);
}

fn qm31Sub(a: QM31, b: QM31) QM31 {
    return a.sub(b);
}

fn qm31Mul(a: QM31, b: QM31) QM31 {
    return a.mul(b);
}

fn qm31PointwiseMul(a: QM31, b: QM31) QM31 {
    return ivalue.pointwiseMul(QM31, a, b);
}

fn notEqual(computed: QM31, stored: QM31) ?Violation {
    if (computed.eql(stored)) return null;
    return .{ .not_equal = .{ .computed = computed, .stored = stored } };
}

fn isU32Limbs(value: QM31) bool {
    const l = ivalue.limbs(value);
    return l[0] <= 0xFFFF and l[1] <= 0xFFFF and l[2] == 0 and l[3] == 0;
}

fn checkTripleXor(gate: TripleXorGate, values: []const QM31) ?Violation {
    const operands = [_]u32{ gate.input_a, gate.input_b, gate.input_c };
    for (operands, 0..) |input, i| {
        if (!isU32Limbs(values[input])) return .{ .triple_xor_input = .{ .input = @intCast(i), .value = values[input] } };
    }
    var xor: u32 = 0;
    for (operands) |input| xor ^= ivalue.unpackU32(QM31, values[input]);
    return notEqual(values[gate.out], ivalue.packU32(QM31, xor));
}

fn checkM31ToU32(gate: M31ToU32Gate, values: []const QM31) ?Violation {
    const input = values[gate.input];
    if (!input.isBase()) return .{ .m31_to_u32_input = input };
    return notEqual(values[gate.out], ivalue.m31ToU32(QM31, input));
}

fn checkBlakeG(gate: BlakeGGate, values: []const QM31) ?Violation {
    var words: [6]u32 = undefined;
    for (gate.inputs(), 0..) |input, i| {
        if (!isU32Limbs(values[input])) return .{ .blake_g_input = .{ .input = @intCast(i), .value = values[input] } };
        words[i] = ivalue.unpackU32(QM31, values[input]);
    }
    const out = blake.blake2sG(words[0], words[1], words[2], words[3], words[4], words[5]);
    for (gate.outputs(), out) |var_idx, word| {
        if (notEqual(values[var_idx], ivalue.packU32(QM31, word))) |v| return v;
    }
    return null;
}

/// Multiset equality of the input and output values, as upstream's counting map.
fn isPermutation(gpa: Allocator, gate: Permutation, values: []const QM31) Allocator.Error!bool {
    var counts: std.AutoHashMapUnmanaged(u128, i64) = .empty;
    defer counts.deinit(gpa);
    for (gate.inputs) |input| (try counts.getOrPutValue(gpa, key(values[input]), 0)).value_ptr.* += 1;
    for (gate.outputs) |out| (try counts.getOrPutValue(gpa, key(values[out]), 0)).value_ptr.* -= 1;
    // Every output was counted against an input and both lists have the same
    // length, so a non-zero count exists iff some count went negative.
    for (gate.outputs) |out| if (counts.get(key(values[out])).? != 0) return false;
    return true;
}

fn key(value: QM31) u128 {
    const l = ivalue.limbs(value);
    return @as(u128, l[0]) | (@as(u128, l[1]) << 32) | (@as(u128, l[2]) << 64) | (@as(u128, l[3]) << 96);
}

// Tests: `crates/circuits/src/circuit_test.rs`.

fn m(value: u32) QM31 {
    return ivalue.qm31FromU32s(value, 0, 0, 0);
}

fn expectViolation(expected: []const u8, violation: ?Violation) !void {
    var buffer: [256]u8 = undefined;
    const text = try std.fmt.bufPrint(&buffer, "{f}", .{violation.?});
    try std.testing.expectEqualStrings(expected, text);
}

test "circuit: add" {
    const gpa = std.testing.allocator;
    var c: Circuit = .{ .n_vars = 3 };
    defer c.deinit(gpa);
    try c.add.append(gpa, .{ .in0 = 0, .in1 = 1, .out = 2 });
    try std.testing.expectEqual(null, try c.check(gpa, &.{ m(1), m(2), m(3) }));
    try expectViolation("(3 + 0i) + (0 + 0i)u != (4 + 0i) + (0 + 0i)u", try c.check(gpa, &.{ m(1), m(2), m(4) }));
    var mult = try c.computeMultiplicities(gpa);
    defer mult.deinit(gpa);
    try std.testing.expectEqualSlices(u32, &.{ 1, 1, 0 }, mult.n_uses);
    try std.testing.expectEqualSlices(u32, &.{ 0, 0, 1 }, mult.n_yields);
}

test "circuit: sub" {
    const gpa = std.testing.allocator;
    var c: Circuit = .{};
    defer c.deinit(gpa);
    try c.sub.append(gpa, .{ .in0 = 0, .in1 = 1, .out = 3 });
    try std.testing.expectEqual(null, try c.check(gpa, &.{ m(10), m(7), m(0), m(3) }));
    try expectViolation("(3 + 0i) + (0 + 0i)u != (4 + 0i) + (0 + 0i)u", try c.check(gpa, &.{ m(10), m(7), m(0), m(4) }));
}

test "circuit: mul" {
    const gpa = std.testing.allocator;
    var c: Circuit = .{};
    defer c.deinit(gpa);
    try c.mul.append(gpa, .{ .in0 = 1, .in1 = 1, .out = 2 });
    try std.testing.expectEqual(null, try c.check(gpa, &.{ m(1), m(4), m(16) }));
    try expectViolation("(25 + 0i) + (0 + 0i)u != (16 + 0i) + (0 + 0i)u", try c.check(gpa, &.{ m(1), m(5), m(16) }));
}

test "circuit: eq" {
    const gpa = std.testing.allocator;
    var c: Circuit = .{ .n_vars = 3 };
    defer c.deinit(gpa);
    try c.eq.append(gpa, .{ .in0 = 1, .in1 = 2 });
    try std.testing.expectEqual(null, try c.check(gpa, &.{ m(1), m(2), m(2) }));
    try expectViolation("(1 + 0i) + (0 + 0i)u != (2 + 0i) + (0 + 0i)u", try c.check(gpa, &.{ m(1), m(1), m(2) }));
    var mult = try c.computeMultiplicities(gpa);
    defer mult.deinit(gpa);
    try std.testing.expectEqualSlices(u32, &.{ 0, 1, 1 }, mult.n_uses);
    try std.testing.expectEqualSlices(u32, &.{ 0, 0, 0 }, mult.n_yields);
}

test "circuit: permutation" {
    const gpa = std.testing.allocator;
    var c: Circuit = .{ .n_vars = 6 };
    defer c.deinit(gpa);
    try c.permutation.append(gpa, &.{ 0, 1, 2 }, &.{ 3, 4, 5 });
    try std.testing.expectEqual(null, try c.check(gpa, &.{ m(1), m(2), m(2), m(2), m(1), m(2) }));
    try expectViolation("Permutation is not valid", try c.check(gpa, &.{ m(1), m(2), m(2), m(2), m(2), m(2) }));
}

test "circuit: output" {
    const gpa = std.testing.allocator;
    var c: Circuit = .{ .n_vars = 3 };
    defer c.deinit(gpa);
    try c.output.append(gpa, 1);
    try std.testing.expectEqual(null, try c.check(gpa, &.{ m(1), m(2), m(2) }));
    var mult = try c.computeMultiplicities(gpa);
    defer mult.deinit(gpa);
    try std.testing.expectEqualSlices(u32, &.{ 0, 1, 0 }, mult.n_uses);
    try std.testing.expectEqualSlices(u32, &.{ 0, 0, 0 }, mult.n_yields);
}

test "circuit: u32 gates reject malformed inputs with upstream messages" {
    const gpa = std.testing.allocator;
    var c: Circuit = .{ .n_vars = 4 };
    defer c.deinit(gpa);
    try c.triple_xor.append(gpa, .{ .input_a = 0, .input_b = 1, .input_c = 2, .out = 3 });
    const x = ivalue.packU32(QM31, 0x1234_5678);
    const y = ivalue.packU32(QM31, 0x0F0F_0F0F);
    const z = ivalue.packU32(QM31, 0xFFFF_0000);
    const out = ivalue.packU32(QM31, 0x1234_5678 ^ 0x0F0F_0F0F ^ 0xFFFF_0000);
    try std.testing.expectEqual(null, try c.check(gpa, &.{ x, y, z, out }));
    try expectViolation(
        "TripleXor: input 1 is not of the form (u16, u16, 0, 0), got (1 + 0i) + (1 + 0i)u",
        try c.check(gpa, &.{ x, ivalue.qm31FromU32s(1, 0, 1, 0), z, out }),
    );

    var n: Circuit = .{ .n_vars = 2 };
    defer n.deinit(gpa);
    try n.m31_to_u32.append(gpa, .{ .input = 0, .out = 1 });
    try std.testing.expectEqual(null, try n.check(gpa, &.{ m(0x1234_5678), ivalue.packU32(QM31, 0x1234_5678) }));
    try expectViolation("M31ToU32: input is not M31, got (5 + 1i) + (0 + 0i)u", try n.check(gpa, &.{ ivalue.qm31FromU32s(5, 1, 0, 0), m(5) }));
}
