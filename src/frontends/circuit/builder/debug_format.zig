//! Upstream `Debug` text of circuits, QM31 values and constant tables.
//!
//! Byte-for-byte the output of `format!("{circuit:?}")` and friends in
//! `crates/circuits` (https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230). Parity tests compare this text
//! with the upstream `expect!` snapshots and with the oracle's
//! `debug_text_sha256`, so it is part of the parity contract, not a
//! convenience printer.

const std = @import("std");
const stwo_core = @import("stwo_core");
const circuit_mod = @import("circuit.zig");
const ivalue = @import("ivalue.zig");

const QM31 = stwo_core.fields.qm31.QM31;
const Circuit = circuit_mod.Circuit;
const Var = circuit_mod.Var;
const Writer = std.Io.Writer;

/// `Display` of a QM31: `(a + bi) + (c + di)u`.
pub fn writeQm31(writer: *Writer, value: QM31) Writer.Error!void {
    const l = ivalue.limbs(value);
    try writer.print("({d} + {d}i) + ({d} + {d}i)u", .{ l[0], l[1], l[2], l[3] });
}

/// `impl Debug for Circuit`: one gate per line, each line ending in `\n`,
/// in `Circuit::all_gates` order.
pub fn writeCircuit(writer: *Writer, circuit: *const Circuit) Writer.Error!void {
    for ([_]struct { []const circuit_mod.BinaryGate, u8 }{
        .{ circuit.add.items, '+' },
        .{ circuit.sub.items, '-' },
        .{ circuit.mul.items, '*' },
        .{ circuit.pointwise_mul.items, 'x' },
    }) |entry| for (entry[0]) |gate| {
        try writer.print("[{d}] = [{d}] {c} [{d}]\n", .{ gate.out, gate.in0, entry[1], gate.in1 });
    };
    for (circuit.eq.items) |gate| try writer.print("[{d}] = [{d}]\n", .{ gate.in0, gate.in1 });
    for (circuit.blake_g_gate.items) |gate| {
        const o = gate.outputs();
        try writer.print("([{d}],[{d}],[{d}],[{d}]) = BlakeGGate([{d}],[{d}],[{d}],[{d}],[{d}],[{d}])\n", .{
            o[0],          o[1],          o[2],         o[3],
            gate.input_a,  gate.input_b,  gate.input_c, gate.input_d,
            gate.input_f0, gate.input_f1,
        });
    }
    for (circuit.triple_xor.items) |gate| {
        try writer.print("[{d}] = TripleXor([{d}], [{d}], [{d}])\n", .{ gate.out, gate.input_a, gate.input_b, gate.input_c });
    }
    for (circuit.m31_to_u32.items) |gate| try writer.print("[{d}] = m31_to_u32([{d}])\n", .{ gate.out, gate.input });
    for (0..circuit.permutation.len()) |g| {
        const gate = circuit.permutation.get(g);
        try writer.writeAll("(");
        try writeUsizeList(writer, gate.outputs);
        try writer.writeAll(") = (");
        try writeUsizeList(writer, gate.inputs);
        try writer.writeAll(")\n");
    }
    for (circuit.output.items) |in0| try writer.print("output [{d}]\n", .{in0});
}

/// `Debug` of a `Vec<usize>`: `[a, b, c]`.
fn writeUsizeList(writer: *Writer, items: []const u32) Writer.Error!void {
    try writer.writeAll("[");
    for (items, 0..) |item, i| {
        if (i != 0) try writer.writeAll(", ");
        try writer.print("{d}", .{item});
    }
    try writer.writeAll("]");
}

/// `{:#?}` of the constants `IndexMap<QM31, Var>`, in insertion order.
pub fn writeConstants(writer: *Writer, keys: []const QM31, vars: []const Var) Writer.Error!void {
    std.debug.assert(keys.len == vars.len);
    if (keys.len == 0) return writer.writeAll("{}");
    try writer.writeAll("{\n");
    for (keys, vars) |value, v| {
        try writer.writeAll("    ");
        try writeQm31(writer, value);
        try writer.print(": [{d}],\n", .{v.idx});
    }
    try writer.writeAll("}");
}

/// The circuit's `Debug` text in a newly allocated buffer owned by the caller.
pub fn circuitText(gpa: std.mem.Allocator, circuit: *const Circuit) std.mem.Allocator.Error![]u8 {
    var out: std.Io.Writer.Allocating = .init(gpa);
    errdefer out.deinit();
    writeCircuit(&out.writer, circuit) catch return error.OutOfMemory;
    return out.toOwnedSlice();
}

test "debug format: every gate kind renders like upstream" {
    const gpa = std.testing.allocator;
    var c: Circuit = .{ .n_vars = 20 };
    defer c.deinit(gpa);
    try c.add.append(gpa, .{ .in0 = 1, .in1 = 2, .out = 3 });
    try c.sub.append(gpa, .{ .in0 = 4, .in1 = 5, .out = 6 });
    try c.mul.append(gpa, .{ .in0 = 7, .in1 = 8, .out = 9 });
    try c.pointwise_mul.append(gpa, .{ .in0 = 3, .in1 = 4, .out = 5 });
    try c.eq.append(gpa, .{ .in0 = 6, .in1 = 0 });
    try c.blake_g_gate.append(gpa, .{ .input_a = 1, .input_b = 2, .input_c = 3, .input_d = 4, .input_f0 = 5, .input_f1 = 6, .out_base = 10 });
    try c.triple_xor.append(gpa, .{ .input_a = 1, .input_b = 2, .input_c = 3, .out = 14 });
    try c.m31_to_u32.append(gpa, .{ .input = 3, .out = 15 });
    try c.permutation.append(gpa, &.{ 16, 17 }, &.{ 18, 19 });
    try c.permutation.append(gpa, &.{}, &.{});
    try c.output.append(gpa, 2);
    const text = try circuitText(gpa, &c);
    defer gpa.free(text);
    try std.testing.expectEqualStrings(
        \\[3] = [1] + [2]
        \\[6] = [4] - [5]
        \\[9] = [7] * [8]
        \\[5] = [3] x [4]
        \\[6] = [0]
        \\([10],[11],[12],[13]) = BlakeGGate([1],[2],[3],[4],[5],[6])
        \\[14] = TripleXor([1], [2], [3])
        \\[15] = m31_to_u32([3])
        \\([18, 19]) = ([16, 17])
        \\([]) = ([])
        \\output [2]
        \\
    , text);
}
