//! Serialize the native curve relation/layout authority for device witness generation.
const std = @import("std");
const A = @import("stwo_riscv_frontend").rv64_air;
const C = A.crypto.curves;
fn vector(comptime L: type, v: C.spec.Vec) usize {
    return L.column(v);
}
fn emit(comptime kind: anytype, a: std.mem.Allocator, out: *std.ArrayList(u8)) !void {
    const L = C.layout.Layout(kind);
    const d = L.DEF;
    const extended = @TypeOf(kind) == C.spec.Op;
    const name = if (extended) @tagName(kind) else if (kind == .add) "Add" else "Double";
    try out.print(a, "struct {s} {{ static constexpr uint32_t MAIN={d},PACKET={d},OUT={d},WIT={d},MULT={d},INPUTS={d},WITNESSES={d},RELATIONS={d},QUERIES={d};\n", .{ name, L.MAIN, L.PACKET, L.OUT, L.WIT, L.MULT, d.inputs, d.witnesses, L.RELATIONS, L.BYTE_QUERIES });
    if (extended) {
        try out.print(a, "static constexpr uint32_t PACKET_BYTES={d},LIMBS={d},OUTPUTS={d},CHECKS={d},SEL={d},INV={d},HALF={d},VARIABLE={d},ODD={d},NZA={d},NONZERO={d};static constexpr int32_t NZB={d};\n", .{ L.PACKET_BYTES, d.limbs, d.outputs, L.CHECKS.len, L.SEL, L.INV, L.HALF, @intFromBool(d.modulus == .variable), @intFromBool(d.odd_modulus), if (d.nonzero) |nz| L.column(nz.a) else 0, @intFromBool(d.nonzero != null), if (d.nonzero) |nz| if (nz.b) |b| @as(i32, @intCast(L.column(b))) else -1 else -1 });
        try out.print(a, "static __device__ uint32_t modulus(const uint32_t*row,uint32_t i){{", .{});
        switch (d.modulus) {
            .constant => |m| {
                try out.appendSlice(a, "switch(i){");
                for (0..d.limbs) |i| try out.print(a, "case {d}:return {d};", .{ i, C.spec.limbOf(m, i) });
                try out.appendSlice(a, "}return 0;");
            },
            .variable => |v| try out.print(a, "return row[{d}+i];", .{L.PACKET + v * d.limbs}),
        }
        try out.appendSlice(a, "}\nstatic __device__ uint32_t checkColumn(uint32_t j){switch(j){");
        for (L.CHECKS, 0..) |check, i| try out.print(a, "case {d}:return {d};", .{ i, L.column(check.x) });
        try out.appendSlice(a, "}return 0;}\nstatic __device__ uint32_t rInverse(uint32_t i){switch(i){");
        if (kind == .bls12_381_fp2_mul) for (0..48) |i| try out.print(a, "case {d}:return {d};", .{ i, C.spec.limbOf(C.native.blsRInv(), i) });
        try out.appendSlice(a, "}return 0;}\n");
    }
    for (d.relations, 0..) |terms, r| {
        try out.print(a, "static __device__ uint32_t terms{d}(Term*t) {{\n", .{r});
        for (terms, 0..) |term, i| try out.print(a, "t[{d}]={{ {d},{d},{d},{d} }};\n", .{ i, vector(L, term.a), if (term.b) |b| @as(i32, @intCast(vector(L, b))) else -1, term.coef, term.shift });
        try out.print(a, "return {d}; }}\n", .{terms.len});
    }
    try out.appendSlice(a, "static __device__ Geometry geometry(uint32_t r) {switch(r){\n");
    for (L.GEOMETRY, 0..) |g, r| {
        try out.print(a, "case {d}: return {{ {d},{d},{d},{d},{d},{d},{d},{{", .{ r, L.QUOTIENT[r], L.CARRY[r], g.q_bytes, g.groups, g.carries, g.group, g.carry_bits });
        for (0..(if (extended) @as(usize, 192) else 96)) |i| try out.print(a, "{d},", .{C.spec.limbOf(g.kp, i)});
        try out.appendSlice(a, "}};\n");
    }
    try out.appendSlice(a, "}return {}; }\nstatic __device__ uint32_t terms(uint32_t r,Term*t){switch(r){\n");
    for (d.relations, 0..) |_, r| try out.print(a, "case {d}:return terms{d}(t);\n", .{ r, r });
    try out.appendSlice(a, "}return 0;}\nstatic __device__ Query query(uint32_t i){switch(i){\n");
    for (L.QUERIES, 0..) |q, i| try out.print(a, "case {d}:return {{{d},{d}}};\n", .{ i, q.column, q.addend });
    try out.appendSlice(a, "}return {};}\nstatic __device__ uint32_t dbase(uint32_t j){switch(j){\n");
    for (L.D, 0..) |v, i| try out.print(a, "case {d}:return {d};\n", .{ i, v });
    try out.appendSlice(a, "}return 0;}\nstatic __device__ uint32_t borrow(uint32_t j){switch(j){\n");
    for (L.BORROW, 0..) |v, i| try out.print(a, "case {d}:return {d};\n", .{ i, v });
    try out.appendSlice(a, "}return 0;} };\n");
}
pub fn write(a: std.mem.Allocator, dir: std.fs.Dir) !void {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(a);
    try out.appendSlice(a, "// Generated from native curves spec/layout. Do not edit.\n#pragma once\n");
    try emit(@as(C.spec.SecpKind, .add), a, &out);
    try emit(@as(C.spec.SecpKind, .double), a, &out);
    try dir.writeFile(.{ .sub_path = "secp_witness_layout.cuh", .data = out.items });
}
test "device secp metadata is derived from native layouts" {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(std.testing.allocator);
    try emit(@as(C.spec.SecpKind, .add), std.testing.allocator, &out);
    try std.testing.expect(out.items.len > 1000);
}

pub const EXTENDED = [_]C.spec.Op{ .bn254_g1_add, .bn254_g1_double, .bn254_fp2_mul, .bls12_381_fp2_mul, .arith384_mont };
pub fn writeExtended(a: std.mem.Allocator, dir: std.fs.Dir) !void {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(a);
    try out.appendSlice(a, "// Generated from native curve authorities.\n#pragma once\n");
    inline for (EXTENDED) |op| try emit(op, a, &out);
    try dir.writeFile(.{ .sub_path = "curve_witness_layout.cuh", .data = out.items });
}
