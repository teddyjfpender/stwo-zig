//! Serialize the native curve relation/layout authority for device witness generation.
const std = @import("std");
const A = @import("stwo_riscv_frontend").rv64_air;
const C = A.crypto.curves;
fn vector(comptime L: type, v: C.spec.Vec) usize {
    return L.column(v);
}
fn emit(comptime kind: C.spec.SecpKind, a: std.mem.Allocator, out: *std.ArrayList(u8)) !void {
    const L = C.layout.Layout(kind);
    const d = L.DEF;
    const name = if (kind == .add) "Add" else "Double";
    try out.print(a, "struct {s} {{ static constexpr uint32_t MAIN={d},PACKET={d},OUT={d},WIT={d},MULT={d},INPUTS={d},WITNESSES={d},RELATIONS={d},QUERIES={d};\n", .{ name, L.MAIN, L.PACKET, L.OUT, L.WIT, L.MULT, d.inputs, d.witnesses, L.RELATIONS, L.BYTE_QUERIES });
    for (d.relations, 0..) |terms, r| {
        try out.print(a, "static __device__ uint32_t terms{d}(Term*t) {{\n", .{r});
        for (terms, 0..) |term, i| try out.print(a, "t[{d}]={{ {d},{d},{d},{d} }};\n", .{ i, vector(L, term.a), if (term.b) |b| @as(i32, @intCast(vector(L, b))) else -1, term.coef, term.shift });
        try out.print(a, "return {d}; }}\n", .{terms.len});
    }
    try out.appendSlice(a, "static __device__ Geometry geometry(uint32_t r) {switch(r){\n");
    for (L.GEOMETRY, 0..) |g, r| {
        try out.print(a, "case {d}: return {{ {d},{d},{d},{d},{d},{d},{d},{{", .{ r, L.QUOTIENT[r], L.CARRY[r], g.q_bytes, g.groups, g.carries, g.group, g.carry_bits });
        for (0..96) |i| try out.print(a, "{d},", .{C.spec.limbOf(g.kp, i)});
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
    try emit(.add, a, &out);
    try emit(.double, a, &out);
    try dir.writeFile(.{ .sub_path = "secp_witness_layout.cuh", .data = out.items });
}
test "device secp metadata is derived from native layouts" {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(std.testing.allocator);
    try emit(.add, std.testing.allocator, &out);
    try std.testing.expect(out.items.len > 1000);
}
