//! C emitter for one exported composition program (QM31). One statement per
//! IR node, so common subexpressions (already hash-consed in the IR) are
//! computed once; node sorts pick M31 scalar code for base values and QM31
//! code only after an FS parameter enters. The quotient entry point fuses the
//! random-power fold and the vanishing-inverse scale, as a GPU kernel would.
//! Arithmetic is canonical (fully reduced), so results are bit-identical to
//! the Zig field implementation.
const std = @import("std");
const R = @import("record.zig");

const prelude =
    \\#include <stdint.h>
    \\#define CIR_P 0x7fffffffu
    \\typedef struct { uint32_t a, b, c, d; } cir_q;
    \\static inline uint32_t cir_add(uint32_t x, uint32_t y) { uint32_t s = x + y; return s >= CIR_P ? s - CIR_P : s; }
    \\static inline uint32_t cir_sub(uint32_t x, uint32_t y) { return x >= y ? x - y : x + CIR_P - y; }
    \\static inline uint32_t cir_neg(uint32_t x) { return x == 0 ? 0 : CIR_P - x; }
    \\static inline uint32_t cir_mul(uint32_t x, uint32_t y) {
    \\  uint64_t p = (uint64_t)x * y; uint64_t r = (p & CIR_P) + (p >> 31); r = (r & CIR_P) + (r >> 31);
    \\  return (uint32_t)(r >= CIR_P ? r - CIR_P : r);
    \\}
    \\static inline cir_q cir_qb(uint32_t x) { cir_q r = { x, 0, 0, 0 }; return r; }
    \\static inline cir_q cir_qadd(cir_q x, cir_q y) { cir_q r = { cir_add(x.a, y.a), cir_add(x.b, y.b), cir_add(x.c, y.c), cir_add(x.d, y.d) }; return r; }
    \\static inline cir_q cir_qsub(cir_q x, cir_q y) { cir_q r = { cir_sub(x.a, y.a), cir_sub(x.b, y.b), cir_sub(x.c, y.c), cir_sub(x.d, y.d) }; return r; }
    \\static inline cir_q cir_qneg(cir_q x) { cir_q r = { cir_neg(x.a), cir_neg(x.b), cir_neg(x.c), cir_neg(x.d) }; return r; }
    \\static inline cir_q cir_qmulb(cir_q x, uint32_t m) { cir_q r = { cir_mul(x.a, m), cir_mul(x.b, m), cir_mul(x.c, m), cir_mul(x.d, m) }; return r; }
    \\/* CM31 = M31[i]/(i^2+1); QM31 = CM31[u]/(u^2-(2+i)); Karatsuba at both levels. */
    \\static inline void cir_cmul(uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t *re, uint32_t *im) {
    \\  uint32_t ac = cir_mul(a, c), bd = cir_mul(b, d), cross = cir_mul(cir_add(a, b), cir_add(c, d));
    \\  *re = cir_sub(ac, bd); *im = cir_sub(cir_sub(cross, ac), bd);
    \\}
    \\static inline cir_q cir_qmul(cir_q x, cir_q y) {
    \\  uint32_t ac_re, ac_im, bd_re, bd_im, s_re, s_im;
    \\  cir_cmul(x.a, x.b, y.a, y.b, &ac_re, &ac_im);
    \\  cir_cmul(x.c, x.d, y.c, y.d, &bd_re, &bd_im);
    \\  cir_cmul(cir_add(x.a, x.c), cir_add(x.b, x.d), cir_add(y.a, y.c), cir_add(y.b, y.d), &s_re, &s_im);
    \\  /* (2+i)*bd = (2re - im) + (re + 2im)i */
    \\  uint32_t rbd_re = cir_sub(cir_add(bd_re, bd_re), bd_im), rbd_im = cir_add(bd_re, cir_add(bd_im, bd_im));
    \\  cir_q r = { cir_add(ac_re, rbd_re), cir_add(ac_im, rbd_im), cir_sub(cir_sub(s_re, ac_re), bd_re), cir_sub(cir_sub(s_im, ac_im), bd_im) };
    \\  return r;
    \\}
    \\static inline cir_q cir_qload(const uint32_t *p, uint32_t i) { cir_q r = { p[4 * i], p[4 * i + 1], p[4 * i + 2], p[4 * i + 3] }; return r; }
    \\
;

fn v(w: anytype, sorts: []const R.ir.Sort, id: u32, want_secure: bool) !void {
    if (want_secure and sorts[id] == .base) return w.print("cir_qb(n{d})", .{id});
    try w.print("n{d}", .{id});
}

/// Emits `void NAME(in, params, out)` (one residual per root, 4 words each)
/// and `void NAME_quotient(in, params, powers, denominator_inverse, out)`,
/// where `powers` holds 4-word secure random powers in emission order
/// (residual j weighted by powers[j]) and `in` holds one M31 per IR input.
pub fn emit(a: std.mem.Allocator, w: anytype, program: *const R.Program, name: []const u8) !void {
    const sorts = try program.sorts(a);
    defer a.free(sorts);
    try w.writeAll(prelude);
    try w.print("/* {s}: {d} residuals, {d} IR nodes, {d} inputs, {d} parameters; identity {s} */\n", .{ name, program.roots.len, program.nodes.len, program.inputs.len, program.parameters.len, std.fmt.bytesToHex(program.identity, .lower) });
    try w.print("static inline void {s}_nodes(const uint32_t *in, const uint32_t *params, cir_q *roots) {{\n", .{name});
    for (program.nodes, 0..) |node, i| {
        const id: u32 = @intCast(i);
        const secure = sorts[i] == .secure;
        try w.writeAll(if (secure) "  const cir_q " else "  const uint32_t ");
        try w.print("n{d} = ", .{id});
        switch (node.op) {
            .input => try w.print("in[{d}]", .{node.value}),
            .parameter => try w.print("cir_qload(params, {d})", .{node.value}),
            .constant => {
                const words = program.constants[node.value];
                if (secure) try w.print("(cir_q){{ {d}u, {d}u, {d}u, {d}u }}", .{ words[0], words[1], words[2], words[3] }) else try w.print("{d}u", .{words[0]});
            },
            .add, .sub => {
                const op = if (node.op == .add) "add" else "sub";
                try w.print("cir_{s}{s}(", .{ if (secure) "q" else "", op });
                try v(w, sorts, node.lhs, secure);
                try w.writeAll(", ");
                try v(w, sorts, node.rhs, secure);
                try w.writeAll(")");
            },
            .neg => try w.print("cir_{s}neg(n{d})", .{ if (secure) "q" else "", node.lhs }),
            .mul => {
                const l = sorts[node.lhs];
                const r = sorts[node.rhs];
                if (l == .base and r == .base) {
                    try w.print("cir_mul(n{d}, n{d})", .{ node.lhs, node.rhs });
                } else if (l == .secure and r == .secure) {
                    try w.print("cir_qmul(n{d}, n{d})", .{ node.lhs, node.rhs });
                } else if (l == .secure) {
                    try w.print("cir_qmulb(n{d}, n{d})", .{ node.lhs, node.rhs });
                } else try w.print("cir_qmulb(n{d}, n{d})", .{ node.rhs, node.lhs });
            },
            .fraction, .range_fraction => unreachable,
        }
        try w.writeAll(";\n");
    }
    for (program.roots, 0..) |root, j| {
        try w.print("  roots[{d}] = ", .{j});
        try v(w, sorts, root, true);
        try w.writeAll(";\n");
    }
    try w.writeAll("}\n");
    try w.print(
        \\void {0s}(const uint32_t *in, const uint32_t *params, uint32_t *out) {{
        \\  cir_q roots[{1d}];
        \\  {0s}_nodes(in, params, roots);
        \\  for (int j = 0; j < {1d}; j++) {{ out[4 * j] = roots[j].a; out[4 * j + 1] = roots[j].b; out[4 * j + 2] = roots[j].c; out[4 * j + 3] = roots[j].d; }}
        \\}}
        \\void {0s}_quotient(const uint32_t *in, const uint32_t *params, const uint32_t *powers, uint32_t denominator_inverse, uint32_t *out) {{
        \\  cir_q roots[{1d}];
        \\  {0s}_nodes(in, params, roots);
        \\  cir_q acc = cir_qb(0);
        \\  for (int j = 0; j < {1d}; j++) acc = cir_qadd(acc, cir_qmul(cir_qload(powers, j), roots[j]));
        \\  acc = cir_qmulb(acc, denominator_inverse);
        \\  out[0] = acc.a; out[1] = acc.b; out[2] = acc.c; out[3] = acc.d;
        \\}}
        \\
    , .{ name, program.roots.len });
}
