//! Scalar OM31 extension of the authenticated quartic AIR instruction stream.
//! Its V1 bytecode/semantic hash is never re-labelled as an eight-coordinate ABI.
//! This explicit lens and field embedding are separately bound by the profile.
const std = @import("std");
const C = @import("stwo_cairo_frontend").witness;
const P = @import("protocol.zig");
const O = P.O;
const Q = P.Q;
const M = P.M;
pub const Program = C.eval_program.Program;
pub const Reader = struct {
    context: *const anyopaque,
    get: *const fn (*const anyopaque, u8, u32, i32) anyerror!O,
    pub fn read(self: @This(), tree: u8, logical: u32, offset: i32) !O {
        if (tree != 2) return self.get(self.context, tree, logical, offset);
        const low = try std.math.add(u32, try std.math.mul(u32, logical / 4, 8), logical % 4);
        return (try self.get(self.context, 2, low, offset)).add(O.basis().mul(try self.get(self.context, 2, try std.math.add(u32, low, 4), offset)));
    }
};
pub fn embed(value: Q) O {
    return .{ .c0 = value, .c1 = Q.zero() };
}
pub fn pack4(values: [4]O) O {
    return O.fromPartialEvals(.{ values[0], values[1], values[2], values[3], O.zero(), O.zero(), O.zero(), O.zero() });
}
/// Admission proves every INTER coordinate is directly consumed by an aligned
/// quartic pack, not by base-field arithmetic whose field would silently change.
pub fn validateLens(a: std.mem.Allocator, p: Program) !void {
    try p.validate();
    const direct = try a.alloc(?C.eval_program.BaseInst, p.header.max_base_regs);
    defer a.free(direct);
    const taint = try a.alloc(bool, direct.len);
    defer a.free(taint);
    @memset(direct, null);
    @memset(taint, false);
    for (p.base_insts) |i| {
        switch (i.op) {
            .trace_col, .preprocessed_col => {
                direct[i.dst] = if (i.interaction == 2) i else null;
                taint[i.dst] = i.interaction == 2;
            },
            .param, .constant => {
                direct[i.dst] = null;
                taint[i.dst] = false;
            },
            .add, .sub, .mul => {
                if (taint[i.a] or taint[i.b]) return error.UnsupportedOm31InteractionArithmetic;
                direct[i.dst] = null;
                taint[i.dst] = false;
            },
            .neg, .inv => {
                if (taint[i.a]) return error.UnsupportedOm31InteractionArithmetic;
                direct[i.dst] = null;
                taint[i.dst] = false;
            },
        }
    }
    for (p.ext_insts) |i| if (i.op == .secure_col) {
        const regs = [_]u32{ i.a, i.b, i.c, i.d };
        var inter = false;
        for (regs) |r| inter = inter or taint[r];
        if (inter) {
            const first = direct[regs[0]] orelse return error.InvalidOm31InteractionPack;
            if (first.a % 4 != 0) return error.InvalidOm31InteractionPack;
            for (regs, 0..) |r, j| {
                const loaded = direct[r] orelse return error.InvalidOm31InteractionPack;
                if (loaded.a != first.a + j or loaded.imm != first.imm or loaded.interaction != 2) return error.InvalidOm31InteractionPack;
            }
        }
    };
}
/// Read parameters and all OODS masks in OM31. Quartic constants and gate
/// semantics embed in its inner subfield; lookup parameters never truncate.
pub const Scratch = struct {
    allocator: std.mem.Allocator,
    base: []O,
    extension: []O,
    pub fn init(a: std.mem.Allocator, p: Program) !Scratch {
        const base = try a.alloc(O, p.header.max_base_regs);
        errdefer a.free(base);
        return .{ .allocator = a, .base = base, .extension = try a.alloc(O, p.header.max_ext_regs) };
    }
    pub fn deinit(self: *@This()) void {
        self.allocator.free(self.base);
        self.allocator.free(self.extension);
        self.* = undefined;
    }
    /// Domain workers reuse one register bank and root buffer for an entire
    /// row tile. No witness planes, parameter arrays or masks are rebuilt here.
    pub fn evaluateInto(self: *Scratch, p: Program, reader: Reader, parameters: []const O, roots: []O) !void {
        if (p.header.n_base_params != 0 or p.header.n_ext_params != parameters.len or roots.len != p.constraint_roots.len or self.base.len < p.header.max_base_regs or self.extension.len < p.header.max_ext_regs) return error.InvalidOm31Parameters;
        const base = self.base;
        const ext = self.extension;
        for (p.base_insts) |i| base[i.dst] = switch (i.op) {
            .trace_col, .preprocessed_col => try reader.read(i.interaction, i.a, i.imm),
            .param => return error.InvalidOm31Parameters,
            .constant => O.fromBase(M.fromCanonical(i.a)),
            .add => base[i.a].add(base[i.b]),
            .sub => base[i.a].sub(base[i.b]),
            .mul => base[i.a].mul(base[i.b]),
            .neg => base[i.a].neg(),
            .inv => try base[i.a].inv(),
        };
        for (p.ext_insts) |i| ext[i.dst] = switch (i.op) {
            .secure_col => pack4(.{ base[i.a], base[i.b], base[i.c], base[i.d] }),
            .param => parameters[i.a],
            .constant => embed(Q.fromU32Unchecked(i.a, i.b, i.c, i.d)),
            .add => ext[i.a].add(ext[i.b]),
            .sub => ext[i.a].sub(ext[i.b]),
            .mul => ext[i.a].mul(ext[i.b]),
            .neg => ext[i.a].neg(),
        };
        for (roots, p.constraint_roots) |*out, index| out.* = ext[index];
    }
};
/// Convenience for isolated OODS evaluation; DOMAIN callers retain Scratch.
pub fn evaluate(a: std.mem.Allocator, p: Program, reader: Reader, parameters: []const O) ![]O {
    var scratch = try Scratch.init(a, p);
    defer scratch.deinit();
    const roots = try a.alloc(O, p.constraint_roots.len);
    errdefer a.free(roots);
    try scratch.evaluateInto(p, reader, parameters, roots);
    return roots;
}
