//! Scalar OM31 extension of the authenticated quartic AIR instruction stream.
//! Its V1 bytecode/semantic hash is never re-labelled as an eight-coordinate ABI.
//! This explicit lens and field embedding are separately bound by the profile.
const std = @import("std");
const C = @import("stwo_cairo_frontend").witness;
const P = @import("protocol.zig");
pub const Program = C.eval_program.Program;
pub const ForLane = @import("program_lane.zig").ForLane;
const Native = ForLane(P.O);
pub const Reader = Native.Reader;
pub const Scratch = Native.Scratch;
pub const embed = Native.embed;
pub const pack4 = Native.pack4;
pub const evaluate = Native.evaluate;
pub const parameters = Native.extensionParameters;

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
