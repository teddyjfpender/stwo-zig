//! Conservative field-shape facts from the typed instruction stream only.
const std = @import("std");
const eval = @import("../witness/eval_program.zig");
const M31 = @import("stwo_core").fields.m31.M31;
pub const Kind = enum { zero, one, base, secure };
pub const Facts = struct {
    base: []?u32,
    extended: []Kind,
    pub fn init(allocator: std.mem.Allocator, program: eval.Program) !Facts {
        const base = try allocator.alloc(?u32, program.header.max_base_regs);
        errdefer allocator.free(base);
        const extended = try allocator.alloc(Kind, program.header.max_ext_regs);
        @memset(base, null);
        @memset(extended, .secure);
        return .{ .base = base, .extended = extended };
    }
    pub fn deinit(self: Facts, allocator: std.mem.Allocator) void {
        allocator.free(self.base);
        allocator.free(self.extended);
    }
    pub fn isBaseZero(self: Facts, index: u32) bool {
        return self.base[index] != null and self.base[index].? == 0;
    }
    pub fn isBaseOne(self: Facts, index: u32) bool {
        return self.base[index] != null and self.base[index].? == 1;
    }
    pub fn baseValue(self: Facts, i: eval.BaseInst) ?u32 {
        switch (i.op) {
            .constant => return i.a,
            .trace_col, .preprocessed_col, .param => return null,
            .add, .sub, .mul => {
                const a = self.base[i.a];
                const b = self.base[i.b];
                if (i.op == .mul and (self.isBaseZero(i.a) or self.isBaseZero(i.b))) return 0;
                if (a == null or b == null) return null;
                const lhs = M31.fromU32Unchecked(a.?);
                const rhs = M31.fromU32Unchecked(b.?);
                return (switch (i.op) {
                    .add => lhs.add(rhs),
                    .sub => lhs.sub(rhs),
                    else => lhs.mul(rhs),
                }).toU32();
            },
            .neg, .inv => {
                const value = self.base[i.a] orelse return null;
                const field = M31.fromU32Unchecked(value);
                return (if (i.op == .neg) M31.zero().sub(field) else if (value == 0) M31.zero() else field.inv() catch unreachable).toU32();
            },
        }
    }
    pub fn extensionKind(self: Facts, i: eval.ExtInst) Kind {
        return switch (i.op) {
            .param => .secure,
            .constant => if (i.b == 0 and i.c == 0 and i.d == 0) scalarKind(i.a) else .secure,
            .secure_col => if (self.isBaseZero(i.b) and self.isBaseZero(i.c) and self.isBaseZero(i.d))
                if (self.base[i.a]) |value| scalarKind(value) else .base
            else
                .secure,
            .neg => switch (self.extended[i.a]) {
                .zero => .zero,
                .one, .base => .base,
                .secure => .secure,
            },
            .add, .sub => if (self.extended[i.b] == .zero) self.extended[i.a] else if (i.op == .add and self.extended[i.a] == .zero) self.extended[i.b] else if (self.extended[i.a] != .secure and self.extended[i.b] != .secure) .base else .secure,
            .mul => if (self.extended[i.a] == .zero or self.extended[i.b] == .zero) .zero else if (self.extended[i.a] == .one) self.extended[i.b] else if (self.extended[i.b] == .one) self.extended[i.a] else if (self.extended[i.a] != .secure and self.extended[i.b] != .secure) .base else .secure,
        };
    }
};
fn scalarKind(value: u32) Kind {
    return if (value == 0) .zero else if (value == 1) .one else .base;
}
