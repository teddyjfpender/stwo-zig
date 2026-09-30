//! Exact root dependency closures for bounded CUDA AIR function frames.
//! Reverse traversal versions imperative writes implicitly: a selected write
//! kills its destination requirement before adding its operand requirements.
const std = @import("std");
const eval = @import("stwo_cairo_frontend").witness.eval_program;

pub const Slice = struct {
    program: eval.Program,
    dynamic_constants: []bool,
    constant_offsets: []u32,

    pub fn init(a: std.mem.Allocator, original: eval.Program, first: usize, end: usize, dynamic: []const bool) !Slice {
        try original.validate();
        if (first >= end or end > original.constraint_roots.len) return error.InvalidConstraintSlice;
        const needed_base = try a.alloc(bool, original.header.max_base_regs);
        defer a.free(needed_base);
        const needed_ext = try a.alloc(bool, original.header.max_ext_regs);
        defer a.free(needed_ext);
        @memset(needed_base, false);
        @memset(needed_ext, false);
        const keep_base = try a.alloc(bool, original.base_insts.len);
        defer a.free(keep_base);
        const keep_ext = try a.alloc(bool, original.ext_insts.len);
        defer a.free(keep_ext);
        @memset(keep_base, false);
        @memset(keep_ext, false);
        for (original.constraint_roots[first..end]) |root| needed_ext[root] = true;
        var index = original.ext_insts.len;
        while (index > 0) {
            index -= 1;
            const inst = original.ext_insts[index];
            if (!needed_ext[inst.dst]) continue;
            keep_ext[index] = true;
            needed_ext[inst.dst] = false;
            switch (inst.op) {
                .secure_col => inline for (.{ inst.a, inst.b, inst.c, inst.d }) |reg| {
                    needed_base[reg] = true;
                },
                .add, .sub, .mul => {
                    needed_ext[inst.a] = true;
                    needed_ext[inst.b] = true;
                },
                .neg => needed_ext[inst.a] = true,
                else => {},
            }
        }
        index = original.base_insts.len;
        while (index > 0) {
            index -= 1;
            const inst = original.base_insts[index];
            if (!needed_base[inst.dst]) continue;
            keep_base[index] = true;
            needed_base[inst.dst] = false;
            switch (inst.op) {
                .add, .sub, .mul => {
                    needed_base[inst.a] = true;
                    needed_base[inst.b] = true;
                },
                .neg, .inv => needed_base[inst.a] = true,
                else => {},
            }
        }
        var base: std.ArrayList(eval.BaseInst) = .empty;
        defer base.deinit(a);
        var extended: std.ArrayList(eval.ExtInst) = .empty;
        defer extended.deinit(a);
        var constants: std.ArrayList(bool) = .empty;
        defer constants.deinit(a);
        var offsets: std.ArrayList(u32) = .empty;
        defer offsets.deinit(a);
        var constant_index: usize = 0;
        for (original.base_insts, keep_base) |inst, keep| {
            if (inst.op == .constant) {
                if (constant_index >= dynamic.len) return error.AirConstantExtentMismatch;
                if (keep) {
                    try constants.append(a, dynamic[constant_index]);
                    try offsets.append(a, @intCast(constant_index));
                }
                constant_index += 1;
            }
            if (keep) try base.append(a, inst);
        }
        if (constant_index != dynamic.len) return error.AirConstantExtentMismatch;
        for (original.ext_insts, keep_ext) |inst, keep| if (keep) {
            try extended.append(a, inst);
        };
        var program = try original.clone(a);
        errdefer program.deinit();
        const base_insts = try base.toOwnedSlice(a);
        a.free(program.base_insts);
        program.base_insts = base_insts;
        const ext_insts = try extended.toOwnedSlice(a);
        a.free(program.ext_insts);
        program.ext_insts = ext_insts;
        // Allocate before releasing the original to preserve error ownership.
        const roots = try a.dupe(u32, original.constraint_roots[first..end]);
        a.free(program.constraint_roots);
        program.constraint_roots = roots;
        program.header.n_constraints = @intCast(roots.len);
        program.header.semantic_hash = program.semanticHash();
        try program.validate();
        const mask = try constants.toOwnedSlice(a);
        errdefer a.free(mask);
        return .{ .program = program, .dynamic_constants = mask, .constant_offsets = try offsets.toOwnedSlice(a) };
    }

    pub fn deinit(self: *Slice) void {
        const a = self.program.allocator;
        a.free(self.constant_offsets);
        a.free(self.dynamic_constants);
        self.program.deinit();
    }
};
