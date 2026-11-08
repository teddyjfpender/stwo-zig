//! Original pinned circuit AIR, with the validated octic interaction lens.
//! The existing quartic emitter and its generated source remain unchanged.
const std = @import("std");
const frontend = @import("stwo_cairo").frontends.cairo;
const eval = frontend.witness.eval_program;
const shared = frontend.codegen.eval_program;
const shapes = frontend.codegen.field_shapes;

pub fn generate(a: std.mem.Allocator, p: eval.Program, index: usize, w: *std.Io.Writer) !void {
    if (p.header.n_base_params != 0) return error.UnsupportedBaseParameters;
    try w.writeAll(@embedFile("prelude.h"));
    try w.writeAll(@embedFile("om31_prelude.h"));
    const last = try a.alloc(usize, p.header.max_ext_regs);
    defer a.free(last);
    @memset(last, std.math.maxInt(usize));
    for (p.ext_insts, 0..) |i, at| last[i.dst] = at;
    const inter = try a.alloc(bool, p.header.max_base_regs);
    defer a.free(inter);
    @memset(inter, false);
    const high_declared = try a.alloc(bool, inter.len);
    defer a.free(high_declared);
    @memset(high_declared, false);
    var visitor = Visitor{ .w = w, .a = a, .last = last, .roots = p.constraint_roots, .inter = inter, .high_declared = high_declared, .facts = try shapes.Facts.init(a, p) };
    defer visitor.facts.deinit(a);
    defer visitor.offsets.deinit(a);
    try w.print("\nvoid cairo_cpu_air_om31_{d}(const ORange *r) {{\nfor(size_t row=r->first;row<r->end;row+=4) {{\nO acc=oz();\n", .{index});
    for (p.base_insts) |i| {
        if (i.op != .trace_col and i.op != .preprocessed_col) continue;
        const slot = try visitor.offset(i.imm);
        if (slot.new) try w.print("size_t p{d}[4];for(int lane=0;lane<4;lane++)p{d}[lane]=omapped_index(row+lane,r,{d});\n", .{ slot.id, slot.id, i.imm });
    }
    try shared.walk(a, p, 0, &visitor);
    try w.writeAll("ostore(r,row,acc);\n}\n}\n");
}

const Visitor = struct {
    w: *std.Io.Writer,
    a: std.mem.Allocator,
    offsets: std.ArrayList(i32) = .empty,
    read: usize = 0,
    inter: []bool,
    high_declared: []bool,
    last: []const usize,
    roots: []const u32,
    ext_cursor: usize = 0,
    root_cursor: usize = 0,
    facts: shapes.Facts,
    fn offset(self: *Visitor, value: i32) !struct { id: usize, new: bool } {
        for (self.offsets.items, 0..) |v, j| if (v == value) return .{ .id = j, .new = false };
        try self.offsets.append(self.a, value);
        return .{ .id = self.offsets.items.len - 1, .new = true };
    }
    pub fn base(self: *Visitor, step: shared.BaseStep) !void {
        const i = step.instruction;
        const w = self.w;
        const known = self.facts.baseValue(i);
        try w.print("{s}b{d}=", .{ if (step.declare) "V " else "", i.dst });
        if (known) |v| {
            try w.print("vs({d}U)", .{v});
        } else switch (i.op) {
            .trace_col, .preprocessed_col => {
                const slot = try self.offset(i.imm);
                try w.print("gather(r->sites[{d}],p{d})", .{ self.read, slot.id });
                self.read += 1;
            },
            .param => return error.UnsupportedBaseParameters,
            .constant => try w.print("vs({d}U)", .{i.a}),
            .add, .sub, .mul => try w.print("{s}(b{d},b{d})", .{ switch (i.op) {
                .add => "va",
                .sub => "vb",
                else => "vm",
            }, i.a, i.b }),
            .neg, .inv => try w.print("{s}(b{d})", .{ if (i.op == .neg) "vn" else "vi", i.a }),
        }
        try w.writeAll(";\n");
        const direct = (i.op == .trace_col or i.op == .preprocessed_col) and i.interaction == 2;
        self.inter[i.dst] = direct;
        if (direct) {
            const slot = try self.offset(i.imm);
            try w.print("{s}h{d}=gather(r->sites[{d}],p{d});\n", .{ if (self.high_declared[i.dst]) "" else "V ", i.dst, self.read, slot.id });
            self.high_declared[i.dst] = true;
            self.read += 1;
        }
        self.facts.base[i.dst] = known;
    }
    pub fn extended(self: *Visitor, step: shared.ExtStep) !void {
        const i = step.instruction;
        const w = self.w;
        try w.print("{s}e{d}=", .{ if (step.declare) "O " else "", i.dst });
        const kind = self.facts.extensionKind(i);
        if (kind == .zero) {
            try w.writeAll("oz()");
        } else switch (i.op) {
            .secure_col => {
                const wide = self.inter[i.a];
                if (self.inter[i.b] != wide or self.inter[i.c] != wide or self.inter[i.d] != wide) return error.InvalidOm31Lens;
                try w.print("(O){{{{b{d},b{d},b{d},b{d},", .{ i.a, i.b, i.c, i.d });
                if (wide) try w.print("h{d},h{d},h{d},h{d}", .{ i.a, i.b, i.c, i.d }) else try w.writeAll("vs(0),vs(0),vs(0),vs(0)");
                try w.writeAll("}}");
            },
            .param => try w.print("os(r->parameters+8*{d})", .{i.a}),
            .constant => try w.print("(O){{{{vs({d}U),vs({d}U),vs({d}U),vs({d}U),vs(0),vs(0),vs(0),vs(0)}}}}", .{ i.a, i.b, i.c, i.d }),
            .add, .sub, .mul => {
                const lhs = self.facts.extended[i.a];
                const rhs = self.facts.extended[i.b];
                if ((i.op == .add or i.op == .sub) and rhs == .zero) {
                    try w.print("e{d}", .{i.a});
                } else if (i.op == .add and lhs == .zero) {
                    try w.print("e{d}", .{i.b});
                } else if (i.op == .mul and lhs == .one) {
                    try w.print("e{d}", .{i.b});
                } else if (i.op == .mul and rhs == .one) {
                    try w.print("e{d}", .{i.a});
                } else if (i.op == .mul and lhs != .secure) {
                    try w.print("omb(e{d},e{d}.x[0])", .{ i.b, i.a });
                } else if (i.op == .mul and rhs != .secure) {
                    try w.print("omb(e{d},e{d}.x[0])", .{ i.a, i.b });
                } else try w.print("{s}(e{d},e{d})", .{ switch (i.op) {
                    .add => "oa",
                    .sub => "ob",
                    else => "om",
                }, i.a, i.b });
            },
            .neg => try w.print("on(e{d})", .{i.a}),
        }
        self.facts.extended[i.dst] = kind;
        try w.writeAll(";\n");
        self.ext_cursor += 1;
        while (self.root_cursor < self.roots.len and self.last[self.roots[self.root_cursor]] < self.ext_cursor) {
            try self.emitRoot(self.roots[self.root_cursor], self.root_cursor);
            self.root_cursor += 1;
        }
    }
    pub fn beginConstraints(self: *Visitor) !void {
        if (self.root_cursor != self.roots.len) return error.UnemittedConstraint;
    }
    pub fn constraint(_: *Visitor, _: shared.ConstraintStep) !void {}
    fn emitRoot(self: *Visitor, root: u32, index: usize) !void {
        switch (self.facts.extended[root]) {
            .zero => {},
            .one => try self.w.print("acc=oa(acc,os(r->coefficients+8*(r->constraint_base+{d})));\n", .{index}),
            .base => try self.w.print("acc=oa(acc,omb(os(r->coefficients+8*(r->constraint_base+{d})),e{d}.x[0]));\n", .{ index, root }),
            .secure => try self.w.print("acc=oa(acc,om(e{d},os(r->coefficients+8*(r->constraint_base+{d}))));\n", .{ root, index }),
        }
    }
};
