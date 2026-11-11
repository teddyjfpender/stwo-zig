const std = @import("std");
const frontend = @import("stwo_cairo").frontends.cairo;
const eval = frontend.witness.eval_program;
const shared = frontend.codegen.eval_program;
const shapes = frontend.codegen.field_shapes;

pub fn generate(allocator: std.mem.Allocator, program: eval.Program, index: usize, writer: *std.Io.Writer) !void {
    if (program.header.n_base_params != 0) return error.UnsupportedBaseParameters;
    try writer.writeAll(@embedFile("prelude.h"));
    try writer.print("\nvoid cairo_cpu_air_{d}(const Range *r) {{\nfor(size_t row=r->first;row<r->end;row+=4) {{\n", .{index});
    const last_writes = try allocator.alloc(usize, program.header.max_ext_regs);
    defer allocator.free(last_writes);
    @memset(last_writes, std.math.maxInt(usize));
    for (program.ext_insts, 0..) |inst, position| last_writes[inst.dst] = position;
    try writer.writeAll("Q acc={{vs(0),vs(0),vs(0),vs(0)}};\n");
    const facts = try shapes.Facts.init(allocator, program);
    defer facts.deinit(allocator);
    var visitor = Visitor{ .writer = writer, .allocator = allocator, .last_writes = last_writes, .roots = program.constraint_roots, .facts = facts };
    defer visitor.offsets.deinit(allocator);
    // Read mapping follows exactly the shared resolver's first appearance order.
    for (program.base_insts) |inst| {
        if (inst.op != .trace_col and inst.op != .preprocessed_col) continue;
        const result = try visitor.offsetSlot(inst.imm);
        if (!result.new) continue;
        try writer.print("size_t p{d}[4];for(int lane=0;lane<4;lane++)p{d}[lane]=mapped_index(row+lane,r,{d});\n", .{ result.slot, result.slot, inst.imm });
    }
    try shared.walk(allocator, program, 0, &visitor);
    try writer.writeAll("store(r,row,acc);\n}\n}\n");
}
const Visitor = struct {
    writer: *std.Io.Writer,
    allocator: std.mem.Allocator,
    offsets: std.ArrayList(i32) = .empty,
    read_index: usize = 0,
    last_writes: []const usize,
    roots: []const u32,
    extension_cursor: usize = 0,
    root_cursor: usize = 0,
    facts: shapes.Facts,
    fn offsetSlot(self: *Visitor, offset: i32) !struct { slot: usize, new: bool } {
        for (self.offsets.items, 0..) |value, index| if (value == offset) return .{ .slot = index, .new = false };
        try self.offsets.append(self.allocator, offset);
        return .{ .slot = self.offsets.items.len - 1, .new = true };
    }
    pub fn base(self: *Visitor, step: shared.BaseStep) !void {
        const i = step.instruction;
        const w = self.writer;
        try w.print("{s}b{d}=", .{ if (step.declare) "V " else "", i.dst });
        const known = self.facts.baseValue(i);
        if (known) |value| {
            try w.print("vs({d}U)", .{value});
        } else switch (i.op) {
            .trace_col, .preprocessed_col => {
                const slot = try self.offsetSlot(i.imm);
                try w.print("gather(r->sites[{d}],p{d})", .{ self.read_index, slot.slot });
                self.read_index += 1;
            },
            .param => return error.UnsupportedBaseParameters,
            .constant => try w.print("vs({d}U)", .{i.a}),
            .add, .sub, .mul => {
                if ((i.op == .add or i.op == .sub) and self.facts.isBaseZero(i.b)) {
                    try w.print("b{d}", .{i.a});
                } else if (i.op == .add and self.facts.isBaseZero(i.a)) {
                    try w.print("b{d}", .{i.b});
                } else if (i.op == .mul and self.facts.isBaseOne(i.a)) {
                    try w.print("b{d}", .{i.b});
                } else if (i.op == .mul and self.facts.isBaseOne(i.b)) {
                    try w.print("b{d}", .{i.a});
                } else try w.print("{s}(b{d},b{d})", .{ switch (i.op) {
                    .add => "va",
                    .sub => "vb",
                    else => "vm",
                }, i.a, i.b });
            },
            .neg, .inv => try w.print("{s}(b{d})", .{ if (i.op == .neg) "vn" else "vi", i.a }),
        }
        self.facts.base[i.dst] = known;
        try w.writeAll(";\n");
    }
    pub fn extended(self: *Visitor, step: shared.ExtStep) !void {
        const i = step.instruction;
        const w = self.writer;
        try w.print("{s}e{d}=", .{ if (step.declare) "Q " else "", i.dst });
        const kind = self.facts.extensionKind(i);
        if (kind == .zero) {
            try w.writeAll("(Q){{vs(0),vs(0),vs(0),vs(0)}}");
        } else switch (i.op) {
            .secure_col => try w.print("(Q){{{{b{d},b{d},b{d},b{d}}}}}", .{ i.a, i.b, i.c, i.d }),
            .param => try w.print("qs(r->parameters+4*{d})", .{i.a}),
            .constant => try w.print("(Q){{{{vs({d}U),vs({d}U),vs({d}U),vs({d}U)}}}}", .{ i.a, i.b, i.c, i.d }),
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
                    try w.print("qmb(e{d},e{d}.x[0])", .{ i.b, i.a });
                } else if (i.op == .mul and rhs != .secure) {
                    try w.print("qmb(e{d},e{d}.x[0])", .{ i.a, i.b });
                } else try w.print("{s}(e{d},e{d})", .{ switch (i.op) {
                    .add => "qa",
                    .sub => "qb",
                    else => "qm",
                }, i.a, i.b });
            },
            .neg => try w.print("qn(e{d})", .{i.a}),
        }
        self.facts.extended[i.dst] = kind;
        try w.writeAll(";\n");
        self.extension_cursor += 1;
        // Accumulate in canonical root order as soon as each root's FINAL
        // definition is available. This shortens live ranges without moving
        // a contribution across a register rewrite or reordering additions.
        while (self.root_cursor < self.roots.len and
            self.last_writes[self.roots[self.root_cursor]] < self.extension_cursor)
        {
            try self.emitConstraint(self.roots[self.root_cursor], self.root_cursor);
            self.root_cursor += 1;
        }
    }
    pub fn beginConstraints(self: *Visitor) !void {
        if (self.root_cursor != self.roots.len) return error.UnemittedConstraint;
    }
    pub fn constraint(_: *Visitor, _: shared.ConstraintStep) !void {}
    fn emitConstraint(self: *Visitor, root: u32, index: usize) !void {
        switch (self.facts.extended[root]) {
            .zero => {},
            .one => try self.writer.print("acc=qa(acc,qs(r->coefficients+4*(r->constraint_base+{d})));\n", .{index}),
            .base => try self.writer.print("acc=qa(acc,qmb(qs(r->coefficients+4*(r->constraint_base+{d})),e{d}.x[0]));\n", .{ index, root }),
            .secure => try self.writer.print("acc=qa(acc,qm(e{d},qs(r->coefficients+4*(r->constraint_base+{d}))));\n", .{ root, index }),
        }
    }
};
