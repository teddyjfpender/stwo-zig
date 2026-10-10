//! Emit Lean expressions from the exact comptime trees used by
//! `evaluateQm31Ops`. This is a source bridge, not a proof of STARK/PCS.
const std = @import("std");
const tree = @import("air_eval/manual/eval_tree.zig");
const circuit = @import("air_eval/manual/circuit.zig");

const operands = [_][]const u8{
    "f.add", "f.sub", "f.mul", "f.pointwiseMul",
    "x.a", "x.b", "x.c", "x.d",
    "y.a", "y.b", "y.c", "y.d",
    "output.a", "output.b", "output.c", "output.d",
};

fn writeExpr(comptime node: tree.Node, writer: *std.Io.Writer) !void {
    switch (node) {
        .operand => |index| {
            if (index >= operands.len) return error.InvalidOperandIndex;
            try writer.print("{s}", .{operands[index]});
        },
        .literal => |value| try writer.print("({d} : F)", .{value}),
        inline .add, .sub, .mul => |children, op| {
            const symbol = switch (op) {
                .add => "+",
                .sub => "-",
                .mul => "*",
                else => comptime unreachable,
            };
            try writer.writeByte('(');
            try writeExpr(children[0].*, writer);
            try writer.print(" {s} ", .{symbol});
            try writeExpr(children[1].*, writer);
            try writer.writeByte(')');
        },
    }
}

pub fn main() !void {
    var buffer: [4096]u8 = undefined;
    var stdout = std.fs.File.stdout().writer(&buffer);
    const writer = &stdout.interface;
    try writer.writeAll(
        "import S31.Gadgets.Air.Qm31Ops\n\n" ++
        "/-! Generated from the native qm31_ops constraint trees. Do not edit. -/\n" ++
        "namespace S31.Gadgets.Air.NativeQm31Air\n" ++
        "open S31.Gadgets.Packed\n" ++
        "open S31.Gadgets.Air.Qm31Ops\n\n" ++
        "def residuals (f : Flags) (x y output : Quad) : List F := [\n",
    );
    inline for (circuit.qm31_ops_constraint_trees, 0..) |constraint, index| {
        if (index != 0) try writer.writeAll(",\n");
        try writer.writeAll("  ");
        try writeExpr(constraint, writer);
    }
    try writer.writeAll("\n]\n\nend S31.Gadgets.Air.NativeQm31Air\n");
    try writer.flush();
}
