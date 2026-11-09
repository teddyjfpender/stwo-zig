//! Compatibility-exact direct polynomial authorship for RV32 FENCE.

const std = @import("std");
const ir = @import("ir.zig");
const source = @import("source.zig");
const types = @import("types.zig");

pub const DIRECT_CONSTRAINT_COUNT: usize = 2;

pub const Result = struct {
    opcode: types.ValueId,
    constraints: [DIRECT_CONSTRAINT_COUNT]types.ConstraintId,
    roots: [DIRECT_CONSTRAINT_COUNT]types.ValueId,
};

pub fn author(
    arena: *ir.Arena,
    enabler: types.ValueId,
    is_active: types.ValueId,
    span: source.SourceSpan,
) !Result {
    const one = try arena.constantField(1, span);
    const opcode = try arena.constantField(45, span);
    const roots = [DIRECT_CONSTRAINT_COUNT]types.ValueId{
        try arena.mul(enabler, try arena.sub(enabler, one, span), span),
        try arena.sub(enabler, is_active, span),
    };
    var constraints: [DIRECT_CONSTRAINT_COUNT]types.ConstraintId = undefined;
    for (&constraints, roots, 0..) |*constraint, root, index| {
        var name_buffer: [64]u8 = undefined;
        const name = try std.fmt.bufPrint(
            &name_buffer,
            "compat.riscv.fence.direct.{d}",
            .{index},
        );
        constraint.* = try arena.assertZero(name, root, null, .semantic, span);
    }
    return .{ .opcode = opcode, .constraints = constraints, .roots = roots };
}
