//! Shared compiler helpers for the three recursion arithmetic components.

const ir = @import("../../air/lang/ir.zig");
const source = @import("../../air/lang/source.zig");
const types = @import("../../air/lang/types.zig");

pub fn selectSchedule(
    comptime field_count: usize,
    arena: *ir.Arena,
    modes: [3][field_count]types.ValueId,
    active: [3]types.ValueId,
    span: source.SourceSpan,
) ![field_count]types.ValueId {
    var selected: [field_count]types.ValueId = undefined;
    for (&selected, 0..) |*value, field| {
        value.* = try arena.add(
            try arena.add(
                try arena.mul(active[0], modes[0][field], span),
                try arena.mul(active[1], modes[1][field], span),
                span,
            ),
            try arena.mul(active[2], modes[2][field], span),
            span,
        );
    }
    return selected;
}

pub fn booleanRoot(
    arena: *ir.Arena,
    value: types.ValueId,
    one: types.ValueId,
    span: source.SourceSpan,
) !types.ValueId {
    return arena.mul(value, try arena.sub(one, value, span), span);
}
