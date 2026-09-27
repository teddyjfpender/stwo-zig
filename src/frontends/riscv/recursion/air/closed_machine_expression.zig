//! Shared lowering/evaluation of the validated, closed machine-expression set.
//! This is not a cast API: language validation owns every permitted use.
const expr = @import("../../air/lang/expr.zig");
const types = @import("../../air/lang/types.zig");
const digest = @import("../../air/lang/digest.zig");
const M = @import("stwo_core").fields.m31.M31;
pub fn supportedFormat(version: u16) bool {
    return version == digest.typed_effect_format_version or version == digest.register_group_format_version or
        version == digest.memory_access_format_version or version == digest.sequential_retirement_format_version;
}
pub fn operands(value: expr.MachineDerived) [3]?types.ValueId {
    return switch (value) {
        .register_address => |v| .{ v.index, null, null },
        .aligned_word_address => |v| .{ v.word_index, null, null },
        .instruction_next_pc => |v| .{ v.current, null, null },
        .instruction_next_clock => |v| .{ v.current, null, null },
        .access_clock => |v| .{ v.instruction_clock, null, null },
        .strict_clock_gap => |v| .{ v.current_clock, v.previous_clock, v.active },
    };
}
pub fn mapped(value: expr.MachineDerived, mapper: anytype) !expr.MachineDerived {
    return switch (value) {
        .register_address => |v| .{ .register_address = .{ .index = try mapper.get(v.index) } },
        .aligned_word_address => |v| .{ .aligned_word_address = .{ .word_index = try mapper.get(v.word_index) } },
        .instruction_next_pc => |v| .{ .instruction_next_pc = .{ .current = try mapper.get(v.current) } },
        .instruction_next_clock => |v| .{ .instruction_next_clock = .{ .current = try mapper.get(v.current) } },
        .access_clock => |v| .{ .access_clock = .{ .instruction_clock = try mapper.get(v.instruction_clock), .phase = v.phase } },
        .strict_clock_gap => |v| .{ .strict_clock_gap = .{ .current_clock = try mapper.get(v.current_clock), .previous_clock = try mapper.get(v.previous_clock), .active = try mapper.get(v.active), .phase = v.phase } },
    };
}
fn constant(comptime S: type, value: u32) S {
    return if (S == M) M.fromCanonical(value) else S.fromBase(M.fromCanonical(value));
}
pub fn evaluate(comptime S: type, op: expr.MachineDerived, values: anytype) S {
    return switch (op) {
        .register_address => |v| values[types.idIndex(v.index)],
        .aligned_word_address => |v| values[types.idIndex(v.word_index)].mul(constant(S, 4)),
        .instruction_next_pc => |v| values[types.idIndex(v.current)].add(constant(S, 4)),
        .instruction_next_clock => |v| values[types.idIndex(v.current)].add(constant(S, 1)),
        .access_clock => |v| values[types.idIndex(v.instruction_clock)].sub(constant(S, 1)).mul(constant(S, 4)).add(constant(S, @intFromEnum(v.phase))),
        .strict_clock_gap => |v| values[types.idIndex(v.current_clock)].sub(values[types.idIndex(v.previous_clock)]).sub(constant(S, 1)),
    };
}
