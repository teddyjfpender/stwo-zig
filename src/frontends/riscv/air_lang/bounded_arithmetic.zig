//! Proof-preserving bounded arithmetic for typed AIR effects.
//!
//! Ordinary AIR arithmetic remains `.felt`. These explicit constructors retain
//! only bounds derivable from typed operands and unsigned constants, reject
//! M31 aliases, and share their inference routine with structural validation.

const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const expr = @import("expr.zig");
const source = @import("source.zig");
const types = @import("types.zig");

pub const Operation = enum { add, mul };
pub const MAX_ONE_HOT_INPUTS: usize = 5;
pub const Error = error{
    BoundedResultOutOfField,
    InvalidBoundedOperand,
    InvalidOneHotSelector,
    UnknownValue,
};

pub fn build(
    arena: anytype,
    comptime operation: Operation,
    lhs: types.ValueId,
    rhs: types.ValueId,
    span: source.SourceSpan,
) !types.ValueId {
    const result_type = try resultType(arena, operation, lhs, rhs);
    var pair = expr.Binary{ .lhs = lhs, .rhs = rhs };
    if (types.idIndex(pair.rhs) < types.idIndex(pair.lhs))
        std.mem.swap(types.ValueId, &pair.lhs, &pair.rhs);
    return arena.internTypedNode(.{
        .ty = result_type,
        .op = switch (operation) {
            .add => .{ .add = pair },
            .mul => .{ .mul = pair },
        },
    }, span);
}

pub fn oneHotSelector(
    arena: anytype,
    values: []const types.ValueId,
    span: source.SourceSpan,
) !types.ValueId {
    if (values.len < 2 or values.len > MAX_ONE_HOT_INPUTS)
        return error.InvalidOneHotSelector;
    for (values, 0..) |value, index| {
        const node = arena.node(value) orelse return error.UnknownValue;
        if (!std.meta.eql(node.key.ty, types.Type.bit))
            return error.InvalidOneHotSelector;
        for (values[0..index]) |prior| if (prior == value)
            return error.InvalidOneHotSelector;
    }
    const checkpoint = arena.nodeCheckpoint();
    errdefer arena.rollbackToNodeCheckpoint(checkpoint);
    var sum = values[0];
    for (values[1 .. values.len - 1]) |value|
        sum = try arena.add(sum, value, span);
    var pair = expr.Binary{ .lhs = sum, .rhs = values[values.len - 1] };
    if (types.idIndex(pair.rhs) < types.idIndex(pair.lhs))
        std.mem.swap(types.ValueId, &pair.lhs, &pair.rhs);
    return arena.internTypedNode(.{
        .ty = .selector,
        .op = .{ .add = pair },
    }, span);
}

pub fn resultType(
    arena: anytype,
    operation: Operation,
    lhs: types.ValueId,
    rhs: types.ValueId,
) Error!types.Type {
    const lhs_max = try valueMaximum(arena, lhs);
    const rhs_max = try valueMaximum(arena, rhs);
    const maximum = switch (operation) {
        .add => std.math.add(u64, lhs_max, rhs_max) catch
            return error.BoundedResultOutOfField,
        .mul => std.math.mul(u64, lhs_max, rhs_max) catch
            return error.BoundedResultOutOfField,
    };
    if (maximum >= m31.Modulus) return error.BoundedResultOutOfField;
    if (maximum <= 1) return .bit;
    if (maximum == std.math.maxInt(u8)) return .byte;
    const bits: u8 = @intCast(std.math.log2_int(u64, maximum) + 1);
    return types.Type.boundedField(bits) catch
        return error.BoundedResultOutOfField;
}

fn valueMaximum(arena: anytype, value: types.ValueId) Error!u64 {
    const node = arena.node(value) orelse return error.UnknownValue;
    switch (node.key.op) {
        .constant => |constant| switch (constant) {
            .unsigned => |constant_value| return constant_value,
            .field => return error.InvalidBoundedOperand,
        },
        .add, .mul => |binary| if (!std.meta.eql(node.key.ty, types.Type.felt) and
            !std.meta.eql(node.key.ty, types.Type.selector))
        {
            const lhs = try valueMaximum(arena, binary.lhs);
            const rhs = try valueMaximum(arena, binary.rhs);
            return switch (node.key.op) {
                .add => std.math.add(u64, lhs, rhs) catch
                    error.BoundedResultOutOfField,
                .mul => std.math.mul(u64, lhs, rhs) catch
                    error.BoundedResultOutOfField,
                else => unreachable,
            };
        },
        else => {},
    }
    return switch (node.key.ty) {
        .bit, .selector => 1,
        .byte => std.math.maxInt(u8),
        .uint16 => std.math.maxInt(u16),
        .uint20 => (1 << 20) - 1,
        .register_index => 31,
        .bounded_uint => |bounded| switch (bounded.representation) {
            .canonical_field => (@as(u64, 1) << @intCast(bounded.bits)) - 1,
            .little_endian_limbs => error.InvalidBoundedOperand,
        },
        else => error.InvalidBoundedOperand,
    };
}
