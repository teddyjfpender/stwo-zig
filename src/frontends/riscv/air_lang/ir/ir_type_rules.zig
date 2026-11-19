//! Dependency-light type and effect rules shared by the logical AIR arena.

const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const program = @import("program.zig");
const types = @import("types.zig");

pub fn isFieldScalar(ty: types.Type) bool {
    return ty.isFieldScalar();
}

pub fn maxUnsignedValue(ty: types.Type) error{UnsupportedConstantType}!u32 {
    return switch (ty) {
        .bit, .selector => 1,
        .byte => std.math.maxInt(u8),
        .uint16 => std.math.maxInt(u16),
        .uint20 => (1 << 20) - 1,
        .register_index => 31,
        .word32, .address, .pc => std.math.maxInt(u32),
        .clock => m31.Modulus - 1,
        .bounded_uint => |bounded| if (bounded.bits == 32)
            std.math.maxInt(u32)
        else
            (@as(u32, 1) << @intCast(bounded.bits)) - 1,
        .felt, .array => error.UnsupportedConstantType,
    };
}

pub fn isSelector(ty: types.Type) bool {
    return ty.isSelector();
}

pub fn requiresAccessOrdinal(kind: program.EffectKind) bool {
    return switch (kind) {
        .register_read,
        .register_write,
        .memory_read,
        .memory_write,
        => true,
        else => false,
    };
}
