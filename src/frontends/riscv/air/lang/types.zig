//! Semantic types and non-interchangeable IDs for the typed AIR language.
//!
//! These types carry meaning only. Claiming that a value is a byte or bounded
//! integer does not silently add a constraint; reviewed builder constructors
//! must either emit the evidence or consume an already constrained value.

const std = @import("std");

pub const ValueId = enum(u32) { _ };
pub const ConstraintId = enum(u32) { _ };
pub const EffectId = enum(u32) { _ };
pub const HintId = enum(u32) { _ };
pub const FunctionId = enum(u32) { _ };
pub const CallId = enum(u32) { _ };
pub const NameId = enum(u32) { _ };
pub const SourceId = enum(u32) { _ };
pub const RelationSchemaId = enum(u16) { _ };

pub const IdError = error{IdOverflow};

/// Converts a collection index into one of this module's typed enum IDs.
pub fn idFromIndex(comptime Id: type, index: usize) IdError!Id {
    const info = @typeInfo(Id);
    if (info != .@"enum") @compileError("typed AIR ID must be an enum");
    const Tag = info.@"enum".tag_type;
    const raw = std.math.cast(Tag, index) orelse return error.IdOverflow;
    return @enumFromInt(raw);
}

pub fn idIndex(id: anytype) usize {
    const Id = @TypeOf(id);
    if (@typeInfo(Id) != .@"enum") @compileError("typed AIR ID must be an enum");
    return @intFromEnum(id);
}

pub const TypeError = error{
    ZeroBitWidth,
    BitWidthTooWide,
    FieldRepresentationNotInjective,
    InvalidLimbWidth,
    InvalidLimbCount,
    LimbWidthMismatch,
    EmptyArray,
};

pub const LimbLayout = struct {
    limb_bits: u8,
    limb_count: u8,

    pub fn validate(self: LimbLayout, bits: u8) TypeError!void {
        if (self.limb_bits == 0 or self.limb_bits > 16)
            return error.InvalidLimbWidth;
        if (self.limb_count == 0 or self.limb_count > 8)
            return error.InvalidLimbCount;
        const represented_bits =
            @as(u16, self.limb_bits) * @as(u16, self.limb_count);
        if (represented_bits != bits) return error.LimbWidthMismatch;
    }
};

pub const UIntRepresentation = union(enum) {
    /// One canonical M31 element. Power-of-two bounds are restricted to at
    /// most 30 bits so the representation is injective without an additional
    /// less-than-modulus predicate.
    canonical_field,
    little_endian_limbs: LimbLayout,
};

pub const BoundedUInt = struct {
    bits: u8,
    representation: UIntRepresentation,

    pub fn validate(self: BoundedUInt) TypeError!void {
        if (self.bits == 0) return error.ZeroBitWidth;
        if (self.bits > 32) return error.BitWidthTooWide;
        switch (self.representation) {
            .canonical_field => if (self.bits > 30)
                return error.FieldRepresentationNotInjective,
            .little_endian_limbs => |layout| try layout.validate(self.bits),
        }
    }
};

/// Static arrays deliberately begin with atomic elements. Nested arrays and
/// arrays of custom bounded representations can be added when a real
/// component requires them, without making IR v0 recursively self-describing.
pub const ArrayElement = enum {
    felt,
    bit,
    byte,
    uint16,
    uint20,
    word32,
    register_index,
    address,
    pc,
    clock,
    selector,
};

pub const StaticArray = struct {
    element: ArrayElement,
    len: u16,

    pub fn validate(self: StaticArray) TypeError!void {
        if (self.len == 0) return error.EmptyArray;
    }
};

pub const Type = union(enum) {
    felt,
    bit,
    byte,
    uint16,
    uint20,
    word32,
    register_index,
    address,
    pc,
    clock,
    selector,
    bounded_uint: BoundedUInt,
    array: StaticArray,

    pub fn validate(self: Type) TypeError!void {
        switch (self) {
            .bounded_uint => |bounded| try bounded.validate(),
            .array => |array| try array.validate(),
            else => {},
        }
    }

    pub fn boundedField(bits: u8) TypeError!Type {
        const result = Type{ .bounded_uint = .{
            .bits = bits,
            .representation = .canonical_field,
        } };
        try result.validate();
        return result;
    }

    pub fn boundedLimbs(
        bits: u8,
        limb_bits: u8,
        limb_count: u8,
    ) TypeError!Type {
        const result = Type{ .bounded_uint = .{
            .bits = bits,
            .representation = .{
                .little_endian_limbs = .{
                    .limb_bits = limb_bits,
                    .limb_count = limb_count,
                },
            },
        } };
        try result.validate();
        return result;
    }

    pub fn staticArray(element: ArrayElement, len: u16) TypeError!Type {
        const result = Type{ .array = .{ .element = element, .len = len } };
        try result.validate();
        return result;
    }

    pub fn isFieldScalar(self: Type) bool {
        return switch (self) {
            .felt,
            .bit,
            .byte,
            .uint16,
            .uint20,
            .register_index,
            .clock,
            .selector,
            => true,
            .bounded_uint => |bounded| switch (bounded.representation) {
                .canonical_field => true,
                .little_endian_limbs => false,
            },
            .word32, .address, .pc, .array => false,
        };
    }

    pub fn isSelector(self: Type) bool {
        return switch (self) {
            .bit, .selector => true,
            else => false,
        };
    }
};
