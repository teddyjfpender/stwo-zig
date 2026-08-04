//! Canonical binary serialization of a validated logical AIR program.
//!
//! The encoding is an identity surface, not an in-memory dump. It uses fixed
//! little-endian integers and explicit stable tags, writes semantically ordered
//! records in arena order, and resolves names and sources to bytes so allocator
//! addresses and interning-table insertion order cannot enter the artifact.

const std = @import("std");
const expr = @import("expr.zig");
const ir = @import("ir.zig");
const program = @import("program.zig");
const source = @import("source.zig");
const types = @import("types.zig");
const validate = @import("validate.zig");

pub const magic = "STWAIRL\x00";
pub const format_version: u16 = 1;
pub const logical_schema_version: u16 = 0;

pub const ManifestError = error{ManifestTooLarge};
pub const Error = std.mem.Allocator.Error || validate.Error || ManifestError;

pub fn serializeAlloc(
    allocator: std.mem.Allocator,
    arena: *const ir.Arena,
) Error![]u8 {
    try validate.validate(arena);
    var bytes: std.ArrayList(u8) = .empty;
    errdefer bytes.deinit(allocator);
    try writeValidated(bytes.writer(allocator), arena);
    return bytes.toOwnedSlice(allocator);
}

/// Writes one validated canonical encoding to `writer`.
pub fn writeCanonical(writer: anytype, arena: *const ir.Arena) !void {
    try validate.validate(arena);
    try writeValidated(writer, arena);
}

fn writeValidated(writer: anytype, arena: *const ir.Arena) !void {
    try writer.writeAll(magic);
    try writeInt(writer, u16, format_version);
    try writeInt(writer, u16, logical_schema_version);
    try writeCount(writer, arena.nodesView().len);
    try writeCount(writer, arena.constraintsView().len);
    try writeCount(writer, arena.hintsView().len);
    try writeCount(writer, arena.effectsView().len);
    try writeCount(writer, arena.functionsView().len);

    for (arena.nodesView()) |node| try writeNode(writer, arena, node);
    for (arena.constraintsView()) |constraint| {
        try writeName(writer, arena, constraint.name);
        try writeValueId(writer, constraint.root);
        try writeOptionalValueId(writer, constraint.gate);
        try writeInt(writer, u8, constraintCategoryTag(constraint.category));
        try writeSpan(writer, arena, constraint.source_span);
    }
    for (arena.hintsView(), 0..) |hint, index| {
        const id = types.idFromIndex(types.HintId, index) catch
            return error.ManifestTooLarge;
        try writeName(writer, arena, hint.recipe);
        try writeValues(writer, arena.hintInputs(id).?);
        try writeValues(writer, arena.hintOutputs(id).?);
        try writeSpan(writer, arena, hint.source_span);
    }
    for (arena.effectsView(), 0..) |effect, index| {
        const id = types.idFromIndex(types.EffectId, index) catch
            return error.ManifestTooLarge;
        try writeInt(writer, u8, effectKindTag(effect.kind));
        try writeValues(writer, arena.effectValues(id).?);
        try writeOptionalValueId(writer, effect.liveness);
        try writeOptionalInt(writer, u8, effect.access_ordinal);
        try writeSpan(writer, arena, effect.source_span);
    }
    for (arena.functionsView(), 0..) |function, index| {
        const id = types.idFromIndex(types.FunctionId, index) catch
            return error.ManifestTooLarge;
        try writeName(writer, arena, function.name);
        try writeValues(writer, arena.functionInputs(id).?);
        try writeValues(writer, arena.functionOutputs(id).?);
        try writeSpan(writer, arena, function.source_span);
    }
}

fn writeNode(writer: anytype, arena: *const ir.Arena, node: expr.Node) !void {
    try writeType(writer, node.key.ty);
    switch (node.key.op) {
        .constant => |constant| switch (constant) {
            .field => |value| {
                try writeInt(writer, u8, 0);
                try writeInt(writer, u32, value);
            },
            .unsigned => |value| {
                try writeInt(writer, u8, 1);
                try writeInt(writer, u32, value);
            },
        },
        .input => |name| {
            try writeInt(writer, u8, 2);
            try writeName(writer, arena, name);
        },
        .add => |binary| {
            try writeInt(writer, u8, 3);
            try writeBinary(writer, binary);
        },
        .sub => |binary| {
            try writeInt(writer, u8, 4);
            try writeBinary(writer, binary);
        },
        .mul => |binary| {
            try writeInt(writer, u8, 5);
            try writeBinary(writer, binary);
        },
        .neg => |value| {
            try writeInt(writer, u8, 6);
            try writeValueId(writer, value);
        },
        .select => |selection| {
            try writeInt(writer, u8, 7);
            try writeValueId(writer, selection.selector);
            try writeValueId(writer, selection.when_true);
            try writeValueId(writer, selection.when_false);
        },
        .hint_output => |output| {
            try writeInt(writer, u8, 8);
            try writeInt(writer, u32, @intFromEnum(output.hint));
            try writeInt(writer, u16, output.index);
        },
    }
    try writeSpan(writer, arena, node.primary_source);
}

fn writeType(writer: anytype, ty: types.Type) !void {
    switch (ty) {
        .felt => try writeInt(writer, u8, 0),
        .bit => try writeInt(writer, u8, 1),
        .byte => try writeInt(writer, u8, 2),
        .uint16 => try writeInt(writer, u8, 3),
        .uint20 => try writeInt(writer, u8, 4),
        .word32 => try writeInt(writer, u8, 5),
        .register_index => try writeInt(writer, u8, 6),
        .address => try writeInt(writer, u8, 7),
        .pc => try writeInt(writer, u8, 8),
        .clock => try writeInt(writer, u8, 9),
        .selector => try writeInt(writer, u8, 10),
        .bounded_uint => |bounded| {
            try writeInt(writer, u8, 11);
            try writeInt(writer, u8, bounded.bits);
            switch (bounded.representation) {
                .canonical_field => try writeInt(writer, u8, 0),
                .little_endian_limbs => |layout| {
                    try writeInt(writer, u8, 1);
                    try writeInt(writer, u8, layout.limb_bits);
                    try writeInt(writer, u8, layout.limb_count);
                },
            }
        },
        .array => |array| {
            try writeInt(writer, u8, 12);
            try writeInt(writer, u8, arrayElementTag(array.element));
            try writeInt(writer, u16, array.len);
        },
    }
}

fn writeSpan(
    writer: anytype,
    arena: *const ir.Arena,
    span: source.SourceSpan,
) !void {
    if (span.source) |source_id| {
        try writeInt(writer, u8, 1);
        try writeString(writer, arena.sourcePath(source_id).?);
        try writePosition(writer, span.start);
        try writePosition(writer, span.end);
    } else {
        try writeInt(writer, u8, 0);
    }
}

fn writePosition(writer: anytype, position: source.Position) !void {
    try writeInt(writer, u32, position.byte_offset);
    try writeInt(writer, u32, position.line);
    try writeInt(writer, u32, position.column);
}

fn writeName(writer: anytype, arena: *const ir.Arena, id: types.NameId) !void {
    try writeString(writer, arena.name(id).?);
}

fn writeString(writer: anytype, value: []const u8) !void {
    try writeCount(writer, value.len);
    try writer.writeAll(value);
}

fn writeValues(writer: anytype, values: []const types.ValueId) !void {
    try writeCount(writer, values.len);
    for (values) |value| try writeValueId(writer, value);
}

fn writeBinary(writer: anytype, binary: expr.Binary) !void {
    try writeValueId(writer, binary.lhs);
    try writeValueId(writer, binary.rhs);
}

fn writeValueId(writer: anytype, id: types.ValueId) !void {
    try writeInt(writer, u32, @intFromEnum(id));
}

fn writeOptionalValueId(writer: anytype, id: ?types.ValueId) !void {
    if (id) |value| {
        try writeInt(writer, u8, 1);
        try writeValueId(writer, value);
    } else {
        try writeInt(writer, u8, 0);
    }
}

fn writeOptionalInt(writer: anytype, comptime T: type, value: ?T) !void {
    if (value) |present| {
        try writeInt(writer, u8, 1);
        try writeInt(writer, T, present);
    } else {
        try writeInt(writer, u8, 0);
    }
}

fn writeCount(writer: anytype, value: usize) !void {
    const count = std.math.cast(u32, value) orelse
        return error.ManifestTooLarge;
    try writeInt(writer, u32, count);
}

fn writeInt(writer: anytype, comptime T: type, value: T) !void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, value, .little);
    try writer.writeAll(&encoded);
}

fn arrayElementTag(element: types.ArrayElement) u8 {
    return switch (element) {
        .felt => 0,
        .bit => 1,
        .byte => 2,
        .uint16 => 3,
        .uint20 => 4,
        .word32 => 5,
        .register_index => 6,
        .address => 7,
        .pc => 8,
        .clock => 9,
        .selector => 10,
    };
}

fn constraintCategoryTag(category: program.ConstraintCategory) u8 {
    return switch (category) {
        .semantic => 0,
        .materialization => 1,
        .type_range => 2,
        .hint_binding => 3,
        .boundary => 4,
        .transition => 5,
        .relation_transition => 6,
    };
}

fn effectKindTag(kind: program.EffectKind) u8 {
    return switch (kind) {
        .program_fetch => 0,
        .register_read => 1,
        .register_write => 2,
        .memory_read => 3,
        .memory_write => 4,
        .range_request => 5,
        .state_consume => 6,
        .state_produce => 7,
        .component_call => 8,
        .public_consume => 9,
        .public_produce => 10,
    };
}
