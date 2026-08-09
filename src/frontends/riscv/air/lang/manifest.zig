//! Canonical binary serialization of a validated logical AIR program.
//!
//! The encoding is an identity surface, not an in-memory dump. It uses fixed
//! little-endian integers and explicit stable tags, writes semantically ordered
//! records in arena order, and resolves names and sources to bytes so allocator
//! addresses and interning-table insertion order cannot enter the artifact.

const std = @import("std");
const expr = @import("expr.zig");
const functions = @import("functions.zig");
const hint_recipe = @import("hint_recipe.zig");
const hints = @import("hints.zig");
const ir = @import("ir.zig");
const program = @import("program.zig");
const source = @import("source.zig");
const types = @import("types.zig");
const validate = @import("validate.zig");

pub const magic = "STWAIRL\x00";
pub const format_version: u16 = 3;
pub const logical_schema_version: u16 = 2;
pub const typed_effect_format_version: u16 = 4;
pub const typed_effect_logical_schema_version: u16 = 3;
pub const register_group_format_version: u16 = 5;
pub const register_group_logical_schema_version: u16 = 4;
pub const memory_access_format_version: u16 = 6;
pub const memory_access_logical_schema_version: u16 = 5;

pub const ManifestError = error{
    ManifestTooLarge,
    MachineDerivedRequiresManifestV5,
    MemoryAccessRequiresManifestV6,
    RelationBindingsRequireManifestV4,
};
pub const Error = std.mem.Allocator.Error || validate.Error || ManifestError;

pub fn serializeAlloc(
    allocator: std.mem.Allocator,
    arena: *const ir.Arena,
) Error![]u8 {
    try validate.validate(arena);
    try requireLegacyEffects(arena);
    var bytes: std.ArrayList(u8) = .empty;
    errdefer bytes.deinit(allocator);
    try writeValidated(bytes.writer(allocator), arena, .legacy_v3);
    return bytes.toOwnedSlice(allocator);
}

/// Canonical logical encoding with explicit typed relation bindings.
pub fn serializeAllocV4(
    allocator: std.mem.Allocator,
    arena: *const ir.Arena,
) Error![]u8 {
    try validate.validate(arena);
    try requireNoMachineDerivedNodes(arena);
    var bytes: std.ArrayList(u8) = .empty;
    errdefer bytes.deinit(allocator);
    try writeValidated(bytes.writer(allocator), arena, .typed_effect_v4);
    return bytes.toOwnedSlice(allocator);
}

/// Canonical logical encoding with closed machine-derived operations and
/// instruction-local access groups.
pub fn serializeAllocV5(
    allocator: std.mem.Allocator,
    arena: *const ir.Arena,
) Error![]u8 {
    try validate.validate(arena);
    try requireNoMemoryAccessCapability(arena);
    var bytes: std.ArrayList(u8) = .empty;
    errdefer bytes.deinit(allocator);
    try writeValidated(bytes.writer(allocator), arena, .register_group_v5);
    return bytes.toOwnedSlice(allocator);
}

/// Canonical logical encoding for fixed load/store access plans.
pub fn serializeAllocV6(
    allocator: std.mem.Allocator,
    arena: *const ir.Arena,
) Error![]u8 {
    try validate.validate(arena);
    var bytes: std.ArrayList(u8) = .empty;
    errdefer bytes.deinit(allocator);
    try writeValidated(bytes.writer(allocator), arena, .memory_access_v6);
    return bytes.toOwnedSlice(allocator);
}

/// Selects the least capable canonical format accepted by `arena`.
pub fn serializeAllocCurrent(
    allocator: std.mem.Allocator,
    arena: *const ir.Arena,
) Error![]u8 {
    try validate.validate(arena);
    const encoding = leastCapableEncoding(arena);
    var bytes: std.ArrayList(u8) = .empty;
    errdefer bytes.deinit(allocator);
    try writeValidated(bytes.writer(allocator), arena, encoding);
    return bytes.toOwnedSlice(allocator);
}

/// Writes one validated canonical encoding to `writer`.
pub fn writeCanonical(writer: anytype, arena: *const ir.Arena) !void {
    try validate.validate(arena);
    try requireLegacyEffects(arena);
    try writeValidated(writer, arena, .legacy_v3);
}

pub fn writeCanonicalV4(writer: anytype, arena: *const ir.Arena) !void {
    try validate.validate(arena);
    try requireNoMachineDerivedNodes(arena);
    try writeValidated(writer, arena, .typed_effect_v4);
}

pub fn writeCanonicalV5(writer: anytype, arena: *const ir.Arena) !void {
    try validate.validate(arena);
    try requireNoMemoryAccessCapability(arena);
    try writeValidated(writer, arena, .register_group_v5);
}

pub fn writeCanonicalV6(writer: anytype, arena: *const ir.Arena) !void {
    try validate.validate(arena);
    try writeValidated(writer, arena, .memory_access_v6);
}

pub fn writeCanonicalCurrent(writer: anytype, arena: *const ir.Arena) !void {
    try validate.validate(arena);
    try writeValidated(writer, arena, leastCapableEncoding(arena));
}

const Encoding = enum {
    legacy_v3,
    typed_effect_v4,
    register_group_v5,
    memory_access_v6,
};

fn writeValidated(
    writer: anytype,
    arena: *const ir.Arena,
    encoding: Encoding,
) !void {
    try writer.writeAll(magic);
    try writeInt(writer, u16, switch (encoding) {
        .legacy_v3 => format_version,
        .typed_effect_v4 => typed_effect_format_version,
        .register_group_v5 => register_group_format_version,
        .memory_access_v6 => memory_access_format_version,
    });
    try writeInt(writer, u16, switch (encoding) {
        .legacy_v3 => logical_schema_version,
        .typed_effect_v4 => typed_effect_logical_schema_version,
        .register_group_v5 => register_group_logical_schema_version,
        .memory_access_v6 => memory_access_logical_schema_version,
    });
    try writeCount(writer, arena.nodesView().len);
    try writeCount(writer, arena.constraintsView().len);
    try writeCount(writer, hints.view(arena).len);
    try writeCount(writer, arena.effectsView().len);
    try writeCount(writer, functions.view(arena).len);
    try writeCount(writer, functions.calls(arena).len);

    for (arena.nodesView()) |node| try writeNode(writer, arena, node);
    for (arena.constraintsView()) |constraint| {
        try writeName(writer, arena, constraint.name);
        try writeValueId(writer, constraint.root);
        try writeOptionalValueId(writer, constraint.gate);
        try writeInt(writer, u8, constraintCategoryTag(constraint.category));
        try writeSpan(writer, arena, constraint.source_span);
    }
    for (hints.view(arena), 0..) |hint, index| {
        const id = types.idFromIndex(types.HintId, index) catch
            return error.ManifestTooLarge;
        const recipe = hint_recipe.getById(hint.recipe) orelse unreachable;
        try writeInt(writer, u16, @intFromEnum(hint.recipe));
        try writeInt(writer, u16, recipe.version);
        try writeOptionalValueId(writer, hint.activation);
        try writeValues(writer, hints.inputs(arena, id).?);
        try writeValues(writer, hints.outputs(arena, id).?);
        const bindings = hints.bindings(arena, id).?;
        try writeCount(writer, bindings.len);
        for (bindings) |binding| {
            try writeInt(writer, u16, binding.output_index);
            try writeHintBindingTarget(writer, binding.target);
            try writeValues(writer, hints.bindingPath(arena, binding).?);
        }
        try writeSpan(writer, arena, hint.source_span);
    }
    for (arena.effectsView(), 0..) |effect, index| {
        const id = types.idFromIndex(types.EffectId, index) catch
            return error.ManifestTooLarge;
        try writeInt(writer, u8, effectKindTag(effect.kind));
        if (encoding != .legacy_v3)
            try writeRelationBinding(writer, effect.binding);
        try writeValues(writer, arena.effectValues(id).?);
        try writeOptionalValueId(writer, effect.liveness);
        try writeOptionalInt(writer, u8, effect.access_ordinal);
        try writeSpan(writer, arena, effect.source_span);
    }
    for (functions.view(arena), 0..) |function, index| {
        const id = types.idFromIndex(types.FunctionId, index) catch
            return error.ManifestTooLarge;
        try writeName(writer, arena, function.name);
        try writeValues(writer, functions.inputs(arena, id).?);
        try writeValues(writer, functions.outputs(arena, id).?);
        try writeSpan(writer, arena, function.source_span);
    }
    for (functions.calls(arena), 0..) |call, index| {
        const id = types.idFromIndex(types.CallId, index) catch
            return error.ManifestTooLarge;
        try writeOptionalFunctionId(writer, call.caller);
        try writeInt(writer, u32, @intFromEnum(call.callee));
        try writeInt(writer, u8, callStrategyTag(call.strategy));
        try writeValues(writer, functions.callArguments(arena, id).?);
        try writeValues(writer, functions.callOutputs(arena, id).?);
        try writeSpan(writer, arena, call.source_span);
    }
}

fn requireLegacyEffects(arena: *const ir.Arena) ManifestError!void {
    for (arena.effectsView()) |effect| {
        if (effect.binding != null)
            return error.RelationBindingsRequireManifestV4;
    }
}

fn requireNoMachineDerivedNodes(arena: *const ir.Arena) ManifestError!void {
    for (arena.nodesView()) |node| switch (node.key.op) {
        .machine_derived => return error.MachineDerivedRequiresManifestV5,
        else => {},
    };
}

fn requireNoMemoryAccessCapability(arena: *const ir.Arena) ManifestError!void {
    if (hasMemoryAccessCapability(arena))
        return error.MemoryAccessRequiresManifestV6;
}

fn leastCapableEncoding(arena: *const ir.Arena) Encoding {
    if (hasMemoryAccessCapability(arena)) return .memory_access_v6;
    if (hasMachineDerivedNodes(arena)) return .register_group_v5;
    if (hasRelationBindings(arena)) return .typed_effect_v4;
    return .legacy_v3;
}

fn hasRelationBindings(arena: *const ir.Arena) bool {
    for (arena.effectsView()) |effect| if (effect.binding != null) return true;
    return false;
}

fn hasMachineDerivedNodes(arena: *const ir.Arena) bool {
    for (arena.nodesView()) |node| switch (node.key.op) {
        .machine_derived => return true,
        else => {},
    };
    return false;
}

fn hasMemoryAccessCapability(arena: *const ir.Arena) bool {
    for (arena.effectsView()) |effect| switch (effect.kind) {
        .memory_read, .memory_write => return true,
        else => {},
    };
    for (arena.nodesView()) |node| switch (node.key.op) {
        .machine_derived => |derived| switch (derived) {
            .aligned_word_address => return true,
            else => {},
        },
        else => {},
    };
    return false;
}

fn writeRelationBinding(
    writer: anytype,
    binding: ?program.RelationBinding,
) !void {
    if (binding) |present| {
        try writeInt(writer, u8, 1);
        try writeInt(writer, u16, @intFromEnum(present.schema));
        try writeInt(writer, u16, present.schema_version);
        try writeInt(writer, u8, @intFromEnum(present.role));
    } else {
        try writeInt(writer, u8, 0);
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
        .call_output => |output| {
            try writeInt(writer, u8, 9);
            try writeInt(writer, u32, @intFromEnum(output.call));
            try writeInt(writer, u16, output.index);
        },
        .machine_derived => |derived| {
            try writeInt(writer, u8, 10);
            switch (derived) {
                .register_address => |address| {
                    try writeInt(writer, u8, 0);
                    try writeValueId(writer, address.index);
                },
                .aligned_word_address => |address| {
                    try writeInt(writer, u8, 3);
                    try writeValueId(writer, address.word_index);
                },
                .access_clock => |clock| {
                    try writeInt(writer, u8, 1);
                    try writeValueId(writer, clock.instruction_clock);
                    try writeInt(writer, u8, @intFromEnum(clock.phase));
                },
                .strict_clock_gap => |gap| {
                    try writeInt(writer, u8, 2);
                    try writeValueId(writer, gap.current_clock);
                    try writeValueId(writer, gap.previous_clock);
                    try writeValueId(writer, gap.active);
                    try writeInt(writer, u8, @intFromEnum(gap.phase));
                },
            }
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

fn writeOptionalFunctionId(writer: anytype, id: ?types.FunctionId) !void {
    if (id) |value| {
        try writeInt(writer, u8, 1);
        try writeInt(writer, u32, @intFromEnum(value));
    } else {
        try writeInt(writer, u8, 0);
    }
}

fn writeHintBindingTarget(
    writer: anytype,
    target: program.HintBindingTarget,
) !void {
    switch (target) {
        .constraint => |id| {
            try writeInt(writer, u8, 0);
            try writeInt(writer, u32, @intFromEnum(id));
        },
        .effect => |id| {
            try writeInt(writer, u8, 1);
            try writeInt(writer, u32, @intFromEnum(id));
        },
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

fn callStrategyTag(strategy: program.CallStrategy) u8 {
    return switch (strategy) {
        .inline_expansion => 0,
        .relation_backed => 1,
    };
}
