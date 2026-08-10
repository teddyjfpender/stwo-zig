//! Domain-separated semantic identity for validated logical AIR programs.
//!
//! The digest is streamed directly from a fixed-width canonical projection. It
//! includes stable semantic names, declared order, types, operations, recipes,
//! bindings, effects, functions, and calls. Diagnostic source paths and spans,
//! interning-table state, allocation capacity, and addresses are excluded.

const std = @import("std");
const expr = @import("expr.zig");
const functions = @import("functions.zig");
const hint_recipe = @import("hint_recipe.zig");
const hints = @import("hints.zig");
const ir = @import("ir.zig");
const program = @import("program.zig");
const types = @import("types.zig");
const validate = @import("validate.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;

pub const Digest = [32]u8;
pub const format_version: u16 = 1;
pub const typed_effect_format_version: u16 = 2;
pub const register_group_format_version: u16 = 3;
pub const memory_access_format_version: u16 = 4;
pub const sequential_retirement_format_version: u16 = 5;
pub const domain_separator = "stwo-zig/typed-air/semantic";
pub const Error = validate.Error;

pub const Identity = struct {
    format_version: u16,
    bytes: Digest,
};

/// Computes a semantic digest without allocating.
pub fn compute(arena: *const ir.Arena) Error!Digest {
    try validate.validate(arena);
    if (hasRelationBindings(arena))
        return error.InvalidEffect;
    return computeValidated(arena, .legacy_v1);
}

/// Semantic identity v2, which explicitly binds typed relation ABI metadata.
pub fn computeV2(arena: *const ir.Arena) validate.Error!Digest {
    try validate.validate(arena);
    if (hasMachineDerivedNodes(arena)) return error.InvalidEffect;
    return computeValidated(arena, .typed_effect_v2);
}

/// Semantic identity v3, which binds closed machine-derived operations and
/// instruction-local access groups in addition to typed relation metadata.
pub fn computeV3(arena: *const ir.Arena) validate.Error!Digest {
    try validate.validate(arena);
    if (hasMemoryAccessCapability(arena) or
        hasSequentialRetirementCapability(arena)) return error.InvalidEffect;
    return computeValidated(arena, .register_group_v3);
}

/// Semantic identity v4 for fixed load/store access plans and aligned memory
/// addresses. Relation ordinal and physical phase remain independently bound.
pub fn computeV4(arena: *const ir.Arena) validate.Error!Digest {
    try validate.validate(arena);
    if (!hasMemoryAccessCapability(arena) or
        hasSequentialRetirementCapability(arena)) return error.InvalidEffect;
    return computeValidated(arena, .memory_access_v4);
}

/// Semantic identity v5 for fixed sequential instruction retirement and every
/// earlier typed capability, including load/store access plans.
pub fn computeV5(arena: *const ir.Arena) validate.Error!Digest {
    try validate.validate(arena);
    if (!hasSequentialRetirementCapability(arena)) return error.InvalidEffect;
    return computeValidated(arena, .sequential_retirement_v5);
}

pub fn computeIdentity(arena: *const ir.Arena) validate.Error!Identity {
    try validate.validate(arena);
    if (hasSequentialRetirementCapability(arena)) {
        return .{
            .format_version = sequential_retirement_format_version,
            .bytes = computeValidated(arena, .sequential_retirement_v5),
        };
    }
    if (hasMemoryAccessCapability(arena)) {
        return .{
            .format_version = memory_access_format_version,
            .bytes = computeValidated(arena, .memory_access_v4),
        };
    }
    if (hasMachineDerivedNodes(arena)) {
        return .{
            .format_version = register_group_format_version,
            .bytes = computeValidated(arena, .register_group_v3),
        };
    }
    if (hasRelationBindings(arena)) {
        return .{
            .format_version = typed_effect_format_version,
            .bytes = computeValidated(arena, .typed_effect_v2),
        };
    }
    return .{
        .format_version = format_version,
        .bytes = computeValidated(arena, .legacy_v1),
    };
}

const Projection = enum {
    legacy_v1,
    typed_effect_v2,
    register_group_v3,
    memory_access_v4,
    sequential_retirement_v5,
};

fn computeValidated(arena: *const ir.Arena, projection: Projection) Digest {
    var hash = Sha256.init(.{});
    hash.update(domain_separator);
    hashInt(&hash, u16, switch (projection) {
        .legacy_v1 => format_version,
        .typed_effect_v2 => typed_effect_format_version,
        .register_group_v3 => register_group_format_version,
        .memory_access_v4 => memory_access_format_version,
        .sequential_retirement_v5 => sequential_retirement_format_version,
    });
    hashCount(&hash, arena.nodesView().len);
    hashCount(&hash, arena.constraintsView().len);
    hashCount(&hash, hints.view(arena).len);
    hashCount(&hash, arena.effectsView().len);
    hashCount(&hash, functions.view(arena).len);
    hashCount(&hash, functions.calls(arena).len);

    for (arena.nodesView()) |node| hashNode(&hash, arena, node);
    for (arena.constraintsView()) |constraint| {
        hashName(&hash, arena, constraint.name);
        hashValueId(&hash, constraint.root);
        hashOptionalValueId(&hash, constraint.gate);
        hashInt(&hash, u8, constraintCategoryTag(constraint.category));
    }
    for (hints.view(arena), 0..) |hint, index| {
        const hint_id = types.idFromIndex(types.HintId, index) catch unreachable;
        const recipe = hint_recipe.getById(hint.recipe).?;
        hashInt(&hash, u16, @intFromEnum(hint.recipe));
        hashInt(&hash, u16, recipe.version);
        hashInt(&hash, u16, @intFromEnum(recipe.algorithm));
        hashInt(&hash, u8, @intFromEnum(recipe.exceptional_cases));
        hashOptionalValueId(&hash, hint.activation);
        hashValues(&hash, hints.inputs(arena, hint_id).?);
        hashValues(&hash, hints.outputs(arena, hint_id).?);
        const bindings = hints.bindings(arena, hint_id).?;
        hashCount(&hash, bindings.len);
        for (bindings) |binding| {
            hashInt(&hash, u16, binding.output_index);
            hashHintBindingTarget(&hash, binding.target);
            hashValues(&hash, hints.bindingPath(arena, binding).?);
        }
    }
    for (arena.effectsView(), 0..) |effect, index| {
        const effect_id = types.idFromIndex(types.EffectId, index) catch unreachable;
        hashInt(&hash, u8, effectKindTag(effect.kind));
        if (projection != .legacy_v1)
            hashRelationBinding(&hash, effect.binding);
        hashValues(&hash, arena.effectValues(effect_id).?);
        hashOptionalValueId(&hash, effect.liveness);
        hashOptionalInt(&hash, u8, effect.access_ordinal);
    }
    for (functions.view(arena), 0..) |function, index| {
        const function_id = types.idFromIndex(types.FunctionId, index) catch unreachable;
        hashName(&hash, arena, function.name);
        hashValues(&hash, functions.inputs(arena, function_id).?);
        hashValues(&hash, functions.outputs(arena, function_id).?);
    }
    for (functions.calls(arena), 0..) |call, index| {
        const call_id = types.idFromIndex(types.CallId, index) catch unreachable;
        hashOptionalFunctionId(&hash, call.caller);
        hashInt(&hash, u32, @intFromEnum(call.callee));
        hashInt(&hash, u8, callStrategyTag(call.strategy));
        hashValues(&hash, functions.callArguments(arena, call_id).?);
        hashValues(&hash, functions.callOutputs(arena, call_id).?);
    }
    return hash.finalResult();
}

fn hasRelationBindings(arena: *const ir.Arena) bool {
    for (arena.effectsView()) |effect| {
        if (effect.binding != null) return true;
    }
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

fn hasSequentialRetirementCapability(arena: *const ir.Arena) bool {
    for (arena.nodesView()) |node| switch (node.key.op) {
        .machine_derived => |derived| switch (derived) {
            .instruction_next_pc, .instruction_next_clock => return true,
            else => {},
        },
        else => {},
    };
    return false;
}

fn hashRelationBinding(
    hash: *Sha256,
    binding: ?program.RelationBinding,
) void {
    if (binding) |present| {
        hashInt(hash, u8, 1);
        hashInt(hash, u16, @intFromEnum(present.schema));
        hashInt(hash, u16, present.schema_version);
        hashInt(hash, u8, @intFromEnum(present.role));
    } else {
        hashInt(hash, u8, 0);
    }
}

fn hashNode(hash: *Sha256, arena: *const ir.Arena, node: expr.Node) void {
    hashType(hash, node.key.ty);
    switch (node.key.op) {
        .constant => |constant| switch (constant) {
            .field => |value| {
                hashInt(hash, u8, 0);
                hashInt(hash, u32, value);
            },
            .unsigned => |value| {
                hashInt(hash, u8, 1);
                hashInt(hash, u32, value);
            },
        },
        .input => |name| {
            hashInt(hash, u8, 2);
            hashName(hash, arena, name);
        },
        .add => |binary| {
            hashInt(hash, u8, 3);
            hashBinary(hash, binary);
        },
        .sub => |binary| {
            hashInt(hash, u8, 4);
            hashBinary(hash, binary);
        },
        .mul => |binary| {
            hashInt(hash, u8, 5);
            hashBinary(hash, binary);
        },
        .neg => |value| {
            hashInt(hash, u8, 6);
            hashValueId(hash, value);
        },
        .select => |selection| {
            hashInt(hash, u8, 7);
            hashValueId(hash, selection.selector);
            hashValueId(hash, selection.when_true);
            hashValueId(hash, selection.when_false);
        },
        .hint_output => |output| {
            hashInt(hash, u8, 8);
            hashInt(hash, u32, @intFromEnum(output.hint));
            hashInt(hash, u16, output.index);
        },
        .call_output => |output| {
            hashInt(hash, u8, 9);
            hashInt(hash, u32, @intFromEnum(output.call));
            hashInt(hash, u16, output.index);
        },
        .machine_derived => |derived| {
            hashInt(hash, u8, 10);
            switch (derived) {
                .register_address => |address| {
                    hashInt(hash, u8, 0);
                    hashValueId(hash, address.index);
                },
                .aligned_word_address => |address| {
                    hashInt(hash, u8, 3);
                    hashValueId(hash, address.word_index);
                },
                .access_clock => |clock| {
                    hashInt(hash, u8, 1);
                    hashValueId(hash, clock.instruction_clock);
                    hashInt(hash, u8, @intFromEnum(clock.phase));
                },
                .strict_clock_gap => |gap| {
                    hashInt(hash, u8, 2);
                    hashValueId(hash, gap.current_clock);
                    hashValueId(hash, gap.previous_clock);
                    hashValueId(hash, gap.active);
                    hashInt(hash, u8, @intFromEnum(gap.phase));
                },
                .instruction_next_pc => |next| {
                    hashInt(hash, u8, 4);
                    hashValueId(hash, next.current);
                },
                .instruction_next_clock => |next| {
                    hashInt(hash, u8, 5);
                    hashValueId(hash, next.current);
                },
            }
        },
    }
}

fn hashType(hash: *Sha256, ty: types.Type) void {
    switch (ty) {
        .felt => hashInt(hash, u8, 0),
        .bit => hashInt(hash, u8, 1),
        .byte => hashInt(hash, u8, 2),
        .uint16 => hashInt(hash, u8, 3),
        .uint20 => hashInt(hash, u8, 4),
        .word32 => hashInt(hash, u8, 5),
        .register_index => hashInt(hash, u8, 6),
        .address => hashInt(hash, u8, 7),
        .pc => hashInt(hash, u8, 8),
        .clock => hashInt(hash, u8, 9),
        .selector => hashInt(hash, u8, 10),
        .bounded_uint => |bounded| {
            hashInt(hash, u8, 11);
            hashInt(hash, u8, bounded.bits);
            switch (bounded.representation) {
                .canonical_field => hashInt(hash, u8, 0),
                .little_endian_limbs => |layout| {
                    hashInt(hash, u8, 1);
                    hashInt(hash, u8, layout.limb_bits);
                    hashInt(hash, u8, layout.limb_count);
                },
            }
        },
        .array => |array| {
            hashInt(hash, u8, 12);
            hashInt(hash, u8, arrayElementTag(array.element));
            hashInt(hash, u16, array.len);
        },
    }
}

fn hashName(hash: *Sha256, arena: *const ir.Arena, id: types.NameId) void {
    hashString(hash, arena.name(id).?);
}

fn hashString(hash: *Sha256, value: []const u8) void {
    hashCount(hash, value.len);
    hash.update(value);
}

fn hashValues(hash: *Sha256, values: []const types.ValueId) void {
    hashCount(hash, values.len);
    for (values) |value| hashValueId(hash, value);
}

fn hashBinary(hash: *Sha256, binary: expr.Binary) void {
    hashValueId(hash, binary.lhs);
    hashValueId(hash, binary.rhs);
}

fn hashValueId(hash: *Sha256, id: types.ValueId) void {
    hashInt(hash, u32, @intFromEnum(id));
}

fn hashOptionalValueId(hash: *Sha256, id: ?types.ValueId) void {
    if (id) |value| {
        hashInt(hash, u8, 1);
        hashValueId(hash, value);
    } else {
        hashInt(hash, u8, 0);
    }
}

fn hashOptionalFunctionId(hash: *Sha256, id: ?types.FunctionId) void {
    if (id) |value| {
        hashInt(hash, u8, 1);
        hashInt(hash, u32, @intFromEnum(value));
    } else {
        hashInt(hash, u8, 0);
    }
}

fn hashOptionalInt(
    hash: *Sha256,
    comptime T: type,
    value: ?T,
) void {
    if (value) |present| {
        hashInt(hash, u8, 1);
        hashInt(hash, T, present);
    } else {
        hashInt(hash, u8, 0);
    }
}

fn hashHintBindingTarget(hash: *Sha256, target: program.HintBindingTarget) void {
    switch (target) {
        .constraint => |id| {
            hashInt(hash, u8, 0);
            hashInt(hash, u32, @intFromEnum(id));
        },
        .effect => |id| {
            hashInt(hash, u8, 1);
            hashInt(hash, u32, @intFromEnum(id));
        },
    }
}

fn hashCount(hash: *Sha256, value: usize) void {
    hashInt(hash, u64, @intCast(value));
}

fn hashInt(hash: *Sha256, comptime T: type, value: T) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, value, .little);
    hash.update(&encoded);
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
