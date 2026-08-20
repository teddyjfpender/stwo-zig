//! Domain-separated semantic identity for validated logical AIR programs.
//!
//! The digest is streamed directly from a fixed-width canonical projection. It
//! includes stable semantic names, declared order, types, operations, recipes,
//! bindings, effects, functions, and calls. Diagnostic source paths and spans,
//! interning-table state, allocation capacity, and addresses are excluded.

const std = @import("std");
const capabilities = @import("capabilities.zig");
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
pub const typed_lookup_request_format_version: u16 = 6;
pub const range_refinement_format_version: u16 = 7;
pub const conditional_access_format_version: u16 = 8;
pub const program_control_target_format_version: u16 = 9;
pub const committed_program_control_target_format_version: u16 = 10;
pub const function_body_format_version: u16 = 11;
pub const domain_separator = "stwo-zig/typed-air/semantic";
pub const Error = validate.Error;

pub const Identity = struct {
    format_version: u16,
    bytes: Digest,
};

/// Computes a semantic digest without allocating.
pub fn compute(arena: *const ir.Arena) Error!Digest {
    try validate.validate(arena);
    if (capabilities.hasRelationBindings(arena) or
        capabilities.hasFunctionBodyOwnership(arena))
        return error.InvalidEffect;
    return computeValidated(arena, .legacy_v1);
}

/// Semantic identity v2, which explicitly binds typed relation ABI metadata.
pub fn computeV2(arena: *const ir.Arena) validate.Error!Digest {
    try validate.validate(arena);
    if (capabilities.hasMachineDerivedNodes(arena) or
        capabilities.hasTypedLookupRequest(arena) or
        capabilities.hasRangeRefinement(arena) or
        capabilities.hasFunctionBodyOwnership(arena)) return error.InvalidEffect;
    return computeValidated(arena, .typed_effect_v2);
}

/// Semantic identity v3, which binds closed machine-derived operations and
/// instruction-local access groups in addition to typed relation metadata.
pub fn computeV3(arena: *const ir.Arena) validate.Error!Digest {
    try validate.validate(arena);
    if (capabilities.hasMemoryAccess(arena) or
        capabilities.hasSequentialRetirement(arena) or
        capabilities.hasTypedLookupRequest(arena) or
        capabilities.hasRangeRefinement(arena) or
        capabilities.hasFunctionBodyOwnership(arena)) return error.InvalidEffect;
    return computeValidated(arena, .register_group_v3);
}

/// Semantic identity v4 for fixed load/store access plans and aligned memory
/// addresses. Relation ordinal and physical phase remain independently bound.
pub fn computeV4(arena: *const ir.Arena) validate.Error!Digest {
    try validate.validate(arena);
    if (!capabilities.hasMemoryAccess(arena) or
        capabilities.hasSequentialRetirement(arena) or
        capabilities.hasTypedLookupRequest(arena) or
        capabilities.hasRangeRefinement(arena) or
        capabilities.hasFunctionBodyOwnership(arena)) return error.InvalidEffect;
    return computeValidated(arena, .memory_access_v4);
}

/// Semantic identity v5 for fixed sequential instruction retirement and every
/// earlier typed capability, including load/store access plans.
pub fn computeV5(arena: *const ir.Arena) validate.Error!Digest {
    try validate.validate(arena);
    if (!capabilities.hasSequentialRetirement(arena) or
        capabilities.hasTypedLookupRequest(arena) or
        capabilities.hasRangeRefinement(arena) or
        capabilities.hasFunctionBodyOwnership(arena)) return error.InvalidEffect;
    return computeValidated(arena, .sequential_retirement_v5);
}

/// Semantic identity v6 for explicit fixed-table operation requests and
/// statically bounded arithmetic. Earlier projections reject these additions,
/// so old v1-v5 digests retain exactly their prior byte domain.
pub fn computeV6(arena: *const ir.Arena) validate.Error!Digest {
    try validate.validate(arena);
    if (!capabilities.hasTypedLookupRequest(arena) or
        capabilities.hasRangeRefinement(arena) or
        capabilities.hasFunctionBodyOwnership(arena)) return error.InvalidEffect;
    return computeValidated(arena, .typed_lookup_request_v6);
}

/// Semantic identity v7 binds proof-carrying range refinements and their exact
/// constraint/effect premises in addition to the complete v6 program.
pub fn computeV7(arena: *const ir.Arena) validate.Error!Digest {
    try validate.validate(arena);
    if (!capabilities.hasRangeRefinement(arena) or
        capabilities.hasConditionalAccess(arena) or
        capabilities.hasProgramControlTarget(arena) or
        capabilities.hasCommittedProgramControlTarget(arena) or
        capabilities.hasFunctionBodyOwnership(arena))
    {
        return error.InvalidEffect;
    }
    return computeValidated(arena, .range_refinement_v7);
}

/// Semantic identity v8 binds the closed conditional load/store access proof,
/// including every zero-column alias and its exact direct/range premises.
pub fn computeV8(arena: *const ir.Arena) validate.Error!Digest {
    try validate.validate(arena);
    if (!capabilities.hasConditionalAccess(arena) or
        capabilities.hasProgramControlTarget(arena) or
        capabilities.hasCommittedProgramControlTarget(arena) or
        capabilities.hasFunctionBodyOwnership(arena))
    {
        return error.InvalidEffect;
    }
    return computeValidated(arena, .conditional_access_v8);
}

/// Semantic identity v9 binds program-authenticated jump and branch targets.
/// This is a new byte domain: v7/v8 remain frozen and explicitly reject the
/// added premise tag rather than changing an already published projection.
pub fn computeV9(arena: *const ir.Arena) validate.Error!Digest {
    try validate.validate(arena);
    if (!capabilities.hasProgramControlTarget(arena) or
        capabilities.hasCommittedProgramControlTarget(arena) or
        capabilities.hasFunctionBodyOwnership(arena))
    {
        return error.InvalidEffect;
    }
    return computeValidated(arena, .program_control_target_v9);
}

/// Semantic identity v10 binds a physical committed control target to its
/// exact program tuple, scalar compatibility views, decision-bit premise, and
/// gated target-equality premise. V1-v9 byte domains remain frozen.
pub fn computeV10(arena: *const ir.Arena) validate.Error!Digest {
    try validate.validate(arena);
    if (!capabilities.hasCommittedProgramControlTarget(arena) or
        capabilities.hasFunctionBodyOwnership(arena))
        return error.InvalidEffect;
    return computeValidated(arena, .committed_program_control_target_v10);
}

/// Semantic identity v11 binds explicit per-function ownership for every
/// proof-bearing record and the redundant sealed body ranges. It is an
/// additive projection over v10's full capability surface; v1-v10 reject this
/// feature so their published byte domains remain frozen.
pub fn computeV11(arena: *const ir.Arena) validate.Error!Digest {
    try validate.validate(arena);
    if (!capabilities.hasFunctionBodyOwnership(arena))
        return error.InvalidEffect;
    return computeValidated(arena, .function_body_v11);
}

pub fn computeIdentity(arena: *const ir.Arena) validate.Error!Identity {
    try validate.validate(arena);
    if (capabilities.hasFunctionBodyOwnership(arena)) {
        return .{
            .format_version = function_body_format_version,
            .bytes = computeValidated(arena, .function_body_v11),
        };
    }
    if (capabilities.hasCommittedProgramControlTarget(arena)) {
        return .{
            .format_version = committed_program_control_target_format_version,
            .bytes = computeValidated(arena, .committed_program_control_target_v10),
        };
    }
    if (capabilities.hasProgramControlTarget(arena)) {
        return .{
            .format_version = program_control_target_format_version,
            .bytes = computeValidated(arena, .program_control_target_v9),
        };
    }
    if (capabilities.hasConditionalAccess(arena)) {
        return .{
            .format_version = conditional_access_format_version,
            .bytes = computeValidated(arena, .conditional_access_v8),
        };
    }
    if (capabilities.hasRangeRefinement(arena)) {
        return .{
            .format_version = range_refinement_format_version,
            .bytes = computeValidated(arena, .range_refinement_v7),
        };
    }
    if (capabilities.hasTypedLookupRequest(arena)) {
        return .{
            .format_version = typed_lookup_request_format_version,
            .bytes = computeValidated(arena, .typed_lookup_request_v6),
        };
    }
    if (capabilities.hasSequentialRetirement(arena)) {
        return .{
            .format_version = sequential_retirement_format_version,
            .bytes = computeValidated(arena, .sequential_retirement_v5),
        };
    }
    if (capabilities.hasMemoryAccess(arena)) {
        return .{
            .format_version = memory_access_format_version,
            .bytes = computeValidated(arena, .memory_access_v4),
        };
    }
    if (capabilities.hasMachineDerivedNodes(arena)) {
        return .{
            .format_version = register_group_format_version,
            .bytes = computeValidated(arena, .register_group_v3),
        };
    }
    if (capabilities.hasRelationBindings(arena)) {
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
    typed_lookup_request_v6,
    range_refinement_v7,
    conditional_access_v8,
    program_control_target_v9,
    committed_program_control_target_v10,
    function_body_v11,
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
        .typed_lookup_request_v6 => typed_lookup_request_format_version,
        .range_refinement_v7 => range_refinement_format_version,
        .conditional_access_v8 => conditional_access_format_version,
        .program_control_target_v9 => program_control_target_format_version,
        .committed_program_control_target_v10 => committed_program_control_target_format_version,
        .function_body_v11 => function_body_format_version,
    });
    hashCount(&hash, arena.nodesView().len);
    hashCount(&hash, arena.constraintsView().len);
    hashCount(&hash, hints.view(arena).len);
    hashCount(&hash, arena.effectsView().len);
    if (projectionHasRangeRefinement(projection))
        hashCount(&hash, arena.range_refinements.items.len);
    if (projectionHasRangeRefinement(projection))
        hashCount(&hash, arena.fixed_table_requests.items.len);
    if (projectionHasConditionalAccess(projection))
        hashCount(&hash, arena.conditional_access_plans.items.len);
    if (projectionHasCommittedProgramControlTarget(projection))
        hashCount(&hash, arena.committed_program_control_targets.items.len);
    hashCount(&hash, functions.view(arena).len);
    hashCount(&hash, functions.calls(arena).len);

    for (arena.nodesView()) |node| hashNode(&hash, arena, node);
    for (arena.constraintsView()) |constraint| {
        if (projectionHasFunctionBody(projection))
            hashOptionalFunctionId(&hash, constraint.owner);
        hashName(&hash, arena, constraint.name);
        hashValueId(&hash, constraint.root);
        hashOptionalValueId(&hash, constraint.gate);
        hashInt(&hash, u8, constraintCategoryTag(constraint.category));
    }
    for (hints.view(arena), 0..) |hint, index| {
        const hint_id = types.idFromIndex(types.HintId, index) catch unreachable;
        const recipe = hint_recipe.getById(hint.recipe).?;
        if (projectionHasFunctionBody(projection))
            hashOptionalFunctionId(&hash, hint.owner);
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
        if (projectionHasFunctionBody(projection))
            hashOptionalFunctionId(&hash, effect.owner);
        hashInt(&hash, u8, effectKindTag(effect.kind));
        if (projection != .legacy_v1)
            hashRelationBinding(&hash, effect.binding);
        hashValues(&hash, arena.effectValues(effect_id).?);
        hashOptionalValueId(&hash, effect.liveness);
        hashOptionalInt(&hash, u8, effect.access_ordinal);
    }
    if (projectionHasRangeRefinement(projection)) {
        for (arena.fixed_table_requests.items) |proof| {
            hashInt(&hash, u32, @intFromEnum(proof.effect));
            hashValueId(&hash, proof.liveness);
        }
        for (arena.range_refinements.items) |item| {
            hashValueId(&hash, item.source);
            hashValueId(&hash, item.target);
            switch (item.premise) {
                .constraint_boolean => |proof| {
                    hashInt(&hash, u8, 0);
                    hashInt(&hash, u32, @intFromEnum(proof.constraint));
                },
                .fixed_table_field => |proof| {
                    hashInt(&hash, u8, 1);
                    hashInt(&hash, u32, @intFromEnum(proof.effect));
                    hashInt(&hash, u8, proof.field_index);
                    hashValueId(&hash, proof.liveness);
                },
                .aligned_control_target => |proof| {
                    hashInt(&hash, u8, 2);
                    hashValueId(&hash, proof.low);
                    hashValueId(&hash, proof.high);
                    hashInt(&hash, u32, @intFromEnum(proof.low_effect));
                    hashInt(&hash, u32, @intFromEnum(proof.high_effect));
                    hashValueId(&hash, proof.liveness);
                },
                .program_control_target => |proof| {
                    hashInt(&hash, u8, 3);
                    hashInt(&hash, u32, @intFromEnum(proof.program_effect));
                    hashValueId(&hash, proof.current_pc);
                    hashValueId(&hash, proof.offset);
                    switch (proof.kind) {
                        .jump => hashInt(&hash, u8, 0),
                        .branch => |branch| {
                            hashInt(&hash, u8, 1);
                            hashValueId(&hash, branch.condition);
                            hashInt(&hash, u32, @intFromEnum(branch.condition_constraint));
                        },
                    }
                    hashValueId(&hash, proof.liveness);
                },
            }
        }
    }
    if (projectionHasConditionalAccess(projection)) {
        for (arena.conditional_access_plans.items) |proof|
            hashConditionalAccessPlan(&hash, proof);
    }
    if (projectionHasCommittedProgramControlTarget(projection)) {
        for (arena.committed_program_control_targets.items) |proof|
            hashCommittedProgramControlTarget(&hash, proof);
    }
    for (functions.view(arena), 0..) |function, index| {
        const function_id = types.idFromIndex(types.FunctionId, index) catch unreachable;
        hashName(&hash, arena, function.name);
        hashValues(&hash, functions.inputs(arena, function_id).?);
        hashValues(&hash, functions.outputs(arena, function_id).?);
        if (projectionHasFunctionBody(projection))
            hashFunctionBody(&hash, function.body);
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

fn projectionHasRangeRefinement(projection: Projection) bool {
    return switch (projection) {
        .range_refinement_v7,
        .conditional_access_v8,
        .program_control_target_v9,
        .committed_program_control_target_v10,
        .function_body_v11,
        => true,
        else => false,
    };
}

fn projectionHasConditionalAccess(projection: Projection) bool {
    return switch (projection) {
        .conditional_access_v8,
        .program_control_target_v9,
        .committed_program_control_target_v10,
        .function_body_v11,
        => true,
        else => false,
    };
}

fn projectionHasCommittedProgramControlTarget(projection: Projection) bool {
    return projection == .committed_program_control_target_v10 or
        projection == .function_body_v11;
}

fn projectionHasFunctionBody(projection: Projection) bool {
    return projection == .function_body_v11;
}

fn hashFunctionBody(hash: *Sha256, body: ?program.FunctionBody) void {
    if (body) |present| {
        hashInt(hash, u8, 1);
        inline for (.{
            present.constraints,
            present.effects,
            present.hints,
            present.calls,
        }) |range| {
            hashInt(hash, u32, range.start);
            hashInt(hash, u32, range.len);
        }
    } else {
        hashInt(hash, u8, 0);
    }
}

fn hashCommittedProgramControlTarget(
    hash: *Sha256,
    proof: program.CommittedProgramControlTargetProof,
) void {
    hashInt(hash, u32, @intFromEnum(proof.program_effect));
    inline for (.{
        proof.current_pc,
        proof.current_pc_polynomial,
        proof.offset,
        proof.condition,
    }) |value| hashValueId(hash, value);
    hashInt(hash, u32, @intFromEnum(proof.condition_constraint));
    hashValueId(hash, proof.committed_target);
    hashValueId(hash, proof.committed_target_polynomial);
    hashInt(hash, u32, @intFromEnum(proof.target_constraint));
    hashValueId(hash, proof.liveness);
}

fn hashConditionalAccessPlan(
    hash: *Sha256,
    proof: program.ConditionalAccessPlanProof,
) void {
    hashInt(hash, u32, @intFromEnum(proof.first_effect));
    hashInt(hash, u32, @intFromEnum(proof.aligned_range));
    hashInt(hash, u32, @intFromEnum(proof.base_range));
    inline for (.{
        proof.active_source,
        proof.active,
        proof.store_source,
        proof.store_selector,
        proof.is_load,
        proof.instruction_clock,
        proof.second_clock,
        proof.memory_address,
        proof.shift_amount,
        proof.register_index,
        proof.word_source,
        proof.word_index,
        proof.base_low,
        proof.base_high,
    }) |value| hashValueId(hash, value);
    hashInt(hash, u32, @intFromEnum(proof.source_address_constraint));
    hashInt(hash, u32, @intFromEnum(proof.destination_address_constraint));
    inline for (.{
        proof.source_address,
        proof.source_clock,
        proof.source_gap,
        proof.destination_address,
        proof.destination_clock,
        proof.destination_gap,
    }) |alias| {
        hashValueId(hash, alias.source);
        hashValueId(hash, alias.target);
    }
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
        .bitwise_request => 11,
    };
}

fn callStrategyTag(strategy: program.CallStrategy) u8 {
    return switch (strategy) {
        .inline_expansion => 0,
        .relation_backed => 1,
    };
}
