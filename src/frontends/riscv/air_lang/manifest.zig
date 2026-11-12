//! Canonical binary serialization of a validated logical AIR program.
//!
//! The encoding is an identity surface, not an in-memory dump. It uses fixed
//! little-endian integers and explicit stable tags, writes semantically ordered
//! records in arena order, and resolves names and sources to bytes so allocator
//! addresses and interning-table insertion order cannot enter the artifact.

const std = @import("std");
const capabilities = @import("capabilities.zig");
const expr = @import("expr.zig");
const functions = @import("functions.zig");
const hint_recipe = @import("hint_recipe.zig");
const hints = @import("hints.zig");
const ir = @import("ir.zig");
const program = @import("program.zig");
const source = @import("source.zig");
const types = @import("types.zig");
const manifest_encoding = @import("manifest_encoding.zig");
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
pub const sequential_retirement_format_version: u16 = 7;
pub const sequential_retirement_logical_schema_version: u16 = 6;
pub const typed_lookup_request_format_version: u16 = 8;
pub const typed_lookup_request_logical_schema_version: u16 = 7;
pub const range_refinement_format_version: u16 = 9;
pub const range_refinement_logical_schema_version: u16 = 8;
pub const conditional_access_format_version: u16 = 10;
pub const conditional_access_logical_schema_version: u16 = 9;
pub const program_control_target_format_version: u16 = 11;
pub const program_control_target_logical_schema_version: u16 = 10;
pub const committed_program_control_target_format_version: u16 = 12;
pub const committed_program_control_target_logical_schema_version: u16 = 11;
pub const function_body_format_version: u16 = 13;
pub const function_body_logical_schema_version: u16 = 12;

pub const ManifestError = error{
    ManifestTooLarge,
    MachineDerivedRequiresManifestV5,
    MemoryAccessRequiresManifestV6,
    RelationBindingsRequireManifestV4,
    SequentialRetirementRequiresManifestV7,
    TypedLookupRequestRequiresManifestV8,
    RangeRefinementRequiresManifestV9,
    ConditionalAccessRequiresManifestV10,
    ProgramControlTargetRequiresManifestV11,
    CommittedProgramControlTargetRequiresManifestV12,
    FunctionBodyOwnershipRequiresManifestV13,
};
pub const Error = std.mem.Allocator.Error || validate.Error || ManifestError;

pub fn serializeAlloc(
    allocator: std.mem.Allocator,
    arena: *const ir.Arena,
) Error![]u8 {
    try validate.validate(arena);
    try requireNoFunctionBodyOwnership(arena);
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
    try requireNoFunctionBodyOwnership(arena);
    try requireNoTypedLookupRequestCapability(arena);
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
    try requireNoFunctionBodyOwnership(arena);
    try requireNoTypedLookupRequestCapability(arena);
    try requireNoSequentialRetirementCapability(arena);
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
    try requireNoFunctionBodyOwnership(arena);
    try requireNoTypedLookupRequestCapability(arena);
    try requireNoSequentialRetirementCapability(arena);
    var bytes: std.ArrayList(u8) = .empty;
    errdefer bytes.deinit(allocator);
    try writeValidated(bytes.writer(allocator), arena, .memory_access_v6);
    return bytes.toOwnedSlice(allocator);
}

/// Canonical logical encoding for fixed sequential retirement derivations and
/// every earlier typed capability, including load/store access plans.
pub fn serializeAllocV7(
    allocator: std.mem.Allocator,
    arena: *const ir.Arena,
) Error![]u8 {
    try validate.validate(arena);
    try requireNoFunctionBodyOwnership(arena);
    try requireNoTypedLookupRequestCapability(arena);
    var bytes: std.ArrayList(u8) = .empty;
    errdefer bytes.deinit(allocator);
    try writeValidated(bytes.writer(allocator), arena, .sequential_retirement_v7);
    return bytes.toOwnedSlice(allocator);
}

/// Canonical logical encoding for explicit fixed-table operation requests and
/// bounded arithmetic, plus every capability represented by v3-v7.
pub fn serializeAllocV8(
    allocator: std.mem.Allocator,
    arena: *const ir.Arena,
) Error![]u8 {
    try validate.validate(arena);
    try requireNoFunctionBodyOwnership(arena);
    try requireNoRangeRefinementCapability(arena);
    var bytes: std.ArrayList(u8) = .empty;
    errdefer bytes.deinit(allocator);
    try writeValidated(bytes.writer(allocator), arena, .typed_lookup_request_v8);
    return bytes.toOwnedSlice(allocator);
}

/// Canonical logical encoding for proof-carrying range refinements and every
/// earlier typed capability.
pub fn serializeAllocV9(
    allocator: std.mem.Allocator,
    arena: *const ir.Arena,
) Error![]u8 {
    try validate.validate(arena);
    try requireNoFunctionBodyOwnership(arena);
    try requireNoConditionalAccessCapability(arena);
    try requireNoProgramControlTargetCapability(arena);
    try requireNoCommittedProgramControlTargetCapability(arena);
    var bytes: std.ArrayList(u8) = .empty;
    errdefer bytes.deinit(allocator);
    try writeValidated(bytes.writer(allocator), arena, .range_refinement_v9);
    return bytes.toOwnedSlice(allocator);
}

/// Canonical logical encoding for the closed conditional load/store schedule,
/// including its proof-only semantic aliases and every prior capability.
pub fn serializeAllocV10(
    allocator: std.mem.Allocator,
    arena: *const ir.Arena,
) Error![]u8 {
    try validate.validate(arena);
    try requireNoFunctionBodyOwnership(arena);
    try requireNoProgramControlTargetCapability(arena);
    try requireNoCommittedProgramControlTargetCapability(arena);
    var bytes: std.ArrayList(u8) = .empty;
    errdefer bytes.deinit(allocator);
    try writeValidated(bytes.writer(allocator), arena, .conditional_access_v10);
    return bytes.toOwnedSlice(allocator);
}

/// Canonical logical encoding for program-authenticated control targets. This
/// new version preserves the byte meaning of v9/v10 and also carries a
/// conditional-access proof when both capabilities appear in one program.
pub fn serializeAllocV11(
    allocator: std.mem.Allocator,
    arena: *const ir.Arena,
) Error![]u8 {
    try validate.validate(arena);
    try requireNoFunctionBodyOwnership(arena);
    try requireNoCommittedProgramControlTargetCapability(arena);
    var bytes: std.ArrayList(u8) = .empty;
    errdefer bytes.deinit(allocator);
    try writeValidated(bytes.writer(allocator), arena, .program_control_target_v11);
    return bytes.toOwnedSlice(allocator);
}

/// Canonical logical encoding for proof-authorized physical control targets.
/// This preserves every v3-v11 byte domain and includes all prior proof
/// sections when capabilities coexist.
pub fn serializeAllocV12(
    allocator: std.mem.Allocator,
    arena: *const ir.Arena,
) Error![]u8 {
    try validate.validate(arena);
    try requireNoFunctionBodyOwnership(arena);
    var bytes: std.ArrayList(u8) = .empty;
    errdefer bytes.deinit(allocator);
    try writeValidated(
        bytes.writer(allocator),
        arena,
        .committed_program_control_target_v12,
    );
    return bytes.toOwnedSlice(allocator);
}

/// Canonical logical encoding for sealed per-function proof-record ownership.
/// This is the complete additive projection over every earlier capability;
/// V3-V12 reject body ownership and therefore remain byte-for-byte frozen.
pub fn serializeAllocV13(
    allocator: std.mem.Allocator,
    arena: *const ir.Arena,
) Error![]u8 {
    try validate.validate(arena);
    if (!capabilities.hasFunctionBodyOwnership(arena))
        return error.FunctionBodyOwnershipRequiresManifestV13;
    var bytes: std.ArrayList(u8) = .empty;
    errdefer bytes.deinit(allocator);
    try writeValidated(bytes.writer(allocator), arena, .function_body_v13);
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
    try requireNoFunctionBodyOwnership(arena);
    try requireLegacyEffects(arena);
    try writeValidated(writer, arena, .legacy_v3);
}

pub fn writeCanonicalV4(writer: anytype, arena: *const ir.Arena) !void {
    try validate.validate(arena);
    try requireNoFunctionBodyOwnership(arena);
    try requireNoTypedLookupRequestCapability(arena);
    try requireNoMachineDerivedNodes(arena);
    try writeValidated(writer, arena, .typed_effect_v4);
}

pub fn writeCanonicalV5(writer: anytype, arena: *const ir.Arena) !void {
    try validate.validate(arena);
    try requireNoFunctionBodyOwnership(arena);
    try requireNoTypedLookupRequestCapability(arena);
    try requireNoSequentialRetirementCapability(arena);
    try requireNoMemoryAccessCapability(arena);
    try writeValidated(writer, arena, .register_group_v5);
}

pub fn writeCanonicalV6(writer: anytype, arena: *const ir.Arena) !void {
    try validate.validate(arena);
    try requireNoFunctionBodyOwnership(arena);
    try requireNoTypedLookupRequestCapability(arena);
    try requireNoSequentialRetirementCapability(arena);
    try writeValidated(writer, arena, .memory_access_v6);
}

pub fn writeCanonicalV7(writer: anytype, arena: *const ir.Arena) !void {
    try validate.validate(arena);
    try requireNoFunctionBodyOwnership(arena);
    try requireNoTypedLookupRequestCapability(arena);
    try writeValidated(writer, arena, .sequential_retirement_v7);
}

pub fn writeCanonicalV8(writer: anytype, arena: *const ir.Arena) !void {
    try validate.validate(arena);
    try requireNoFunctionBodyOwnership(arena);
    try requireNoRangeRefinementCapability(arena);
    try writeValidated(writer, arena, .typed_lookup_request_v8);
}

pub fn writeCanonicalV9(writer: anytype, arena: *const ir.Arena) !void {
    try validate.validate(arena);
    try requireNoFunctionBodyOwnership(arena);
    try requireNoConditionalAccessCapability(arena);
    try requireNoProgramControlTargetCapability(arena);
    try requireNoCommittedProgramControlTargetCapability(arena);
    try writeValidated(writer, arena, .range_refinement_v9);
}

pub fn writeCanonicalV10(writer: anytype, arena: *const ir.Arena) !void {
    try validate.validate(arena);
    try requireNoFunctionBodyOwnership(arena);
    try requireNoProgramControlTargetCapability(arena);
    try requireNoCommittedProgramControlTargetCapability(arena);
    try writeValidated(writer, arena, .conditional_access_v10);
}

pub fn writeCanonicalV11(writer: anytype, arena: *const ir.Arena) !void {
    try validate.validate(arena);
    try requireNoFunctionBodyOwnership(arena);
    try requireNoCommittedProgramControlTargetCapability(arena);
    try writeValidated(writer, arena, .program_control_target_v11);
}

pub fn writeCanonicalV12(writer: anytype, arena: *const ir.Arena) !void {
    try validate.validate(arena);
    try requireNoFunctionBodyOwnership(arena);
    try writeValidated(writer, arena, .committed_program_control_target_v12);
}

pub fn writeCanonicalV13(writer: anytype, arena: *const ir.Arena) !void {
    try validate.validate(arena);
    if (!capabilities.hasFunctionBodyOwnership(arena))
        return error.FunctionBodyOwnershipRequiresManifestV13;
    try writeValidated(writer, arena, .function_body_v13);
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
    sequential_retirement_v7,
    typed_lookup_request_v8,
    range_refinement_v9,
    conditional_access_v10,
    program_control_target_v11,
    committed_program_control_target_v12,
    function_body_v13,
};

fn writeValidated(
    writer: anytype,
    arena: *const ir.Arena,
    encoding: Encoding,
) !void {
    if (capabilities.hasFunctionBodyOwnership(arena) and
        encoding != .function_body_v13)
    {
        return error.FunctionBodyOwnershipRequiresManifestV13;
    }
    try writer.writeAll(magic);
    try writeInt(writer, u16, switch (encoding) {
        .legacy_v3 => format_version,
        .typed_effect_v4 => typed_effect_format_version,
        .register_group_v5 => register_group_format_version,
        .memory_access_v6 => memory_access_format_version,
        .sequential_retirement_v7 => sequential_retirement_format_version,
        .typed_lookup_request_v8 => typed_lookup_request_format_version,
        .range_refinement_v9 => range_refinement_format_version,
        .conditional_access_v10 => conditional_access_format_version,
        .program_control_target_v11 => program_control_target_format_version,
        .committed_program_control_target_v12 => committed_program_control_target_format_version,
        .function_body_v13 => function_body_format_version,
    });
    try writeInt(writer, u16, switch (encoding) {
        .legacy_v3 => logical_schema_version,
        .typed_effect_v4 => typed_effect_logical_schema_version,
        .register_group_v5 => register_group_logical_schema_version,
        .memory_access_v6 => memory_access_logical_schema_version,
        .sequential_retirement_v7 => sequential_retirement_logical_schema_version,
        .typed_lookup_request_v8 => typed_lookup_request_logical_schema_version,
        .range_refinement_v9 => range_refinement_logical_schema_version,
        .conditional_access_v10 => conditional_access_logical_schema_version,
        .program_control_target_v11 => program_control_target_logical_schema_version,
        .committed_program_control_target_v12 => committed_program_control_target_logical_schema_version,
        .function_body_v13 => function_body_logical_schema_version,
    });
    try writeCount(writer, arena.nodesView().len);
    try writeCount(writer, arena.constraintsView().len);
    try writeCount(writer, hints.view(arena).len);
    try writeCount(writer, arena.effectsView().len);
    if (encodingHasRangeRefinement(encoding))
        try writeCount(writer, arena.range_refinements.items.len);
    if (encodingHasRangeRefinement(encoding))
        try writeCount(writer, arena.fixed_table_requests.items.len);
    if (encodingHasConditionalAccess(encoding))
        try writeCount(writer, arena.conditional_access_plans.items.len);
    if (encodingHasCommittedProgramControlTarget(encoding))
        try writeCount(writer, arena.committed_program_control_targets.items.len);
    try writeCount(writer, functions.view(arena).len);
    try writeCount(writer, functions.calls(arena).len);

    for (arena.nodesView()) |node| try writeNode(writer, arena, node);
    for (arena.constraintsView()) |constraint| {
        if (encodingHasFunctionBody(encoding))
            try writeOptionalFunctionId(writer, constraint.owner);
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
        if (encodingHasFunctionBody(encoding))
            try writeOptionalFunctionId(writer, hint.owner);
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
        if (encodingHasFunctionBody(encoding))
            try writeOptionalFunctionId(writer, effect.owner);
        try writeInt(writer, u8, effectKindTag(effect.kind));
        if (encoding != .legacy_v3)
            try writeRelationBinding(writer, effect.binding);
        try writeValues(writer, arena.effectValues(id).?);
        try writeOptionalValueId(writer, effect.liveness);
        try writeOptionalInt(writer, u8, effect.access_ordinal);
        try writeSpan(writer, arena, effect.source_span);
    }
    if (encodingHasRangeRefinement(encoding)) {
        for (arena.fixed_table_requests.items) |proof| {
            try writeInt(writer, u32, @intFromEnum(proof.effect));
            try writeValueId(writer, proof.liveness);
            try writeSpan(writer, arena, proof.source_span);
        }
        for (arena.range_refinements.items) |item| {
            try writeValueId(writer, item.source);
            try writeValueId(writer, item.target);
            switch (item.premise) {
                .constraint_boolean => |proof| {
                    try writeInt(writer, u8, 0);
                    try writeInt(writer, u32, @intFromEnum(proof.constraint));
                },
                .fixed_table_field => |proof| {
                    try writeInt(writer, u8, 1);
                    try writeInt(writer, u32, @intFromEnum(proof.effect));
                    try writeInt(writer, u8, proof.field_index);
                    try writeValueId(writer, proof.liveness);
                },
                .aligned_control_target => |proof| {
                    try writeInt(writer, u8, 2);
                    try writeValueId(writer, proof.low);
                    try writeValueId(writer, proof.high);
                    try writeInt(writer, u32, @intFromEnum(proof.low_effect));
                    try writeInt(writer, u32, @intFromEnum(proof.high_effect));
                    try writeValueId(writer, proof.liveness);
                },
                .program_control_target => |proof| {
                    try writeInt(writer, u8, 3);
                    try writeInt(writer, u32, @intFromEnum(proof.program_effect));
                    try writeValueId(writer, proof.current_pc);
                    try writeValueId(writer, proof.offset);
                    switch (proof.kind) {
                        .jump => try writeInt(writer, u8, 0),
                        .branch => |branch| {
                            try writeInt(writer, u8, 1);
                            try writeValueId(writer, branch.condition);
                            try writeInt(writer, u32, @intFromEnum(branch.condition_constraint));
                        },
                    }
                    try writeValueId(writer, proof.liveness);
                },
            }
            try writeSpan(writer, arena, item.source_span);
        }
    }
    if (encodingHasConditionalAccess(encoding)) {
        for (arena.conditional_access_plans.items) |proof| {
            try writeConditionalAccessPlan(writer, arena, proof);
        }
    }
    if (encodingHasCommittedProgramControlTarget(encoding)) {
        for (arena.committed_program_control_targets.items) |proof| {
            try writeCommittedProgramControlTarget(writer, arena, proof);
        }
    }
    for (functions.view(arena), 0..) |function, index| {
        const id = types.idFromIndex(types.FunctionId, index) catch
            return error.ManifestTooLarge;
        try writeName(writer, arena, function.name);
        try writeValues(writer, functions.inputs(arena, id).?);
        try writeValues(writer, functions.outputs(arena, id).?);
        if (encodingHasFunctionBody(encoding))
            try writeFunctionBody(writer, function.body);
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
    if (capabilities.hasRelationBindings(arena))
        return error.RelationBindingsRequireManifestV4;
}

fn requireNoMachineDerivedNodes(arena: *const ir.Arena) ManifestError!void {
    if (capabilities.hasMachineDerivedNodes(arena))
        return error.MachineDerivedRequiresManifestV5;
}

fn requireNoMemoryAccessCapability(arena: *const ir.Arena) ManifestError!void {
    if (capabilities.hasMemoryAccess(arena))
        return error.MemoryAccessRequiresManifestV6;
}

fn requireNoSequentialRetirementCapability(
    arena: *const ir.Arena,
) ManifestError!void {
    if (capabilities.hasSequentialRetirement(arena))
        return error.SequentialRetirementRequiresManifestV7;
}

fn requireNoTypedLookupRequestCapability(
    arena: *const ir.Arena,
) ManifestError!void {
    if (capabilities.hasTypedLookupRequest(arena))
        return error.TypedLookupRequestRequiresManifestV8;
}

fn requireNoRangeRefinementCapability(arena: *const ir.Arena) ManifestError!void {
    if (capabilities.hasRangeRefinement(arena))
        return error.RangeRefinementRequiresManifestV9;
}

fn requireNoConditionalAccessCapability(arena: *const ir.Arena) ManifestError!void {
    if (capabilities.hasConditionalAccess(arena))
        return error.ConditionalAccessRequiresManifestV10;
}

fn requireNoProgramControlTargetCapability(
    arena: *const ir.Arena,
) ManifestError!void {
    if (capabilities.hasProgramControlTarget(arena))
        return error.ProgramControlTargetRequiresManifestV11;
}

fn requireNoCommittedProgramControlTargetCapability(
    arena: *const ir.Arena,
) ManifestError!void {
    if (capabilities.hasCommittedProgramControlTarget(arena))
        return error.CommittedProgramControlTargetRequiresManifestV12;
}

fn requireNoFunctionBodyOwnership(arena: *const ir.Arena) ManifestError!void {
    if (capabilities.hasFunctionBodyOwnership(arena))
        return error.FunctionBodyOwnershipRequiresManifestV13;
}

fn leastCapableEncoding(arena: *const ir.Arena) Encoding {
    if (capabilities.hasFunctionBodyOwnership(arena))
        return .function_body_v13;
    if (capabilities.hasCommittedProgramControlTarget(arena))
        return .committed_program_control_target_v12;
    if (capabilities.hasProgramControlTarget(arena))
        return .program_control_target_v11;
    if (capabilities.hasConditionalAccess(arena)) return .conditional_access_v10;
    if (capabilities.hasRangeRefinement(arena)) return .range_refinement_v9;
    if (capabilities.hasTypedLookupRequest(arena))
        return .typed_lookup_request_v8;
    if (capabilities.hasSequentialRetirement(arena))
        return .sequential_retirement_v7;
    if (capabilities.hasMemoryAccess(arena)) return .memory_access_v6;
    if (capabilities.hasMachineDerivedNodes(arena)) return .register_group_v5;
    if (capabilities.hasRelationBindings(arena)) return .typed_effect_v4;
    return .legacy_v3;
}

fn encodingHasRangeRefinement(encoding: Encoding) bool {
    return switch (encoding) {
        .range_refinement_v9,
        .conditional_access_v10,
        .program_control_target_v11,
        .committed_program_control_target_v12,
        .function_body_v13,
        => true,
        else => false,
    };
}

fn encodingHasConditionalAccess(encoding: Encoding) bool {
    return switch (encoding) {
        .conditional_access_v10,
        .program_control_target_v11,
        .committed_program_control_target_v12,
        .function_body_v13,
        => true,
        else => false,
    };
}

fn encodingHasCommittedProgramControlTarget(encoding: Encoding) bool {
    return encoding == .committed_program_control_target_v12 or
        encoding == .function_body_v13;
}

fn encodingHasFunctionBody(encoding: Encoding) bool {
    return encoding == .function_body_v13;
}

const writeFunctionBody = manifest_encoding.writeFunctionBody;
const writeCommittedProgramControlTarget = manifest_encoding.writeCommittedProgramControlTarget;
const writeConditionalAccessPlan = manifest_encoding.writeConditionalAccessPlan;
const writeRelationBinding = manifest_encoding.writeRelationBinding;
const writeNode = manifest_encoding.writeNode;
const writeType = manifest_encoding.writeType;
const writeSpan = manifest_encoding.writeSpan;
const writePosition = manifest_encoding.writePosition;
const writeName = manifest_encoding.writeName;
const writeString = manifest_encoding.writeString;
const writeValues = manifest_encoding.writeValues;
const writeBinary = manifest_encoding.writeBinary;
const writeValueId = manifest_encoding.writeValueId;
const writeOptionalValueId = manifest_encoding.writeOptionalValueId;
const writeOptionalFunctionId = manifest_encoding.writeOptionalFunctionId;
const writeHintBindingTarget = manifest_encoding.writeHintBindingTarget;
const writeOptionalInt = manifest_encoding.writeOptionalInt;
const writeCount = manifest_encoding.writeCount;
const writeInt = manifest_encoding.writeInt;
const arrayElementTag = manifest_encoding.arrayElementTag;
const constraintCategoryTag = manifest_encoding.constraintCategoryTag;
const effectKindTag = manifest_encoding.effectKindTag;
const callStrategyTag = manifest_encoding.callStrategyTag;
