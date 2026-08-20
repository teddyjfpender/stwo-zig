//! Allocation-free structural validation for completed logical AIR programs.
//!
//! Constructors maintain these invariants during normal authoring. This pass
//! deliberately re-establishes them from stored data so deserializers and
//! future compiler passes have one defensive boundary before lowering.

const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const effects = @import("effects.zig");
const expr = @import("expr.zig");
const functions = @import("functions.zig");
const hint_recipe = @import("hint_recipe.zig");
const hints = @import("hints.zig");
const ir = @import("ir.zig");
const program = @import("program.zig");
const range_refinement = @import("range_refinement.zig");
const relation = @import("relation.zig");
const types = @import("types.zig");
const bounded_arithmetic = @import("bounded_arithmetic.zig");
const validate_support = @import("validate_support.zig");

pub const Error = error{
    DuplicateAccessOrdinal,
    DuplicateConstraintName,
    DuplicateFunctionName,
    DuplicateName,
    DuplicateNode,
    DuplicateSource,
    InvalidAccessOrdinal,
    InvalidCall,
    InvalidCallGraph,
    InvalidCallOutput,
    InvalidConstraint,
    InvalidEffect,
    InvalidFunction,
    InvalidFunctionBody,
    InvalidHint,
    InvalidHintBinding,
    InvalidHintOutput,
    InvalidInternTable,
    InvalidName,
    InvalidNodeOrder,
    InvalidNodeReference,
    InvalidNodeShape,
    InvalidRange,
    InvalidRangeRefinement,
    InvalidSource,
    InvalidSourceSpan,
    InvalidType,
    NonCanonicalNode,
    UnboundHintOutput,
    UnknownHintRecipe,
};

/// Validates in stable arena order and returns the first structural error.
/// It allocates nothing. Interning caches are verified as integrity indexes,
/// never treated as an independent source of semantic truth.
pub fn validate(arena: *const ir.Arena) Error!void {
    try validateNames(arena);
    try validateSources(arena);
    try validateHints(arena);
    try validateFunctions(arena);
    try validateCalls(arena);
    try validateNodes(arena);
    try validateHintInvocations(arena);
    try validateConstraints(arena);
    try validateEffects(arena);
    range_refinement.validateProgram(arena) catch
        return error.InvalidRangeRefinement;
    try validateHintBindings(arena);
    try validateFunctionBodyOwnership(arena);
}

fn validateNames(arena: *const ir.Arena) Error!void {
    if (arena.names_by_text.count() != arena.names.items.len)
        return error.InvalidInternTable;
    for (arena.names.items, 0..) |name, index| {
        if (name.len == 0) return error.InvalidName;
        const expected = types.idFromIndex(types.NameId, index) catch
            return error.InvalidName;
        const actual = arena.names_by_text.get(name) orelse
            return error.InvalidInternTable;
        if (actual != expected) return error.DuplicateName;
    }
}

fn validateSources(arena: *const ir.Arena) Error!void {
    if (arena.sources_by_path.count() != arena.sources.items.len)
        return error.InvalidInternTable;
    for (arena.sources.items, 0..) |item, index| {
        if (!validName(arena, item.path)) return error.InvalidSource;
        const expected = types.idFromIndex(types.SourceId, index) catch
            return error.InvalidSource;
        const actual = arena.sources_by_path.get(item.path) orelse
            return error.InvalidInternTable;
        if (actual != expected) return error.DuplicateSource;
    }
}

fn validateHints(arena: *const ir.Arena) Error!void {
    var input_cursor: usize = 0;
    var output_cursor: usize = 0;
    for (hints.view(arena), 0..) |hint, hint_index| {
        if (hint_recipe.getById(hint.recipe) == null)
            return error.UnknownHintRecipe;
        validateSpan(arena, hint.source_span) catch return error.InvalidSourceSpan;
        if (hint.activation) |activation| {
            if (!validValue(arena, activation)) return error.InvalidHint;
        }

        const inputs = try canonicalRange(
            hint.inputs,
            arena.hint_inputs.items,
            &input_cursor,
        );
        const outputs = try canonicalRange(
            hint.outputs,
            arena.hint_outputs.items,
            &output_cursor,
        );
        if (outputs.len == 0) return error.InvalidHint;
        for (inputs) |input_id| {
            if (!validValue(arena, input_id)) return error.InvalidHint;
        }
        for (outputs, 0..) |output_id, output_index| {
            const output_node = arena.node(output_id) orelse
                return error.InvalidHintOutput;
            switch (output_node.key.op) {
                .hint_output => |binding| {
                    if (types.idIndex(binding.hint) != hint_index or
                        binding.index != output_index)
                    {
                        return error.InvalidHintOutput;
                    }
                },
                else => return error.InvalidHintOutput,
            }
        }
    }
    if (input_cursor != arena.hint_inputs.items.len or
        output_cursor != arena.hint_outputs.items.len)
    {
        return error.InvalidRange;
    }
}

fn validateHintInvocations(arena: *const ir.Arena) Error!void {
    for (hints.view(arena), 0..) |hint, hint_index| {
        const item = hint_recipe.getById(hint.recipe) orelse
            return error.UnknownHintRecipe;
        const hint_id = types.idFromIndex(types.HintId, hint_index) catch
            return error.InvalidHint;
        const inputs = hints.inputs(arena, hint_id) orelse
            return error.InvalidHint;
        const outputs = hints.outputs(arena, hint_id) orelse
            return error.InvalidHint;
        if (inputs.len != item.input_types.len or
            outputs.len != item.output_types.len)
        {
            return error.InvalidHint;
        }
        for (inputs, item.input_types) |input_id, expected_type| {
            const input = arena.node(input_id) orelse return error.InvalidHint;
            if (!std.meta.eql(input.key.ty, expected_type))
                return error.InvalidHint;
        }
        for (outputs, item.output_types) |output_id, expected_type| {
            const output = arena.node(output_id) orelse
                return error.InvalidHintOutput;
            if (!std.meta.eql(output.key.ty, expected_type))
                return error.InvalidHintOutput;
        }
        if (hint.activation) |activation_id| {
            const activation = arena.node(activation_id) orelse
                return error.InvalidHint;
            if (!activation.key.ty.isSelector()) return error.InvalidHint;
        }
    }
}

fn validateNodes(arena: *const ir.Arena) Error!void {
    if (arena.interned_nodes.count() != arena.nodesView().len)
        return error.InvalidInternTable;
    for (arena.nodesView(), 0..) |node, index| {
        node.key.ty.validate() catch return error.InvalidType;
        validateSpan(arena, node.primary_source) catch
            return error.InvalidSourceSpan;
        try validateNode(arena, node, index);

        const expected = types.idFromIndex(types.ValueId, index) catch
            return error.InvalidNodeReference;
        const actual = arena.interned_nodes.get(node.key) orelse
            return error.InvalidInternTable;
        if (actual != expected) return error.DuplicateNode;
    }
}

fn validateNode(arena: *const ir.Arena, node: expr.Node, index: usize) Error!void {
    switch (node.key.op) {
        .constant => |constant| switch (constant) {
            .field => |value| {
                if (!isFelt(node.key.ty) or value >= m31.Modulus)
                    return error.InvalidNodeShape;
            },
            .unsigned => |value| {
                const maximum = ir.maxUnsignedValue(node.key.ty) catch
                    return error.InvalidNodeShape;
                if (value > maximum) return error.InvalidNodeShape;
            },
        },
        .input => |name| {
            if (!validName(arena, name)) return error.InvalidNodeShape;
            const id = types.idFromIndex(types.ValueId, index) catch
                return error.InvalidNodeReference;
            const alias_source = semanticAliasSource(arena, id);
            for (arena.nodesView()[0..index], 0..) |prior, prior_index| {
                switch (prior.key.op) {
                    .input => |prior_name| if (prior_name == name and
                        (alias_source == null or
                            types.idIndex(alias_source.?) != prior_index))
                    {
                        return error.InvalidNodeShape;
                    },
                    else => {},
                }
            }
        },
        .add, .sub, .mul => |binary| {
            const lhs = try priorNode(arena, binary.lhs, index);
            const rhs = try priorNode(arena, binary.rhs, index);
            if (!ir.isFieldScalar(lhs.key.ty) or
                !ir.isFieldScalar(rhs.key.ty))
            {
                const id = types.idFromIndex(types.ValueId, index) catch
                    return error.InvalidNodeReference;
                if ((!isFelt(node.key.ty) and
                    !std.meta.eql(node.key.ty, types.Type.pc)) or
                    !range_refinement.isProgramControlPcAdd(arena, id))
                {
                    return error.InvalidNodeShape;
                }
            }
            if (!isFelt(node.key.ty)) switch (node.key.op) {
                .add => {
                    if (isSemanticAliasTarget(arena, @enumFromInt(index))) {
                        // The terminal evidence graph validates this clone.
                    } else if (std.meta.eql(node.key.ty, types.Type.selector)) {
                        if (!isCanonicalOneHotSelector(arena, index))
                            return error.InvalidNodeShape;
                    } else {
                        const expected = bounded_arithmetic.resultType(
                            arena,
                            .add,
                            binary.lhs,
                            binary.rhs,
                        ) catch return error.InvalidNodeShape;
                        if (!std.meta.eql(node.key.ty, expected))
                            return error.InvalidNodeShape;
                    }
                },
                .mul => {
                    if (!isSemanticAliasTarget(arena, @enumFromInt(index))) {
                        const expected = bounded_arithmetic.resultType(
                            arena,
                            .mul,
                            binary.lhs,
                            binary.rhs,
                        ) catch return error.InvalidNodeShape;
                        if (!std.meta.eql(node.key.ty, expected))
                            return error.InvalidNodeShape;
                    }
                },
                .sub => if (!isSemanticAliasTarget(arena, @enumFromInt(index)))
                    return error.InvalidNodeShape,
                else => unreachable,
            };
            switch (node.key.op) {
                .add, .mul => if (types.idIndex(binary.lhs) >
                    types.idIndex(binary.rhs))
                {
                    return error.NonCanonicalNode;
                },
                else => {},
            }
        },
        .neg => |value| {
            const operand = try priorNode(arena, value, index);
            if (!isFelt(node.key.ty) or !ir.isFieldScalar(operand.key.ty))
                return error.InvalidNodeShape;
        },
        .select => |selection| {
            const selector = try priorNode(arena, selection.selector, index);
            const when_true = try priorNode(arena, selection.when_true, index);
            const when_false = try priorNode(arena, selection.when_false, index);
            if (!ir.isSelector(selector.key.ty) or
                !std.meta.eql(when_true.key.ty, when_false.key.ty) or
                !std.meta.eql(node.key.ty, when_true.key.ty))
            {
                return error.InvalidNodeShape;
            }
        },
        .hint_output => |binding| {
            const outputs = hints.outputs(arena, binding.hint) orelse
                return error.InvalidHintOutput;
            const output_index: usize = binding.index;
            if (output_index >= outputs.len or
                types.idIndex(outputs[output_index]) != index)
            {
                return error.InvalidHintOutput;
            }
        },
        .call_output => |binding| {
            const outputs = functions.callOutputs(arena, binding.call) orelse
                return error.InvalidCallOutput;
            const output_index: usize = binding.index;
            if (output_index >= outputs.len or
                types.idIndex(outputs[output_index]) != index)
            {
                return error.InvalidCallOutput;
            }
        },
        .machine_derived => |derived| switch (derived) {
            .register_address => |address| {
                const register = try priorNode(arena, address.index, index);
                if (!std.meta.eql(node.key.ty, types.Type.address) or
                    !std.meta.eql(register.key.ty, types.Type.register_index))
                {
                    return error.InvalidNodeShape;
                }
            },
            .aligned_word_address => |address| {
                const word_index = try priorNode(arena, address.word_index, index);
                if (!std.meta.eql(node.key.ty, types.Type.address) or
                    !std.meta.eql(word_index.key.ty, types.Type.uint20))
                {
                    return error.InvalidNodeShape;
                }
            },
            .access_clock => |clock| {
                const instruction_clock = try priorNode(
                    arena,
                    clock.instruction_clock,
                    index,
                );
                if (!std.meta.eql(node.key.ty, types.Type.clock) or
                    !std.meta.eql(instruction_clock.key.ty, types.Type.clock))
                {
                    return error.InvalidNodeShape;
                }
            },
            .strict_clock_gap => |gap| {
                const current = try priorNode(arena, gap.current_clock, index);
                const previous = try priorNode(arena, gap.previous_clock, index);
                const active = try priorNode(arena, gap.active, index);
                if (!std.meta.eql(node.key.ty, types.Type.uint20) or
                    !std.meta.eql(current.key.ty, types.Type.clock) or
                    !std.meta.eql(previous.key.ty, types.Type.clock) or
                    !ir.isSelector(active.key.ty))
                {
                    return error.InvalidNodeShape;
                }
                const current_clock = switch (current.key.op) {
                    .machine_derived => |current_derived| switch (current_derived) {
                        .access_clock => |clock| clock,
                        else => return error.InvalidNodeShape,
                    },
                    else => return error.InvalidNodeShape,
                };
                if (current_clock.phase != gap.phase)
                    return error.InvalidNodeShape;
            },
            .instruction_next_pc => |next| {
                const current = try priorNode(arena, next.current, index);
                if (!std.meta.eql(node.key.ty, types.Type.pc) or
                    !std.meta.eql(current.key.ty, types.Type.pc))
                {
                    return error.InvalidNodeShape;
                }
            },
            .instruction_next_clock => |next| {
                const current = try priorNode(arena, next.current, index);
                if (!std.meta.eql(node.key.ty, types.Type.clock) or
                    !std.meta.eql(current.key.ty, types.Type.clock))
                {
                    return error.InvalidNodeShape;
                }
            },
        },
    }
}

fn isCanonicalOneHotSelector(arena: *const ir.Arena, root_index: usize) bool {
    var leaves: [bounded_arithmetic.MAX_ONE_HOT_INPUTS]types.ValueId = undefined;
    var leaf_count: usize = 0;
    const root = types.idFromIndex(types.ValueId, root_index) catch return false;
    collectOneHotLeaves(arena, root, root_index + 1, &leaves, &leaf_count) catch
        return false;
    if (leaf_count < 2 or leaf_count > leaves.len) return false;
    for (leaves[0..leaf_count], 0..) |leaf, index| {
        for (leaves[0..index]) |prior| if (prior == leaf) return false;
    }
    return true;
}

fn collectOneHotLeaves(
    arena: *const ir.Arena,
    id: types.ValueId,
    root_limit: usize,
    leaves: *[bounded_arithmetic.MAX_ONE_HOT_INPUTS]types.ValueId,
    leaf_count: *usize,
) error{InvalidShape}!void {
    const index = types.idIndex(id);
    if (index >= root_limit) return error.InvalidShape;
    const node = arena.node(id) orelse return error.InvalidShape;
    if (std.meta.eql(node.key.ty, types.Type.bit)) {
        if (leaf_count.* == leaves.len) return error.InvalidShape;
        leaves[leaf_count.*] = id;
        leaf_count.* += 1;
        return;
    }
    const binary = switch (node.key.op) {
        .add => |binary| binary,
        else => return error.InvalidShape,
    };
    if (!(isFelt(node.key.ty) or
        std.meta.eql(node.key.ty, types.Type.selector)))
    {
        return error.InvalidShape;
    }
    try collectOneHotLeaves(arena, binary.lhs, index, leaves, leaf_count);
    try collectOneHotLeaves(arena, binary.rhs, index, leaves, leaf_count);
}

fn validateConstraints(arena: *const ir.Arena) Error!void {
    for (arena.constraintsView(), 0..) |constraint, index| {
        if (!validName(arena, constraint.name)) return error.InvalidConstraint;
        validateSpan(arena, constraint.source_span) catch
            return error.InvalidSourceSpan;
        const root = arena.node(constraint.root) orelse
            return error.InvalidConstraint;
        if (!ir.isFieldScalar(root.key.ty)) return error.InvalidConstraint;
        if (constraint.gate) |gate_id| {
            const gate = arena.node(gate_id) orelse
                return error.InvalidConstraint;
            if (!ir.isSelector(gate.key.ty)) return error.InvalidConstraint;
        }
        for (arena.constraintsView()[0..index]) |prior| {
            if (constraint.name == prior.name)
                return error.DuplicateConstraintName;
        }
    }
}

fn validateEffects(arena: *const ir.Arena) Error!void {
    var value_cursor: usize = 0;
    var used_ordinals = [_]bool{false} ** 256;
    for (arena.effectsView()) |effect| {
        validateSpan(arena, effect.source_span) catch
            return error.InvalidSourceSpan;
        const values = try canonicalRange(
            effect.values,
            arena.effectValuesView(),
            &value_cursor,
        );
        if (values.len == 0) return error.InvalidEffect;
        for (values) |value| {
            if (!validValue(arena, value)) return error.InvalidEffect;
        }
        if (effect.liveness) |liveness_id| {
            const valid_liveness = if (effect.kind == .component_call)
                (arena.node(liveness_id) orelse
                    return error.InvalidEffect).key.ty.isFieldScalar()
            else if (effect.binding) |binding| blk: {
                const schema = relation.getById(binding.schema) orelse break :blk false;
                break :blk switch (schema.multiplicity) {
                    .role_signed_liveness => range_refinement.isBoundedLiveness(
                        arena,
                        liveness_id,
                    ),
                    .role_signed_weight => (arena.node(liveness_id) orelse
                        break :blk false).key.ty.isFieldScalar(),
                };
            } else range_refinement.isBoundedLiveness(arena, liveness_id);
            if (!valid_liveness)
                return error.InvalidEffect;
        }
        // The old provisional record treated ordinals as globally unique.
        // Relation-bound access groups deliberately share one ordinal across
        // consume, emit, and clock-gap events; their group validator owns that
        // policy.  Preserve the legacy rule only for unbound records.
        if (effect.binding == null) {
            if (ir.requiresAccessOrdinal(effect.kind) !=
                (effect.access_ordinal != null))
            {
                return error.InvalidAccessOrdinal;
            }
            if (effect.access_ordinal) |ordinal| {
                if (used_ordinals[ordinal]) return error.DuplicateAccessOrdinal;
                used_ordinals[ordinal] = true;
            }
        }
    }
    if (value_cursor != arena.effectValuesView().len)
        return error.InvalidRange;
    effects.validateProgram(arena) catch return error.InvalidEffect;
}

fn validateHintBindings(arena: *const ir.Arena) Error!void {
    var binding_cursor: usize = 0;
    var path_cursor: usize = 0;
    for (hints.view(arena), 0..) |hint, hint_index| {
        const range = hint.bindings orelse return error.UnboundHintOutput;
        const hint_bindings = try canonicalBindingRange(
            range,
            arena.hint_bindings.items,
            &binding_cursor,
        );
        if (hint_bindings.len == 0) return error.UnboundHintOutput;
        const hint_id = types.idFromIndex(types.HintId, hint_index) catch
            return error.InvalidHintBinding;
        const outputs = hints.outputs(arena, hint_id) orelse
            return error.InvalidHintBinding;

        for (hint_bindings, 0..) |binding, binding_index| {
            const output_index: usize = binding.output_index;
            if (output_index >= outputs.len) return error.InvalidHintBinding;
            if (binding_index != 0 and
                !hintBindingLess(hint_bindings[binding_index - 1], binding))
            {
                return error.InvalidHintBinding;
            }
            const path = try canonicalRange(
                binding.path,
                arena.hint_binding_values.items,
                &path_cursor,
            );
            if (!hints.targetMatchesActivation(arena, hint.activation, binding.target) or
                !hints.pathIsValid(
                    arena,
                    outputs[output_index],
                    binding.target,
                    path,
                ))
            {
                return error.InvalidHintBinding;
            }
        }

        for (outputs, 0..) |_, output_index| {
            var found = false;
            for (hint_bindings) |binding| {
                if (binding.output_index == output_index) {
                    found = true;
                    break;
                }
            }
            if (!found) return error.UnboundHintOutput;
        }
    }
    if (binding_cursor != arena.hint_bindings.items.len or
        path_cursor != arena.hint_binding_values.items.len)
    {
        return error.InvalidRange;
    }
}

fn validateFunctions(arena: *const ir.Arena) Error!void {
    if (arena.open_function != null or arena.open_function_body)
        return error.InvalidFunction;
    var input_cursor: usize = 0;
    var output_cursor: usize = 0;
    for (functions.view(arena), 0..) |function, index| {
        if (!validName(arena, function.name)) return error.InvalidFunction;
        if (!function.complete) return error.InvalidFunction;
        validateSpan(arena, function.source_span) catch
            return error.InvalidSourceSpan;
        const inputs = try canonicalRange(
            function.inputs,
            arena.function_inputs.items,
            &input_cursor,
        );
        const outputs = try canonicalRange(
            function.outputs,
            arena.function_outputs.items,
            &output_cursor,
        );
        for (inputs) |input_id| {
            const input_node = arena.node(input_id) orelse
                return error.InvalidFunction;
            if (input_node.key.op != .input) return error.InvalidFunction;
        }
        for (outputs) |output_id| {
            if (!validValue(arena, output_id)) return error.InvalidFunction;
        }
        for (functions.view(arena)[0..index]) |prior| {
            if (function.name == prior.name)
                return error.DuplicateFunctionName;
        }
    }
    if (input_cursor != arena.function_inputs.items.len or
        output_cursor != arena.function_outputs.items.len)
    {
        return error.InvalidRange;
    }
}

/// Re-establishes the redundant, authenticated owner/range boundary for the
/// opt-in function-body representation. This pass deliberately allocates
/// nothing: body ranges are small contiguous indexes and expression nodes are
/// already topological, so dependency visibility can be checked directly.
fn validateFunctionBodyOwnership(arena: *const ir.Arena) Error!void {
    for (functions.view(arena), 0..) |function, function_index| {
        const body = function.body orelse continue;
        const owner = types.idFromIndex(types.FunctionId, function_index) catch
            return error.InvalidFunctionBody;

        try validateItemRange(body.constraints, arena.constraintsView().len);
        try validateItemRange(body.effects, arena.effectsView().len);
        try validateItemRange(body.hints, hints.view(arena).len);
        try validateItemRange(body.calls, functions.calls(arena).len);

        for (@as(usize, body.constraints.start)..itemEnd(body.constraints)) |index| {
            if (arena.constraintsView()[index].owner != owner)
                return error.InvalidFunctionBody;
        }
        for (@as(usize, body.effects.start)..itemEnd(body.effects)) |index| {
            if (arena.effectsView()[index].owner != owner)
                return error.InvalidFunctionBody;
        }
        for (@as(usize, body.hints.start)..itemEnd(body.hints)) |index| {
            if (hints.view(arena)[index].owner != owner)
                return error.InvalidFunctionBody;
        }
        for (@as(usize, body.calls.start)..itemEnd(body.calls)) |index| {
            if (functions.calls(arena)[index].caller != owner)
                return error.InvalidFunctionBody;
        }

        const declared_outputs = functions.outputs(arena, owner) orelse
            return error.InvalidFunctionBody;
        for (declared_outputs) |value| {
            if (!valueAccessibleToOwner(arena, value, owner))
                return error.InvalidFunctionBody;
        }

        for (@as(usize, body.constraints.start)..itemEnd(body.constraints)) |index| {
            const constraint = arena.constraintsView()[index];
            if (!valueAccessibleToOwner(arena, constraint.root, owner) or
                (constraint.gate != null and
                    !valueAccessibleToOwner(arena, constraint.gate.?, owner)))
            {
                return error.InvalidFunctionBody;
            }
        }
        for (@as(usize, body.effects.start)..itemEnd(body.effects)) |index| {
            const effect = arena.effectsView()[index];
            const values = effect.values.slice(arena.effectValuesView()) orelse
                return error.InvalidFunctionBody;
            for (values) |value| {
                if (!valueAccessibleToOwner(arena, value, owner))
                    return error.InvalidFunctionBody;
            }
            if (effect.liveness) |liveness| {
                if (!valueAccessibleToOwner(arena, liveness, owner))
                    return error.InvalidFunctionBody;
            }
        }
        for (@as(usize, body.hints.start)..itemEnd(body.hints)) |index| {
            const hint_id = types.idFromIndex(types.HintId, index) catch
                return error.InvalidFunctionBody;
            const invocation = hints.view(arena)[index];
            for (hints.inputs(arena, hint_id) orelse
                return error.InvalidFunctionBody) |value|
            {
                if (!valueAccessibleToOwner(arena, value, owner))
                    return error.InvalidFunctionBody;
            }
            if (invocation.activation) |activation| {
                if (!valueAccessibleToOwner(arena, activation, owner))
                    return error.InvalidFunctionBody;
            }
        }
        for (@as(usize, body.calls.start)..itemEnd(body.calls)) |index| {
            const call_id = types.idFromIndex(types.CallId, index) catch
                return error.InvalidFunctionBody;
            for (functions.callArguments(arena, call_id) orelse
                return error.InvalidFunctionBody) |value|
            {
                if (!valueAccessibleToOwner(arena, value, owner))
                    return error.InvalidFunctionBody;
            }
        }
    }

    // Every explicit owner must be covered by the matching sealed range. This
    // reverse direction is what catches one-record omissions and truncated
    // bodies; the forward checks above catch overlap and cross-owner ranges.
    for (arena.constraintsView(), 0..) |constraint, index| {
        try requireOwnerCoverage(arena, constraint.owner, .constraints, index);
    }
    for (arena.effectsView(), 0..) |effect, index| {
        try requireOwnerCoverage(arena, effect.owner, .effects, index);
    }
    for (hints.view(arena), 0..) |hint, index| {
        try requireOwnerCoverage(arena, hint.owner, .hints, index);
        const bindings = hints.bindings(
            arena,
            types.idFromIndex(types.HintId, index) catch
                return error.InvalidFunctionBody,
        ) orelse return error.InvalidFunctionBody;
        for (bindings) |binding| {
            const target_owner = switch (binding.target) {
                .constraint => |id| (arena.constraint(id) orelse
                    return error.InvalidFunctionBody).owner,
                .effect => |id| (arena.effect(id) orelse
                    return error.InvalidFunctionBody).owner,
            };
            if (target_owner != hint.owner) return error.InvalidFunctionBody;
        }
    }
    for (functions.calls(arena), 0..) |call, index| {
        const caller = call.caller orelse continue;
        const declaration = functions.get(arena, caller) orelse
            return error.InvalidFunctionBody;
        if (declaration.body) |body| {
            if (!body.calls.contains(index)) return error.InvalidFunctionBody;
        }
    }
}

const BodyRecordKind = enum { constraints, effects, hints };

fn requireOwnerCoverage(
    arena: *const ir.Arena,
    owner: ?types.FunctionId,
    comptime kind: BodyRecordKind,
    index: usize,
) Error!void {
    const function_id = owner orelse return;
    const declaration = functions.get(arena, function_id) orelse
        return error.InvalidFunctionBody;
    const body = declaration.body orelse return error.InvalidFunctionBody;
    const range = switch (kind) {
        .constraints => body.constraints,
        .effects => body.effects,
        .hints => body.hints,
    };
    if (!range.contains(index)) return error.InvalidFunctionBody;
}

fn validateItemRange(range: program.ItemRange, item_count: usize) Error!void {
    if (range.len == 0 and range.start != 0)
        return error.InvalidFunctionBody;
    const end = range.end() orelse return error.InvalidFunctionBody;
    if (end > item_count) return error.InvalidFunctionBody;
}

fn itemEnd(range: program.ItemRange) usize {
    return @as(usize, range.start) + @as(usize, range.len);
}

fn valueAccessibleToOwner(
    arena: *const ir.Arena,
    value: types.ValueId,
    owner: types.FunctionId,
) bool {
    const node = arena.node(value) orelse return false;
    return switch (node.key.op) {
        .constant => true,
        .input => containsValue(functions.inputs(arena, owner) orelse return false, value),
        .add, .sub, .mul => |binary| valueAccessibleToOwner(arena, binary.lhs, owner) and
            valueAccessibleToOwner(arena, binary.rhs, owner),
        .neg => |operand| valueAccessibleToOwner(arena, operand, owner),
        .select => |selection| valueAccessibleToOwner(arena, selection.selector, owner) and
            valueAccessibleToOwner(arena, selection.when_true, owner) and
            valueAccessibleToOwner(arena, selection.when_false, owner),
        .hint_output => |output| blk: {
            const hint = hints.get(arena, output.hint) orelse break :blk false;
            break :blk hint.owner == owner;
        },
        .call_output => |output| blk: {
            const call = functions.getCall(arena, output.call) orelse break :blk false;
            break :blk call.caller == owner;
        },
        .machine_derived => |derived| switch (derived) {
            .register_address => |address| valueAccessibleToOwner(arena, address.index, owner),
            .aligned_word_address => |address| valueAccessibleToOwner(arena, address.word_index, owner),
            .access_clock => |clock| valueAccessibleToOwner(arena, clock.instruction_clock, owner),
            .strict_clock_gap => |gap| valueAccessibleToOwner(arena, gap.current_clock, owner) and
                valueAccessibleToOwner(arena, gap.previous_clock, owner) and
                valueAccessibleToOwner(arena, gap.active, owner),
            .instruction_next_pc => |next| valueAccessibleToOwner(arena, next.current, owner),
            .instruction_next_clock => |next| valueAccessibleToOwner(arena, next.current, owner),
        },
    };
}

fn containsValue(values: []const types.ValueId, wanted: types.ValueId) bool {
    return std.mem.indexOfScalar(types.ValueId, values, wanted) != null;
}

const validateCalls = validate_support.validateCalls;
const canonicalRange = validate_support.canonicalRange;
const canonicalBindingRange = validate_support.canonicalBindingRange;
const hintBindingLess = validate_support.hintBindingLess;
const priorNode = validate_support.priorNode;
const validName = validate_support.validName;
const validValue = validate_support.validValue;
const semanticAliasSource = validate_support.semanticAliasSource;
const isSemanticAliasTarget = validate_support.isSemanticAliasTarget;
const validateSpan = validate_support.validateSpan;
const isFelt = validate_support.isFelt;
