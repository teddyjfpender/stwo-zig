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
const types = @import("types.zig");

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
    InvalidHint,
    InvalidHintBinding,
    InvalidHintOutput,
    InvalidInternTable,
    InvalidName,
    InvalidNodeOrder,
    InvalidNodeReference,
    InvalidNodeShape,
    InvalidRange,
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
    try validateHintBindings(arena);
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
            for (arena.nodesView()[0..index]) |prior| {
                switch (prior.key.op) {
                    .input => |prior_name| if (prior_name == name)
                        return error.InvalidNodeShape,
                    else => {},
                }
            }
        },
        .add, .sub, .mul => |binary| {
            const lhs = try priorNode(arena, binary.lhs, index);
            const rhs = try priorNode(arena, binary.rhs, index);
            if (!isFelt(node.key.ty) or
                !ir.isFieldScalar(lhs.key.ty) or
                !ir.isFieldScalar(rhs.key.ty))
            {
                return error.InvalidNodeShape;
            }
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
                if (current_clock.ordinal != gap.ordinal)
                    return error.InvalidNodeShape;
            },
        },
    }
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
            const liveness = arena.node(liveness_id) orelse
                return error.InvalidEffect;
            if (!ir.isSelector(liveness.key.ty)) return error.InvalidEffect;
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
    if (arena.open_function != null) return error.InvalidFunction;
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

fn validateCalls(arena: *const ir.Arena) Error!void {
    var argument_cursor: usize = 0;
    var output_cursor: usize = 0;
    for (functions.calls(arena), 0..) |call, call_index| {
        validateSpan(arena, call.source_span) catch
            return error.InvalidSourceSpan;
        const callee = functions.get(arena, call.callee) orelse
            return error.InvalidCall;
        if (!callee.complete) return error.InvalidCall;
        if (call.caller) |caller_id| {
            const caller = functions.get(arena, caller_id) orelse
                return error.InvalidCall;
            if (!caller.complete) return error.InvalidCall;
            if (types.idIndex(call.callee) >= types.idIndex(caller_id))
                return error.InvalidCallGraph;
        }
        const arguments = try canonicalRange(
            call.arguments,
            arena.call_arguments.items,
            &argument_cursor,
        );
        const outputs = try canonicalRange(
            call.outputs,
            arena.call_outputs.items,
            &output_cursor,
        );
        const expected_inputs = functions.inputs(arena, call.callee) orelse
            return error.InvalidCall;
        const expected_outputs = functions.outputs(arena, call.callee) orelse
            return error.InvalidCall;
        if (arguments.len != expected_inputs.len or
            outputs.len != expected_outputs.len)
        {
            return error.InvalidCall;
        }
        for (arguments, expected_inputs) |actual_id, expected_id| {
            const actual = arena.node(actual_id) orelse return error.InvalidCall;
            const expected = arena.node(expected_id) orelse return error.InvalidCall;
            if (!std.meta.eql(actual.key.ty, expected.key.ty))
                return error.InvalidCall;
        }
        for (outputs, expected_outputs, 0..) |output_id, expected_id, output_index| {
            const output_node = arena.node(output_id) orelse
                return error.InvalidCallOutput;
            const expected_node = arena.node(expected_id) orelse
                return error.InvalidCall;
            if (!std.meta.eql(output_node.key.ty, expected_node.key.ty))
                return error.InvalidCallOutput;
            switch (output_node.key.op) {
                .call_output => |binding| {
                    if (types.idIndex(binding.call) != call_index or
                        binding.index != output_index)
                    {
                        return error.InvalidCallOutput;
                    }
                },
                else => return error.InvalidCallOutput,
            }
        }
    }
    if (argument_cursor != arena.call_arguments.items.len or
        output_cursor != arena.call_outputs.items.len)
    {
        return error.InvalidRange;
    }
}

fn canonicalRange(
    range: program.RefRange,
    values: []const types.ValueId,
    cursor: *usize,
) Error![]const types.ValueId {
    if (range.start != cursor.*) return error.InvalidRange;
    const slice = range.slice(values) orelse return error.InvalidRange;
    cursor.* = std.math.add(usize, cursor.*, slice.len) catch
        return error.InvalidRange;
    return slice;
}

fn canonicalBindingRange(
    range: program.RefRange,
    values: []const program.HintBinding,
    cursor: *usize,
) Error![]const program.HintBinding {
    if (range.start != cursor.*) return error.InvalidRange;
    const start: usize = range.start;
    const len: usize = range.len;
    const end = std.math.add(usize, start, len) catch
        return error.InvalidRange;
    if (end > values.len) return error.InvalidRange;
    cursor.* = end;
    return values[start..end];
}

fn hintBindingLess(lhs: program.HintBinding, rhs: program.HintBinding) bool {
    if (lhs.output_index != rhs.output_index)
        return lhs.output_index < rhs.output_index;
    const lhs_tag = hintBindingTargetTag(lhs.target);
    const rhs_tag = hintBindingTargetTag(rhs.target);
    if (lhs_tag != rhs_tag) return lhs_tag < rhs_tag;
    return hintBindingTargetIndex(lhs.target) < hintBindingTargetIndex(rhs.target);
}

fn hintBindingTargetTag(target: program.HintBindingTarget) u8 {
    return switch (target) {
        .constraint => 0,
        .effect => 1,
    };
}

fn hintBindingTargetIndex(target: program.HintBindingTarget) usize {
    return switch (target) {
        .constraint => |id| types.idIndex(id),
        .effect => |id| types.idIndex(id),
    };
}

fn priorNode(
    arena: *const ir.Arena,
    id: types.ValueId,
    current_index: usize,
) Error!expr.Node {
    const index = types.idIndex(id);
    if (index >= arena.nodesView().len) return error.InvalidNodeReference;
    if (index >= current_index) return error.InvalidNodeOrder;
    return arena.nodesView()[index];
}

fn validName(arena: *const ir.Arena, id: types.NameId) bool {
    return types.idIndex(id) < arena.names.items.len;
}

fn validValue(arena: *const ir.Arena, id: types.ValueId) bool {
    return types.idIndex(id) < arena.nodesView().len;
}

fn validateSpan(arena: *const ir.Arena, span: @import("source.zig").SourceSpan) !void {
    try arena.validateSpan(span);
}

fn isFelt(ty: types.Type) bool {
    return switch (ty) {
        .felt => true,
        else => false,
    };
}
