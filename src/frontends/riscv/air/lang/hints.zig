//! Typed hint construction and explicit proof-binding metadata.
//!
//! A recipe creates untrusted output nodes. The author then binds every output
//! to at least one constraint root or ordered effect through an explicit,
//! allocation-free-verifiable value path. Binding gates/liveness must exactly
//! match the hint activation.

const std = @import("std");
const expr = @import("expr.zig");
const hint_recipe = @import("hint_recipe.zig");
const ir = @import("ir.zig");
const program = @import("program.zig");
const source = @import("source.zig");
const types = @import("types.zig");

pub const BindingSpec = struct {
    output_index: u16,
    target: program.HintBindingTarget,
    path: []const types.ValueId,
};

pub const HintError = error{
    HintAlreadyBound,
    InvalidHintActivation,
    InvalidHintBindingOutput,
    InvalidHintBindingPath,
    InvalidHintBindingTarget,
    NonCanonicalHintBindingOrder,
    UnknownHint,
};

pub const Error = ir.Error || hint_recipe.InvocationError || HintError;

pub fn get(arena: *const ir.Arena, id: types.HintId) ?program.Hint {
    const index = types.idIndex(id);
    if (index >= arena.hints.items.len) return null;
    return arena.hints.items[index];
}

/// Borrowed until the next hint insertion or arena deinitialization.
pub fn view(arena: *const ir.Arena) []const program.Hint {
    return arena.hints.items;
}

pub fn inputs(
    arena: *const ir.Arena,
    id: types.HintId,
) ?[]const types.ValueId {
    const item = get(arena, id) orelse return null;
    return item.inputs.slice(arena.hint_inputs.items);
}

pub fn outputs(
    arena: *const ir.Arena,
    id: types.HintId,
) ?[]const types.ValueId {
    const item = get(arena, id) orelse return null;
    return item.outputs.slice(arena.hint_outputs.items);
}

pub fn bindings(
    arena: *const ir.Arena,
    id: types.HintId,
) ?[]const program.HintBinding {
    const item = get(arena, id) orelse return null;
    const range = item.bindings orelse return null;
    return bindingSlice(range, arena.hint_bindings.items);
}

pub fn bindingPath(
    arena: *const ir.Arena,
    binding: program.HintBinding,
) ?[]const types.ValueId {
    return binding.path.slice(arena.hint_binding_values.items);
}

/// Creates typed, untrusted outputs for one closed-registry recipe.
pub fn add(
    arena: *ir.Arena,
    kind: hint_recipe.Kind,
    input_values: []const types.ValueId,
    activation: ?types.ValueId,
    span: source.SourceSpan,
) Error!types.HintId {
    const recipe = hint_recipe.get(kind);
    try arena.validateSpan(span);
    if (input_values.len != recipe.input_types.len)
        return error.InvalidHintInputArity;
    for (input_values, recipe.input_types) |input_id, expected_type| {
        const input_node = arena.node(input_id) orelse return error.UnknownValue;
        if (!std.meta.eql(input_node.key.ty, expected_type))
            return error.InvalidHintInputType;
    }
    if (activation) |activation_id| {
        const activation_node = arena.node(activation_id) orelse
            return error.UnknownValue;
        if (!activation_node.key.ty.isSelector())
            return error.InvalidHintActivation;
    }
    const hint_id = try types.idFromIndex(types.HintId, arena.hints.items.len);
    const input_range = try program.RefRange.init(
        arena.hint_inputs.items.len,
        input_values.len,
    );
    const output_range = try program.RefRange.init(
        arena.hint_outputs.items.len,
        recipe.output_types.len,
    );

    const input_start = arena.hint_inputs.items.len;
    errdefer arena.hint_inputs.shrinkRetainingCapacity(input_start);
    try arena.hint_inputs.appendSlice(arena.allocator, input_values);

    const output_start = arena.hint_outputs.items.len;
    errdefer arena.hint_outputs.shrinkRetainingCapacity(output_start);
    const node_checkpoint = arena.nodeCheckpoint();
    errdefer arena.rollbackToNodeCheckpoint(node_checkpoint);
    for (recipe.output_types, 0..) |ty, output_index| {
        const output = try arena.internHintOutput(
            hint_id,
            @intCast(output_index),
            ty,
            span,
        );
        try arena.hint_outputs.append(arena.allocator, output);
    }

    try arena.hints.append(arena.allocator, .{
        .recipe = recipe.id,
        .inputs = input_range,
        .outputs = output_range,
        .activation = activation,
        .bindings = null,
        .source_span = span,
    });
    return hint_id;
}

/// Seals one hint's canonical binding list. Hints are sealed in declaration
/// order; bindings are ordered by output, then target kind, then target ID.
pub fn bind(
    arena: *ir.Arena,
    hint_id: types.HintId,
    specs: []const BindingSpec,
) Error!void {
    const hint_index = types.idIndex(hint_id);
    if (hint_index >= arena.hints.items.len) return error.UnknownHint;
    const hint = arena.hints.items[hint_index];
    if (hint.bindings != null) return error.HintAlreadyBound;
    for (arena.hints.items[0..hint_index]) |prior| {
        if (prior.bindings == null) return error.NonCanonicalHintBindingOrder;
    }
    if (specs.len == 0) return error.InvalidHintBindingOutput;

    const hint_outputs = outputs(arena, hint_id).?;
    for (specs, 0..) |spec, spec_index| {
        if (spec.output_index >= hint_outputs.len)
            return error.InvalidHintBindingOutput;
        if (spec_index != 0 and !bindingKeyLess(specs[spec_index - 1], spec))
            return error.NonCanonicalHintBindingOrder;
        try validateBindingSpec(arena, hint, hint_outputs, spec);
    }
    for (hint_outputs, 0..) |_, output_index| {
        var found = false;
        for (specs) |spec| {
            if (spec.output_index == output_index) {
                found = true;
                break;
            }
        }
        if (!found) return error.InvalidHintBindingOutput;
    }

    const binding_range = try program.RefRange.init(
        arena.hint_bindings.items.len,
        specs.len,
    );
    const binding_start = arena.hint_bindings.items.len;
    errdefer arena.hint_bindings.shrinkRetainingCapacity(binding_start);
    const path_start = arena.hint_binding_values.items.len;
    errdefer arena.hint_binding_values.shrinkRetainingCapacity(path_start);

    for (specs) |spec| {
        const path_range = try program.RefRange.init(
            arena.hint_binding_values.items.len,
            spec.path.len,
        );
        try arena.hint_binding_values.appendSlice(arena.allocator, spec.path);
        try arena.hint_bindings.append(arena.allocator, .{
            .output_index = spec.output_index,
            .target = spec.target,
            .path = path_range,
        });
    }
    arena.hints.items[hint_index].bindings = binding_range;
}

pub fn targetMatchesActivation(
    arena: *const ir.Arena,
    activation: ?types.ValueId,
    target: program.HintBindingTarget,
) bool {
    return switch (target) {
        .constraint => |constraint_id| blk: {
            const constraint = arena.constraint(constraint_id) orelse break :blk false;
            break :blk constraint.category == .hint_binding and
                constraint.gate == activation;
        },
        .effect => |effect_id| blk: {
            const effect = arena.effect(effect_id) orelse break :blk false;
            break :blk effect.liveness == activation;
        },
    };
}

pub fn pathIsValid(
    arena: *const ir.Arena,
    output: types.ValueId,
    target: program.HintBindingTarget,
    path: []const types.ValueId,
) bool {
    if (path.len == 0 or path[0] != output) return false;
    for (path[1..], path[0 .. path.len - 1]) |current, dependency| {
        const node = arena.node(current) orelse return false;
        if (!directlyUses(node.key.op, dependency)) return false;
    }
    const endpoint = path[path.len - 1];
    return switch (target) {
        .constraint => |constraint_id| blk: {
            const constraint = arena.constraint(constraint_id) orelse break :blk false;
            break :blk constraint.root == endpoint;
        },
        .effect => |effect_id| blk: {
            const values = arena.effectValues(effect_id) orelse break :blk false;
            break :blk std.mem.indexOfScalar(types.ValueId, values, endpoint) != null;
        },
    };
}

fn validateBindingSpec(
    arena: *const ir.Arena,
    hint: program.Hint,
    hint_outputs: []const types.ValueId,
    spec: BindingSpec,
) Error!void {
    if (!targetMatchesActivation(arena, hint.activation, spec.target))
        return error.InvalidHintBindingTarget;
    const output_index: usize = spec.output_index;
    if (!pathIsValid(
        arena,
        hint_outputs[output_index],
        spec.target,
        spec.path,
    )) return error.InvalidHintBindingPath;
}

fn directlyUses(op: expr.Op, dependency: types.ValueId) bool {
    return switch (op) {
        .add, .sub, .mul => |binary| binary.lhs == dependency or
            binary.rhs == dependency,
        .neg => |value| value == dependency,
        .select => |selection| selection.selector == dependency or
            selection.when_true == dependency or
            selection.when_false == dependency,
        .constant, .input, .hint_output, .call_output => false,
    };
}

fn bindingKeyLess(lhs: BindingSpec, rhs: BindingSpec) bool {
    if (lhs.output_index != rhs.output_index)
        return lhs.output_index < rhs.output_index;
    const lhs_tag = targetTag(lhs.target);
    const rhs_tag = targetTag(rhs.target);
    if (lhs_tag != rhs_tag) return lhs_tag < rhs_tag;
    return targetIndex(lhs.target) < targetIndex(rhs.target);
}

fn targetTag(target: program.HintBindingTarget) u8 {
    return switch (target) {
        .constraint => 0,
        .effect => 1,
    };
}

fn targetIndex(target: program.HintBindingTarget) usize {
    return switch (target) {
        .constraint => |id| types.idIndex(id),
        .effect => |id| types.idIndex(id),
    };
}

fn bindingSlice(
    range: program.RefRange,
    items: []const program.HintBinding,
) ?[]const program.HintBinding {
    const start: usize = range.start;
    const len: usize = range.len;
    const end = std.math.add(usize, start, len) catch return null;
    if (end > items.len) return null;
    return items[start..end];
}
