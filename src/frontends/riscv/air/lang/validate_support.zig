//! Dependency-light call, range, and node-reference validation helpers.

const std = @import("std");
const expr = @import("expr.zig");
const functions = @import("functions.zig");
const ir = @import("ir.zig");
const program = @import("program.zig");
const range_refinement = @import("range_refinement.zig");
const types = @import("types.zig");

pub fn validateCalls(arena: *const ir.Arena) !void {
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

pub fn canonicalRange(
    range: program.RefRange,
    values: []const types.ValueId,
    cursor: *usize,
) ![]const types.ValueId {
    if (range.start != cursor.*) return error.InvalidRange;
    const slice = range.slice(values) orelse return error.InvalidRange;
    cursor.* = std.math.add(usize, cursor.*, slice.len) catch
        return error.InvalidRange;
    return slice;
}

pub fn canonicalBindingRange(
    range: program.RefRange,
    values: []const program.HintBinding,
    cursor: *usize,
) ![]const program.HintBinding {
    if (range.start != cursor.*) return error.InvalidRange;
    const start: usize = range.start;
    const len: usize = range.len;
    const end = std.math.add(usize, start, len) catch
        return error.InvalidRange;
    if (end > values.len) return error.InvalidRange;
    cursor.* = end;
    return values[start..end];
}

pub fn hintBindingLess(lhs: program.HintBinding, rhs: program.HintBinding) bool {
    if (lhs.output_index != rhs.output_index)
        return lhs.output_index < rhs.output_index;
    const lhs_tag = hintBindingTargetTag(lhs.target);
    const rhs_tag = hintBindingTargetTag(rhs.target);
    if (lhs_tag != rhs_tag) return lhs_tag < rhs_tag;
    return hintBindingTargetIndex(lhs.target) < hintBindingTargetIndex(rhs.target);
}

pub fn hintBindingTargetTag(target: program.HintBindingTarget) u8 {
    return switch (target) {
        .constraint => 0,
        .effect => 1,
    };
}

pub fn hintBindingTargetIndex(target: program.HintBindingTarget) usize {
    return switch (target) {
        .constraint => |id| types.idIndex(id),
        .effect => |id| types.idIndex(id),
    };
}

pub fn priorNode(
    arena: *const ir.Arena,
    id: types.ValueId,
    current_index: usize,
) !expr.Node {
    const index = types.idIndex(id);
    if (index >= arena.nodesView().len) return error.InvalidNodeReference;
    if (index >= current_index) return error.InvalidNodeOrder;
    return arena.nodesView()[index];
}

pub fn validName(arena: *const ir.Arena, id: types.NameId) bool {
    return types.idIndex(id) < arena.names.items.len;
}

pub fn validValue(arena: *const ir.Arena, id: types.ValueId) bool {
    return types.idIndex(id) < arena.nodesView().len;
}

pub fn semanticAliasSource(
    arena: *const ir.Arena,
    value: types.ValueId,
) ?types.ValueId {
    return range_refinement.sourceForTarget(arena, value) orelse
        @import("conditional_access_plan.zig").sourceForTarget(arena, value);
}

pub fn isSemanticAliasTarget(arena: *const ir.Arena, value: types.ValueId) bool {
    return semanticAliasSource(arena, value) != null;
}

pub fn validateSpan(arena: *const ir.Arena, span: @import("source.zig").SourceSpan) !void {
    try arena.validateSpan(span);
}

pub fn isFelt(ty: types.Type) bool {
    return switch (ty) {
        .felt => true,
        else => false,
    };
}
