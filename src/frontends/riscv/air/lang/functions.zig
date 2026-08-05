//! Static function declarations and call construction.
//!
//! Functions are declared in dependency-topological order. A caller is opened,
//! may call only already-complete callees, and is then finished with its output
//! values. This construction rule makes recursive cycles unrepresentable while
//! retaining explicit call records for inline or relation-backed lowering.

const std = @import("std");
const ir = @import("ir.zig");
const program = @import("program.zig");
const source = @import("source.zig");
const types = @import("types.zig");

pub const FunctionError = error{
    ArgumentTypeMismatch,
    CallArityMismatch,
    DuplicateFunctionName,
    FunctionAlreadyOpen,
    FunctionNotComplete,
    FunctionNotOpen,
    InvalidFunctionInput,
    NonTopologicalCall,
    TooManyCallOutputs,
    UnknownFunction,
};

pub const Error = ir.Error || FunctionError;

pub fn get(arena: *const ir.Arena, id: types.FunctionId) ?program.Function {
    const index = types.idIndex(id);
    if (index >= arena.functions.items.len) return null;
    return arena.functions.items[index];
}

/// Borrowed until the next function insertion or arena deinitialization.
pub fn view(arena: *const ir.Arena) []const program.Function {
    return arena.functions.items;
}

pub fn inputs(
    arena: *const ir.Arena,
    id: types.FunctionId,
) ?[]const types.ValueId {
    const item = get(arena, id) orelse return null;
    return item.inputs.slice(arena.function_inputs.items);
}

pub fn outputs(
    arena: *const ir.Arena,
    id: types.FunctionId,
) ?[]const types.ValueId {
    const item = get(arena, id) orelse return null;
    return item.outputs.slice(arena.function_outputs.items);
}

pub fn getCall(arena: *const ir.Arena, id: types.CallId) ?program.Call {
    const index = types.idIndex(id);
    if (index >= arena.calls.items.len) return null;
    return arena.calls.items[index];
}

/// Borrowed until the next call insertion or arena deinitialization.
pub fn calls(arena: *const ir.Arena) []const program.Call {
    return arena.calls.items;
}

pub fn callArguments(
    arena: *const ir.Arena,
    id: types.CallId,
) ?[]const types.ValueId {
    const item = getCall(arena, id) orelse return null;
    return item.arguments.slice(arena.call_arguments.items);
}

pub fn callOutputs(
    arena: *const ir.Arena,
    id: types.CallId,
) ?[]const types.ValueId {
    const item = getCall(arena, id) orelse return null;
    return item.outputs.slice(arena.call_outputs.items);
}

pub fn add(
    arena: *ir.Arena,
    stable_name: []const u8,
    input_values: []const types.ValueId,
    output_values: []const types.ValueId,
    span: source.SourceSpan,
) Error!types.FunctionId {
    const id = try begin(arena, stable_name, input_values, span);
    errdefer abortFreshDeclaration(arena, id);
    try finish(arena, id, output_values);
    return id;
}

pub fn begin(
    arena: *ir.Arena,
    stable_name: []const u8,
    input_values: []const types.ValueId,
    span: source.SourceSpan,
) Error!types.FunctionId {
    if (arena.open_function != null) return error.FunctionAlreadyOpen;
    try arena.validateSpan(span);
    for (input_values) |input_id| {
        const input_node = arena.node(input_id) orelse return error.UnknownValue;
        switch (input_node.key.op) {
            .input => {},
            else => return error.InvalidFunctionInput,
        }
    }

    const name_id = try arena.internName(stable_name);
    for (arena.functions.items) |existing| {
        if (existing.name == name_id) return error.DuplicateFunctionName;
    }

    const id = try types.idFromIndex(types.FunctionId, arena.functions.items.len);
    const input_range = try program.RefRange.init(
        arena.function_inputs.items.len,
        input_values.len,
    );
    const output_range = try program.RefRange.init(
        arena.function_outputs.items.len,
        0,
    );
    const input_start = arena.function_inputs.items.len;
    errdefer arena.function_inputs.shrinkRetainingCapacity(input_start);
    try arena.function_inputs.appendSlice(arena.allocator, input_values);
    try arena.functions.append(arena.allocator, .{
        .name = name_id,
        .inputs = input_range,
        .outputs = output_range,
        .source_span = span,
        .complete = false,
    });
    arena.open_function = id;
    return id;
}

pub fn finish(
    arena: *ir.Arena,
    id: types.FunctionId,
    output_values: []const types.ValueId,
) Error!void {
    if (arena.open_function == null or arena.open_function.? != id)
        return error.FunctionNotOpen;
    const index = types.idIndex(id);
    if (index >= arena.functions.items.len) return error.UnknownFunction;
    for (output_values) |output_id| {
        if (arena.node(output_id) == null) return error.UnknownValue;
    }

    const output_range = try program.RefRange.init(
        arena.function_outputs.items.len,
        output_values.len,
    );
    const output_start = arena.function_outputs.items.len;
    errdefer arena.function_outputs.shrinkRetainingCapacity(output_start);
    try arena.function_outputs.appendSlice(arena.allocator, output_values);
    arena.functions.items[index].outputs = output_range;
    arena.functions.items[index].complete = true;
    arena.open_function = null;
}

/// Creates a call owned by the currently open function, or a root call when no
/// function is open. Internal calls may target only earlier complete functions.
pub fn call(
    arena: *ir.Arena,
    callee: types.FunctionId,
    arguments: []const types.ValueId,
    strategy: program.CallStrategy,
    span: source.SourceSpan,
) Error!types.CallId {
    try arena.validateSpan(span);
    const callee_item = get(arena, callee) orelse return error.UnknownFunction;
    const caller = arena.open_function;
    if (caller) |caller_id| {
        if (types.idIndex(callee) >= types.idIndex(caller_id))
            return error.NonTopologicalCall;
    }
    if (!callee_item.complete) return error.FunctionNotComplete;

    const expected_inputs = inputs(arena, callee).?;
    if (arguments.len != expected_inputs.len) return error.CallArityMismatch;
    for (arguments, expected_inputs) |actual_id, expected_id| {
        const actual = arena.node(actual_id) orelse return error.UnknownValue;
        const expected = arena.node(expected_id) orelse return error.UnknownValue;
        if (!std.meta.eql(actual.key.ty, expected.key.ty))
            return error.ArgumentTypeMismatch;
    }
    const callee_outputs = outputs(arena, callee).?;
    if (callee_outputs.len > @as(usize, std.math.maxInt(u16)) + 1)
        return error.TooManyCallOutputs;

    const call_id = try types.idFromIndex(types.CallId, arena.calls.items.len);
    const argument_range = try program.RefRange.init(
        arena.call_arguments.items.len,
        arguments.len,
    );
    const output_range = try program.RefRange.init(
        arena.call_outputs.items.len,
        callee_outputs.len,
    );
    const argument_start = arena.call_arguments.items.len;
    errdefer arena.call_arguments.shrinkRetainingCapacity(argument_start);
    try arena.call_arguments.appendSlice(arena.allocator, arguments);

    const output_start = arena.call_outputs.items.len;
    errdefer arena.call_outputs.shrinkRetainingCapacity(output_start);
    const node_checkpoint = arena.nodeCheckpoint();
    errdefer arena.rollbackToNodeCheckpoint(node_checkpoint);
    for (callee_outputs, 0..) |callee_output, output_index| {
        const output_type = arena.node(callee_output).?.key.ty;
        const output = try arena.internCallOutput(
            call_id,
            @intCast(output_index),
            output_type,
            span,
        );
        try arena.call_outputs.append(arena.allocator, output);
    }

    try arena.calls.append(arena.allocator, .{
        .caller = caller,
        .callee = callee,
        .strategy = strategy,
        .arguments = argument_range,
        .outputs = output_range,
        .source_span = span,
    });
    return call_id;
}

fn abortFreshDeclaration(arena: *ir.Arena, id: types.FunctionId) void {
    std.debug.assert(arena.open_function == id);
    std.debug.assert(types.idIndex(id) + 1 == arena.functions.items.len);
    const item = arena.functions.pop().?;
    std.debug.assert(!item.complete);
    arena.function_inputs.shrinkRetainingCapacity(item.inputs.start);
    arena.open_function = null;
}
