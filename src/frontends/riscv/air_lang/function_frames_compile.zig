//! Cold construction pass for compiler-owned function frames.
//!
//! The public frame ABI and its allocation-free validator stay in
//! `function_frames.zig`. This module owns only the allocation-heavy graph
//! walk that materializes that canonical representation.

const std = @import("std");
const digest = @import("digest.zig");
const functions = @import("functions.zig");
const hints = @import("hints.zig");
const ir = @import("ir.zig");
const types = @import("types.zig");
const validate_program = @import("validate.zig");

pub fn compile(
    comptime api: type,
    allocator: std.mem.Allocator,
    arena: *const ir.Arena,
) api.Error!api.OwnedPlan {
    const ActivationEvent = api.ActivationEvent;
    const CallBinding = api.CallBinding;
    const Frame = api.Frame;
    const FunctionRelationId = api.FunctionRelationId;
    const OwnedPlan = api.OwnedPlan;
    const Range = api.Range;
    const BODY_OWNERSHIP_VERSION = api.BODY_OWNERSHIP_VERSION;
    const FORMAT_VERSION = api.FORMAT_VERSION;
    const POLICY_VERSION = api.POLICY_VERSION;
    const containsValue = api.CompilerHooks.containsValue;
    const hashPlan = api.CompilerHooks.hashPlan;
    const idFromIndex = api.CompilerHooks.idFromIndex;
    const itemRangeEnd = api.CompilerHooks.itemRangeEnd;
    const mark = api.CompilerHooks.mark;
    const rejectDuplicateValues = api.CompilerHooks.rejectDuplicateValues;
    const relationDigest = api.CompilerHooks.relationDigest;
    const requireFieldScalar = api.CompilerHooks.requireFieldScalar;
    const validateActivationAbi = api.CompilerHooks.validateActivationAbi;

    try validate_program.validate(arena);
    const semantic_identity = try digest.computeIdentity(arena);

    var frames: std.ArrayList(Frame) = .empty;
    defer frames.deinit(allocator);
    var frame_values: std.ArrayList(types.ValueId) = .empty;
    defer frame_values.deinit(allocator);
    var constraint_ids: std.ArrayList(types.ConstraintId) = .empty;
    defer constraint_ids.deinit(allocator);
    var effect_ids: std.ArrayList(types.EffectId) = .empty;
    defer effect_ids.deinit(allocator);
    var hint_ids: std.ArrayList(types.HintId) = .empty;
    defer hint_ids.deinit(allocator);
    var body_call_ids: std.ArrayList(types.CallId) = .empty;
    defer body_call_ids.deinit(allocator);
    var call_bindings: std.ArrayList(CallBinding) = .empty;
    defer call_bindings.deinit(allocator);
    var tuple_values: std.ArrayList(types.ValueId) = .empty;
    defer tuple_values.deinit(allocator);
    var events: std.ArrayList(ActivationEvent) = .empty;
    defer events.deinit(allocator);

    const function_count = functions.view(arena).len;
    const node_count = arena.nodesView().len;
    const hint_count = hints.view(arena).len;
    var has_owned_body = false;
    for (functions.view(arena)) |function| {
        if (function.body != null) {
            has_owned_body = true;
            break;
        }
    }

    const reachable = try allocator.alloc(bool, node_count);
    defer allocator.free(reachable);
    const deterministic = try allocator.alloc(bool, function_count);
    defer allocator.free(deterministic);
    @memset(deterministic, true);
    const relation_required = try allocator.alloc(bool, function_count);
    defer allocator.free(relation_required);
    @memset(relation_required, false);
    const no_owner = std.math.maxInt(u32);
    const hint_owner = try allocator.alloc(u32, hint_count);
    defer allocator.free(hint_owner);
    @memset(hint_owner, no_owner);

    for (functions.calls(arena)) |call| {
        if (call.strategy == .relation_backed)
            relation_required[types.idIndex(call.callee)] = true;
    }

    for (functions.view(arena), 0..) |function, function_index| {
        @memset(reachable, false);
        const function_id = idFromIndex(types.FunctionId, function_index);
        const declared_inputs = functions.inputs(arena, function_id) orelse
            return error.InvalidFrame;
        const declared_outputs = functions.outputs(arena, function_id) orelse
            return error.InvalidFrame;
        try rejectDuplicateValues(declared_inputs);

        for (declared_outputs) |value| try mark(reachable, value);
        for (functions.calls(arena), 0..) |call, call_index| {
            if (call.caller == null or call.caller.? != function_id) continue;
            const call_id = idFromIndex(types.CallId, call_index);
            for (functions.callArguments(arena, call_id) orelse
                return error.InvalidCallBinding) |value| try mark(reachable, value);
            for (functions.callOutputs(arena, call_id) orelse
                return error.InvalidCallBinding) |value| try mark(reachable, value);
        }

        const constraint_start = constraint_ids.items.len;
        const effect_start = effect_ids.items.len;
        const hint_start = hint_ids.items.len;
        const body_call_start = body_call_ids.items.len;
        if (function.body) |body| {
            for (@as(usize, body.constraints.start)..itemRangeEnd(body.constraints)) |record_index| {
                const constraint_id = idFromIndex(types.ConstraintId, record_index);
                const constraint = arena.constraintsView()[record_index];
                try constraint_ids.append(allocator, constraint_id);
                try mark(reachable, constraint.root);
                if (constraint.gate) |gate| try mark(reachable, gate);
            }
            for (@as(usize, body.effects.start)..itemRangeEnd(body.effects)) |record_index| {
                const effect_id = idFromIndex(types.EffectId, record_index);
                const effect = arena.effectsView()[record_index];
                try effect_ids.append(allocator, effect_id);
                for (arena.effectValues(effect_id) orelse
                    return error.InvalidFrame) |value| try mark(reachable, value);
                if (effect.liveness) |liveness| try mark(reachable, liveness);
            }
            for (@as(usize, body.hints.start)..itemRangeEnd(body.hints)) |record_index| {
                const hint_id = idFromIndex(types.HintId, record_index);
                const invocation = hints.view(arena)[record_index];
                try hint_ids.append(allocator, hint_id);
                for (hints.inputs(arena, hint_id) orelse
                    return error.InvalidFrame) |value| try mark(reachable, value);
                for (hints.outputs(arena, hint_id) orelse
                    return error.InvalidFrame) |value| try mark(reachable, value);
                if (invocation.activation) |activation| try mark(reachable, activation);
            }
            for (@as(usize, body.calls.start)..itemRangeEnd(body.calls)) |record_index| {
                try body_call_ids.append(
                    allocator,
                    idFromIndex(types.CallId, record_index),
                );
            }
        }

        var is_deterministic = true;
        var reverse = node_count;
        while (reverse > 0) {
            reverse -= 1;
            if (!reachable[reverse]) continue;
            const node = arena.nodesView()[reverse];
            switch (node.key.op) {
                .constant => {},
                .input => if (!containsValue(declared_inputs, @enumFromInt(reverse)))
                    return error.FrameReadsUndeclaredInput,
                .add, .sub, .mul => |binary| {
                    try mark(reachable, binary.lhs);
                    try mark(reachable, binary.rhs);
                },
                .neg => |value| try mark(reachable, value),
                .select => |selection| {
                    try mark(reachable, selection.selector);
                    try mark(reachable, selection.when_true);
                    try mark(reachable, selection.when_false);
                },
                .hint_output => |output| {
                    const hint_index = types.idIndex(output.hint);
                    if (hint_index >= hint_owner.len) return error.InvalidFrame;
                    if (hint_owner[hint_index] != no_owner and
                        hint_owner[hint_index] != function_index)
                    {
                        return error.CrossFrameHint;
                    }
                    hint_owner[hint_index] = @intCast(function_index);
                    const invocation = hints.get(arena, output.hint) orelse
                        return error.InvalidFrame;
                    for (hints.inputs(arena, output.hint) orelse
                        return error.InvalidFrame) |value| try mark(reachable, value);
                    if (invocation.activation) |activation|
                        try mark(reachable, activation);
                    is_deterministic = false;
                },
                .call_output => |output| {
                    const call = functions.getCall(arena, output.call) orelse
                        return error.InvalidCallBinding;
                    if (call.caller == null or call.caller.? != function_id)
                        return error.FrameReadsUndeclaredInput;
                    const callee_index = types.idIndex(call.callee);
                    if (callee_index >= function_index)
                        return error.InvalidCallBinding;
                    if (!deterministic[callee_index]) is_deterministic = false;
                    for (functions.callArguments(arena, output.call) orelse
                        return error.InvalidCallBinding) |value| try mark(reachable, value);
                },
                .machine_derived => |derived| switch (derived) {
                    .register_address => |address| try mark(reachable, address.index),
                    .aligned_word_address => |address| try mark(reachable, address.word_index),
                    .access_clock => |clock| try mark(reachable, clock.instruction_clock),
                    .strict_clock_gap => |gap| {
                        try mark(reachable, gap.current_clock);
                        try mark(reachable, gap.previous_clock);
                        try mark(reachable, gap.active);
                    },
                    .instruction_next_pc => |next| try mark(reachable, next.current),
                    .instruction_next_clock => |next| try mark(reachable, next.current),
                },
            }
        }
        deterministic[function_index] = is_deterministic;

        const write_start = frame_values.items.len;
        for (arena.nodesView(), 0..) |node, node_index| {
            if (!reachable[node_index]) continue;
            switch (node.key.op) {
                .constant, .input => {},
                else => try frame_values.append(
                    allocator,
                    @enumFromInt(node_index),
                ),
            }
        }
        const write_range = try Range.init(
            write_start,
            frame_values.items.len - write_start,
        );

        const tuple_start = tuple_values.items.len;
        try tuple_values.appendSlice(allocator, declared_inputs);
        try tuple_values.appendSlice(allocator, declared_outputs);
        const activation_tuple = try Range.init(
            tuple_start,
            tuple_values.items.len - tuple_start,
        );
        const body_constraints = try Range.init(
            constraint_start,
            constraint_ids.items.len - constraint_start,
        );
        const body_effects = try Range.init(
            effect_start,
            effect_ids.items.len - effect_start,
        );
        const body_hints = try Range.init(
            hint_start,
            hint_ids.items.len - hint_start,
        );
        const body_calls = try Range.init(
            body_call_start,
            body_call_ids.items.len - body_call_start,
        );
        const argument_count = std.math.cast(u32, declared_inputs.len) orelse
            return error.CountOverflow;
        const return_count = std.math.cast(u32, declared_outputs.len) orelse
            return error.CountOverflow;
        const relation_id: FunctionRelationId = @enumFromInt(function_index);
        try frames.append(allocator, .{
            .function = function_id,
            .relation = relation_id,
            .argument_count = argument_count,
            .return_count = return_count,
            .writes = write_range,
            .activation_tuple = activation_tuple,
            .body_constraints = body_constraints,
            .body_effects = body_effects,
            .body_hints = body_hints,
            .body_calls = body_calls,
            .deterministic = is_deterministic,
            .relation_required = relation_required[function_index],
            .relation_digest = relationDigest(
                arena,
                semantic_identity,
                function_id,
            ),
        });
    }

    for (functions.calls(arena), 0..) |call, call_index| {
        const call_id = idFromIndex(types.CallId, call_index);
        const arguments = functions.callArguments(arena, call_id) orelse
            return error.InvalidCallBinding;
        const outputs = functions.callOutputs(arena, call_id) orelse
            return error.InvalidCallBinding;
        const tuple_start = tuple_values.items.len;
        try tuple_values.appendSlice(allocator, arguments);
        try tuple_values.appendSlice(allocator, outputs);
        const tuple_range = try Range.init(
            tuple_start,
            tuple_values.items.len - tuple_start,
        );
        const binding = CallBinding{
            .call = call_id,
            .caller = call.caller,
            .callee = call.callee,
            .strategy = call.strategy,
            .argument_count = std.math.cast(u32, arguments.len) orelse
                return error.CountOverflow,
            .return_count = std.math.cast(u32, outputs.len) orelse
                return error.CountOverflow,
            .tuple = tuple_range,
        };
        if (call.strategy == .relation_backed) {
            try validateActivationAbi(arena, &frames.items[types.idIndex(call.callee)]);
            for (arguments) |value| try requireFieldScalar(arena, value);
            for (outputs) |value| try requireFieldScalar(arena, value);
        }
        try call_bindings.append(allocator, binding);
    }

    for (frames.items) |item| {
        if (!item.relation_required) continue;
        try validateActivationAbi(arena, &item);
        try events.append(allocator, .{
            .kind = .callee_consume,
            .role = .consume,
            .weight = .callee_enabler,
            .relation = item.relation,
            .callee = item.function,
            .owner = item.function,
            .call = null,
            .tuple = item.activation_tuple,
        });
    }
    for (call_bindings.items) |item| {
        if (item.strategy != .relation_backed) continue;
        const target = frames.items[types.idIndex(item.callee)];
        try events.append(allocator, if (item.caller) |caller| .{
            .kind = .caller_emit,
            .role = .emit,
            .weight = .caller_enabler,
            .relation = target.relation,
            .callee = item.callee,
            .owner = caller,
            .call = item.call,
            .tuple = item.tuple,
        } else .{
            .kind = .public_emit,
            .role = .emit,
            .weight = .public_multiplicity,
            .relation = target.relation,
            .callee = item.callee,
            .owner = null,
            .call = item.call,
            .tuple = item.tuple,
        });
    }

    const owned_frames = try frames.toOwnedSlice(allocator);
    errdefer allocator.free(owned_frames);
    const owned_frame_values = try frame_values.toOwnedSlice(allocator);
    errdefer allocator.free(owned_frame_values);
    const owned_constraint_ids = try constraint_ids.toOwnedSlice(allocator);
    errdefer allocator.free(owned_constraint_ids);
    const owned_effect_ids = try effect_ids.toOwnedSlice(allocator);
    errdefer allocator.free(owned_effect_ids);
    const owned_hint_ids = try hint_ids.toOwnedSlice(allocator);
    errdefer allocator.free(owned_hint_ids);
    const owned_body_call_ids = try body_call_ids.toOwnedSlice(allocator);
    errdefer allocator.free(owned_body_call_ids);
    const owned_calls = try call_bindings.toOwnedSlice(allocator);
    errdefer allocator.free(owned_calls);
    const owned_tuple_values = try tuple_values.toOwnedSlice(allocator);
    errdefer allocator.free(owned_tuple_values);
    const owned_events = try events.toOwnedSlice(allocator);
    errdefer allocator.free(owned_events);

    var result = OwnedPlan{
        .allocator = allocator,
        .format_version = FORMAT_VERSION,
        .policy_version = POLICY_VERSION,
        .body_ownership_version = if (has_owned_body) BODY_OWNERSHIP_VERSION else 0,
        .semantic_identity_format_version = semantic_identity.format_version,
        .semantic_digest = semantic_identity.bytes,
        .frames = owned_frames,
        .frame_values = owned_frame_values,
        .constraint_ids = owned_constraint_ids,
        .effect_ids = owned_effect_ids,
        .hint_ids = owned_hint_ids,
        .call_ids = owned_body_call_ids,
        .calls = owned_calls,
        .tuple_values = owned_tuple_values,
        .events = owned_events,
        .plan_digest = .{0} ** 32,
    };
    result.plan_digest = hashPlan(&result);
    try result.validate();
    return result;
}
