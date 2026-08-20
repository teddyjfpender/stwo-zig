//! Cold protocol authority for compiler-owned function activations.
//!
//! Construction, arena/plan admission, and canonical descriptor projection
//! live here; the stable wire representation and hot evaluator remain in
//! `function_activation_logup.zig`.

const std = @import("std");
const fields = @import("stwo_core").fields;
const QM31 = fields.qm31.QM31;
const frames = @import("function_frames.zig");
const functions = @import("functions.zig");
const ir = @import("ir.zig");
const types = @import("types.zig");

pub fn compileAndDraw(
    comptime api: type,
    allocator: std.mem.Allocator,
    arena: *const ir.Arena,
    plan: *const frames.OwnedPlan,
    channel: anytype,
) !api.OwnedProtocol {
    const EventDescriptor = api.EventDescriptor;
    const IndexRange = api.IndexRange;
    const OwnedProtocol = api.OwnedProtocol;
    const RelationDescriptor = api.RelationDescriptor;
    const FORMAT_VERSION = api.FORMAT_VERSION;
    const POLICY_VERSION = api.POLICY_VERSION;
    const hashProtocol = api.AuthorityHooks.hashProtocol;
    const rangeSliceMut = api.AuthorityHooks.rangeSliceMut;
    const validateChallengePair = api.AuthorityHooks.validateChallengePair;
    try plan.validate();
    if (plan.body_ownership_version == 0) return inactiveProtocol(api, allocator);
    try plan.validateAgainst(allocator, arena);
    const relation_count = requiredRelationCount(plan);
    if (relation_count == 0) return inactiveProtocol(api, allocator);
    try validateOwnedAuthority(api, arena, plan);

    var total_powers: usize = 0;
    for (plan.frames) |frame| {
        if (!frame.relation_required) continue;
        total_powers = std.math.add(
            usize,
            total_powers,
            @as(usize, frame.argument_count) + @as(usize, frame.return_count),
        ) catch return error.CountOverflow;
    }
    var total_tuple_values: usize = 0;
    for (plan.events) |event| {
        total_tuple_values = std.math.add(usize, total_tuple_values, event.tuple.len) catch
            return error.CountOverflow;
    }

    const relations = try allocator.alloc(RelationDescriptor, relation_count);
    errdefer allocator.free(relations);
    const alpha_powers = try allocator.alloc(QM31, total_powers);
    errdefer allocator.free(alpha_powers);
    const events = try allocator.alloc(EventDescriptor, plan.events.len);
    errdefer allocator.free(events);
    const tuple_values = try allocator.alloc(types.ValueId, total_tuple_values);
    errdefer allocator.free(tuple_values);

    var relation_cursor: usize = 0;
    var power_cursor: usize = 0;
    for (plan.frames) |frame| {
        if (!frame.relation_required) continue;
        const arity = std.math.add(
            usize,
            frame.argument_count,
            frame.return_count,
        ) catch return error.CountOverflow;
        relations[relation_cursor] = .{
            .function = frame.function,
            .relation = frame.relation,
            .tuple_arity = std.math.cast(u16, arity) orelse
                return error.CountOverflow,
            .alpha_powers = try IndexRange.init(power_cursor, arity),
            .relation_digest = frame.relation_digest,
            .z = undefined,
            .alpha = undefined,
        };
        relation_cursor += 1;
        power_cursor += arity;
    }

    var tuple_cursor: usize = 0;
    for (plan.events, 0..) |event, event_index| {
        const relation_index = compactRelationIndex(api, relations, event.relation) orelse
            return error.InvalidPlanBinding;
        const tuple = plan.tuple(event.tuple) orelse return error.InvalidPlanBinding;
        @memcpy(tuple_values[tuple_cursor..][0..tuple.len], tuple);
        events[event_index] = .{
            .kind = event.kind,
            .role = event.role,
            .weight = event.weight,
            .relation_index = @intCast(relation_index),
            .callee = event.callee,
            .owner = event.owner,
            .call = event.call,
            .tuple = try IndexRange.init(tuple_cursor, tuple.len),
        };
        tuple_cursor += tuple.len;
    }

    var staged_channel = channel.*;
    mixChallengePrefix(api, &staged_channel, plan, relations, events.len);
    const draw_count = std.math.mul(usize, relation_count, 2) catch
        return error.CountOverflow;
    const draws = try staged_channel.drawSecureFelts(allocator, draw_count);
    defer allocator.free(draws);
    if (draws.len != draw_count) return error.InvalidProtocolShape;
    for (relations, 0..) |*relation, index| {
        relation.z = draws[2 * index];
        relation.alpha = draws[2 * index + 1];
        try validateChallengePair(relation.z, relation.alpha);
        const powers = rangeSliceMut(QM31, relation.alpha_powers, alpha_powers).?;
        var power = QM31.one();
        for (powers) |*slot| {
            slot.* = power;
            power = power.mul(relation.alpha);
        }
    }

    var result = OwnedProtocol{
        .allocator = allocator,
        .active = true,
        .format_version = FORMAT_VERSION,
        .policy_version = POLICY_VERSION,
        .semantic_identity_format_version = plan.semantic_identity_format_version,
        .semantic_digest = plan.semantic_digest,
        .frame_plan_digest = plan.plan_digest,
        .relations = relations,
        .alpha_powers = alpha_powers,
        .events = events,
        .tuple_values = tuple_values,
        .protocol_digest = .{0} ** 32,
    };
    result.protocol_digest = hashProtocol(&result);
    try result.validate();
    channel.* = staged_channel;
    return result;
}

fn inactiveProtocol(
    comptime api: type,
    allocator: std.mem.Allocator,
) api.OwnedProtocol {
    const EventDescriptor = api.EventDescriptor;
    const RelationDescriptor = api.RelationDescriptor;
    const FORMAT_VERSION = api.FORMAT_VERSION;
    const POLICY_VERSION = api.POLICY_VERSION;
    return .{
        .allocator = allocator,
        .active = false,
        .format_version = FORMAT_VERSION,
        .policy_version = POLICY_VERSION,
        .semantic_identity_format_version = 0,
        .semantic_digest = .{0} ** 32,
        .frame_plan_digest = .{0} ** 32,
        .relations = emptyMutable(RelationDescriptor),
        .alpha_powers = emptyMutable(QM31),
        .events = emptyMutable(EventDescriptor),
        .tuple_values = emptyMutable(types.ValueId),
        .protocol_digest = .{0} ** 32,
    };
}

pub fn validateOwnedAuthority(
    comptime api: type,
    arena: *const ir.Arena,
    plan: *const frames.OwnedPlan,
) api.ValidationError!void {
    for (plan.frames) |frame| {
        if (!frame.relation_required) continue;
        const declaration = functions.get(arena, frame.function) orelse
            return error.InvalidPlanBinding;
        if (declaration.body == null) return error.UnownedActivation;
    }
    for (plan.events) |event| {
        if (event.owner) |owner| {
            const declaration = functions.get(arena, owner) orelse
                return error.InvalidPlanBinding;
            if (declaration.body == null) return error.UnownedActivation;
        }
        if (event.call) |call_id| {
            const call = functions.getCall(arena, call_id) orelse
                return error.InvalidPlanBinding;
            if (call.strategy != .relation_backed or call.callee != event.callee or
                call.caller != event.owner)
            {
                return error.InvalidPlanBinding;
            }
        }
    }
}

pub fn descriptorsMatchPlan(
    comptime api: type,
    protocol: *const api.OwnedProtocol,
    plan: *const frames.OwnedPlan,
) bool {
    const rangeSlice = api.AuthorityHooks.rangeSlice;
    if (protocol.relations.len != requiredRelationCount(plan) or
        protocol.events.len != plan.events.len)
    {
        return false;
    }
    var relation_cursor: usize = 0;
    for (plan.frames) |frame| {
        if (!frame.relation_required) continue;
        const actual = protocol.relations[relation_cursor];
        if (actual.function != frame.function or actual.relation != frame.relation or
            actual.tuple_arity != frame.argument_count + frame.return_count or
            !std.mem.eql(u8, &actual.relation_digest, &frame.relation_digest))
        {
            return false;
        }
        relation_cursor += 1;
    }
    for (plan.events, protocol.events) |expected, actual| {
        const relation_index = compactRelationIndex(
            api,
            protocol.relations,
            expected.relation,
        ) orelse return false;
        if (actual.kind != expected.kind or actual.role != expected.role or
            actual.weight != expected.weight or
            actual.relation_index != relation_index or
            actual.callee != expected.callee or actual.owner != expected.owner or
            actual.call != expected.call)
        {
            return false;
        }
        const expected_tuple = plan.tuple(expected.tuple) orelse return false;
        const actual_tuple = rangeSlice(
            types.ValueId,
            actual.tuple,
            protocol.tuple_values,
        ) orelse return false;
        if (!std.mem.eql(types.ValueId, expected_tuple, actual_tuple)) return false;
    }
    return true;
}

pub fn requiredRelationCount(plan: *const frames.OwnedPlan) usize {
    var count: usize = 0;
    for (plan.frames) |frame| if (frame.relation_required) {
        count += 1;
    };
    return count;
}

fn compactRelationIndex(
    comptime api: type,
    relations: []const api.RelationDescriptor,
    wanted: frames.FunctionRelationId,
) ?usize {
    const wanted_index = @intFromEnum(wanted);
    var low: usize = 0;
    var high = relations.len;
    while (low < high) {
        const middle = low + (high - low) / 2;
        const actual = @intFromEnum(relations[middle].relation);
        if (actual < wanted_index) {
            low = middle + 1;
        } else {
            high = middle;
        }
    }
    return if (low < relations.len and relations[low].relation == wanted)
        low
    else
        null;
}

fn mixChallengePrefix(
    comptime api: type,
    channel: anytype,
    plan: *const frames.OwnedPlan,
    relations: []const api.RelationDescriptor,
    event_count: usize,
) void {
    const FORMAT_VERSION = api.FORMAT_VERSION;
    const POLICY_VERSION = api.POLICY_VERSION;
    const SOURCE_COEFFICIENT_BOUND_EXCLUSIVE =
        api.SOURCE_COEFFICIENT_BOUND_EXCLUSIVE;
    const TRANSCRIPT_DOMAIN_TAG = api.TRANSCRIPT_DOMAIN_TAG;
    const degreeCertificateWord = api.AuthorityHooks.degreeCertificateWord;
    channel.mixU64(TRANSCRIPT_DOMAIN_TAG);
    channel.mixU64((@as(u64, FORMAT_VERSION) << 32) | POLICY_VERSION);
    channel.mixU64(degreeCertificateWord());
    channel.mixU64(SOURCE_COEFFICIENT_BOUND_EXCLUSIVE);
    mixDigest(channel, plan.semantic_digest);
    mixDigest(channel, plan.plan_digest);
    channel.mixU64(@intCast(relations.len));
    channel.mixU64(@intCast(event_count));
    for (relations) |relation| {
        channel.mixU64(@intFromEnum(relation.function));
        channel.mixU64(@intFromEnum(relation.relation));
        channel.mixU64(relation.tuple_arity);
        mixDigest(channel, relation.relation_digest);
    }
}

fn mixDigest(channel: anytype, digest: [32]u8) void {
    var words: [8]u32 = undefined;
    for (&words, 0..) |*word, index| {
        word.* = std.mem.readInt(u32, digest[4 * index ..][0..4], .little);
    }
    channel.mixU32s(&words);
}

fn emptyMutable(comptime T: type) []T {
    return @constCast((&[_]T{})[0..]);
}
