//! Base-plus-call relation schedule for the U256 swap candidate.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const base_challenges = @import("../relation_challenges.zig");
const base_relation = @import("../lang/relation.zig");
const types = @import("../lang/types.zig");
const caller = @import("stack_swap_caller_candidate_v1.zig");
const words = @import("stack_swap_word_candidate_v1.zig");

pub const production_active = false;
pub const call_schema_numeric_id: u16 = base_relation.BASE_RELATION_COUNT;
pub const relation_count: usize = base_relation.BASE_RELATION_COUNT + 1;
pub const call_arity: usize = 5;
pub const CallTuple = [call_arity]M31;

pub fn CallTupleFor(comptime S: type) type {
    return [call_arity]S;
}

pub const Schema = struct {
    id: types.RelationSchemaId,
    version: u16,
    name: []const u8,
    fields: []const base_relation.FieldSpec,
    request_is_unit: bool,
    supply_is_weighted: bool,
};

const call_fields = [_]base_relation.FieldSpec{.{ .exact = .felt }} ** call_arity;

pub const call_schema = Schema{
    .id = @enumFromInt(call_schema_numeric_id),
    .version = 1,
    .name = "stwo.riscv.guest-u256-swap-call.v1",
    .fields = &call_fields,
    .request_is_unit = true,
    .supply_is_weighted = false,
};

pub const Relations = struct {
    base: base_challenges.Relations,
    call: base_challenges.RelationElements(call_arity),

    pub fn draw(allocator: std.mem.Allocator, channel: anytype) !Relations {
        const base = try base_challenges.Relations.draw(allocator, channel);
        const extension = try channel.drawSecureFelts(allocator, 2);
        defer allocator.free(extension);
        if (extension.len != 2) return error.InvalidChallengeDraw;
        return .{ .base = base, .call = .init(extension[0], extension[1]) };
    }

    pub fn dummy() Relations {
        return .{ .base = .dummy(), .call = .dummy() };
    }
};

pub fn InteractionScalar(comptime S: type) type {
    return if (S == M31) QM31 else S;
}

pub fn combine(
    comptime S: type,
    relation: anytype,
    tuple: anytype,
) InteractionScalar(S) {
    if (comptime S == M31) return relation.combineBase(tuple);
    if (comptime S == QM31) return relation.combineSecure(tuple);
    return relation.combine(tuple);
}

pub fn callerCallTuple(
    comptime S: type,
    main: *const [caller.main_column_count]S,
) CallTupleFor(S) {
    return .{
        main[caller.Layout.execution_clock],
        main[caller.Layout.call_index],
        main[caller.Layout.pc],
        main[caller.Layout.wordIndex(0)],
        main[caller.Layout.wordIndex(1)],
    };
}

pub fn wordCallTuple(
    comptime S: type,
    main: *const [words.main_column_count]S,
) CallTupleFor(S) {
    return .{
        main[words.Layout.execution_clock],
        main[words.Layout.call_index],
        main[words.Layout.pc],
        main[words.Layout.lhs_word_address],
        main[words.Layout.rhs_word_address],
    };
}

comptime {
    if (production_active or
        relation_count != 13 or
        call_schema_numeric_id != 12 or
        call_fields.len != call_arity)
    {
        @compileError("stack-swap relation identity drifted");
    }
}
