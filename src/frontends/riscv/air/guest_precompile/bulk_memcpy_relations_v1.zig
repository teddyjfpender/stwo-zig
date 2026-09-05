//! Base-plus-call relation schedule for the candidate bulk-memcpy profile.
//!
//! All twelve Stark-V base buses are drawn first and unchanged.  The sole
//! extension bus joins one caller row to the first word row of the same bulk
//! copy.  The tuple binds execution order, PC, both aligned spans, byte length,
//! word count, and first/last byte offsets.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const base_challenges = @import("../relation_challenges.zig");
const base_relation = @import("../lang/relation.zig");
const types = @import("../lang/types.zig");
const caller = @import("bulk_memcpy_caller_candidate_v1.zig");
const words = @import("bulk_memcpy_word_candidate_v1.zig");

pub const production_active = false;
pub const call_schema_numeric_id: u16 = base_relation.BASE_RELATION_COUNT;
pub const relation_count: usize = base_relation.BASE_RELATION_COUNT + 1;
pub const call_arity: usize = 9;
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

const call_fields = [_]base_relation.FieldSpec{
    .{ .exact = .felt },
} ** call_arity;

pub const call_schema = Schema{
    .id = @enumFromInt(call_schema_numeric_id),
    .version = 1,
    .name = "stwo.riscv.guest_bulk_memcpy_call_v1",
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
        return .{
            .base = base,
            .call = .init(extension[0], extension[1]),
        };
    }

    pub fn dummy() Relations {
        return .{ .base = .dummy(), .call = .dummy() };
    }
};

/// Native base rows interact in QM31; recursive recorders retain their own
/// scalar. This matches the generic base-AIR relation convention.
pub fn InteractionScalar(comptime S: type) type {
    return if (S == M31) QM31 else S;
}

pub fn liftInteraction(comptime S: type, value: S) InteractionScalar(S) {
    if (comptime S == M31) return QM31.fromBase(value);
    return value;
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
    const start = weighted4(S, main, caller.Layout.start_selectors, 0);
    const end = weighted4(S, main, caller.Layout.end_selectors, 1);
    return .{
        main[caller.Layout.execution_clock],
        main[caller.Layout.call_index],
        main[caller.Layout.pc],
        main[caller.Layout.source_word_index],
        main[caller.Layout.destination_word_index],
        composeBytes(S, main, 2),
        main[caller.Layout.expected_word_count],
        start,
        end,
    };
}

pub fn wordCallTuple(
    comptime S: type,
    main: *const [words.main_column_count]S,
) CallTupleFor(S) {
    const one = S.one();
    const start = weighted4(S, main, words.Layout.start_selectors, 0);
    const end = main[words.Layout.length]
        .add(start)
        .sub(main[words.Layout.expected_word_count].sub(one).mul(scalar(S, 4)));
    return .{
        main[words.Layout.execution_clock],
        main[words.Layout.call_index],
        main[words.Layout.pc],
        main[words.Layout.source_word_index],
        main[words.Layout.destination_word_index],
        main[words.Layout.length],
        main[words.Layout.expected_word_count],
        start,
        end,
    };
}

fn composeBytes(
    comptime S: type,
    main: *const [caller.main_column_count]S,
    group: usize,
) S {
    return main[caller.Layout.valueByte(group, 0)]
        .add(main[caller.Layout.valueByte(group, 1)].mul(scalar(S, 1 << 8)))
        .add(main[caller.Layout.valueByte(group, 2)].mul(scalar(S, 1 << 16)))
        .add(main[caller.Layout.valueByte(group, 3)].mul(scalar(S, 1 << 24)));
}

fn weighted4(
    comptime S: type,
    main: anytype,
    start: usize,
    comptime offset: u32,
) S {
    var result = S.zero();
    for (0..4) |index| result = result.add(
        main[start + index].mul(scalar(S, @as(u32, @intCast(index)) + offset)),
    );
    return result;
}

pub fn scalar(comptime S: type, value: u32) S {
    if (comptime S == M31) return M31.fromCanonical(value);
    if (comptime S == QM31) return QM31.fromBase(M31.fromCanonical(value));
    return S.fromBase(M31.fromCanonical(value));
}

comptime {
    if (caller.production_active or words.production_active or
        relation_count != 13 or call_schema_numeric_id != 12 or
        call_fields.len != call_arity)
    {
        @compileError("bulk memcpy relation identity drifted");
    }
}
