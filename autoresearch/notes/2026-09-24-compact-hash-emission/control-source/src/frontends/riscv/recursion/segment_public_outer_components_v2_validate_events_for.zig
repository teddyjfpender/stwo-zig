//! Internal segment public outer components v2 authority shard; use segment_public_outer_components_v2.zig publicly.

const dependency_0 = @import("segment_public_outer_components_v2_contract.zig");

const ControlPlan = dependency_0.ControlPlan;
const ControlRow = dependency_0.ControlRow;
const ControlRuntime = dependency_0.ControlRuntime;
const Error = dependency_0.Error;
const M31 = dependency_0.M31;
const RelayPlan = dependency_0.RelayPlan;
const RelayRow = dependency_0.RelayRow;
const RelayRuntime = dependency_0.RelayRuntime;
const control_witness_v2 = dependency_0.control_witness_v2;
const manifest_mod = dependency_0.manifest_mod;
const relation_interaction = dependency_0.relation_interaction;
const source_v2 = dependency_0.source_v2;
const std = dependency_0.std;
const evaluateRelationOp = dependency_0.evaluateRelationOp;

pub fn validateActiveControlEvents(
    plan: *const ControlPlan,
    rows: []const ControlRow,
    events: []const control_witness_v2.RelationEventV2,
) !void {
    const slot_count = ControlRuntime.LOGICAL_INPUT_COUNT +
        relation_interaction.MAX_COMPILED_NODES;
    var slots: [slot_count]M31 = undefined;
    var cursor: usize = 0;
    for (rows, 0..) |row, logical_row| {
        @memcpy(slots[0..ControlRuntime.LOGICAL_INPUT_COUNT], &row);
        for (plan.compiled_nodes[0..plan.compiled_node_count]) |node|
            slots[node.destination] = evaluateRelationOp(node.op, &slots);
        for (plan.events) |expected| {
            const magnitude = slots[expected.numerator_slot];
            if (magnitude.isZero()) continue;
            if (cursor >= events.len) return error.EventProjectionMismatch;
            const actual = events[cursor];
            actual.validate() catch return error.EventProjectionMismatch;
            if (actual.logical_row != logical_row or
                actual.event_ordinal != expected.ordinal or
                actual.domain != expected.domain or actual.role != expected.role or
                actual.arity != expected.arity or
                actual.multiplicity != magnitude.toU32())
            {
                return error.EventProjectionMismatch;
            }
            for (
                actual.tuple[0..actual.arity],
                expected.value_slots[0..expected.arity],
            ) |got, slot| if (!got.eql(slots[slot]))
                return error.EventProjectionMismatch;
            cursor += 1;
        }
    }
    if (cursor != events.len) return error.EventProjectionMismatch;
}

pub fn validateEventsFor(
    plan: *const RelayPlan,
    rows: []const RelayRow,
    events: []const source_v2.RelationEventV2,
    cursor: *usize,
    component: manifest_mod.ComponentKey,
) !void {
    const slot_count = RelayRuntime.LOGICAL_INPUT_COUNT +
        relation_interaction.MAX_COMPILED_NODES;
    var slots: [slot_count]M31 = undefined;
    for (rows, 0..) |row, logical_row| {
        @memcpy(slots[0..RelayRuntime.LOGICAL_INPUT_COUNT], &row);
        for (plan.compiled_nodes[0..plan.compiled_node_count]) |node|
            slots[node.destination] = evaluateRelationOp(node.op, &slots);
        for (plan.events, 0..) |expected, ordinal| {
            if (cursor.* >= events.len) return error.EventProjectionMismatch;
            const actual = events[cursor.*];
            actual.validate() catch return error.EventProjectionMismatch;
            const magnitude = slots[expected.numerator_slot];
            if (actual.roster_row != manifest_mod.keyIndex(component) or
                actual.logical_row != logical_row or
                actual.event_ordinal != ordinal or
                actual.event_ordinal != expected.ordinal or
                actual.domain != expected.domain or
                actual.role != expected.role or
                actual.arity != expected.arity or
                actual.multiplicity != magnitude.toU32())
            {
                return error.EventProjectionMismatch;
            }
            if (actual.domain == .range_check_8_8)
                return error.EventProjectionMismatch;
            for (
                actual.tuple[0..actual.arity],
                expected.value_slots[0..expected.arity],
            ) |got, slot| if (!got.eql(slots[slot]))
                return error.EventProjectionMismatch;
            cursor.* += 1;
        }
    }
}

pub fn hashNativeDigest(hash: anytype, value: source_v2.Digest) void {
    for (value) |word| hashInt(hash, u32, word);
}

pub fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}

pub fn checkedAdd(left: usize, right: usize) Error!usize {
    return std.math.add(usize, left, right) catch error.ArithmeticOverflow;
}
