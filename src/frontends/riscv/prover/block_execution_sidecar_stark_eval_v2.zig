//! Shared native/OODS row formulas for one typed opcode access sidecar.
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const opcode = @import("../runner/trace.zig");
const bridge = @import("block_execution_access_bridge_v2.zig");
const integer = @import("block_execution_integer_bridge_v2.zig");
const transition = @import("block_execution_transition_interaction_v2.zig");
const bytes = @import("block_execution_byte_range_v2.zig");

pub const INTERACTION_COUNT: usize = transition.COLUMN_COUNT + bytes.COLUMN_COUNT;
pub const CONSTRAINT_COUNT: usize = integer.RESIDUAL_COUNT + 3 + bytes.BATCH_COUNT;

pub fn evaluateRow(self: anytype, main: []const Q, witness_columns: [integer.COLUMN_COUNT]Q, interaction: [INTERACTION_COUNT]Q, previous: [INTERACTION_COUNT]Q) ![CONSTRAINT_COUNT]Q {
    const pairs = try bridge.fromCommittedMain(Q, self.family, main);
    if (self.slot >= pairs.len) return error.InvalidExecutionSidecarSlot;
    return evaluatePair(self, pairs.items[self.slot], witness_columns, interaction, previous);
}

pub fn evaluatePair(self: anytype, pair: bridge.Pair(Q), witness_columns: [integer.COLUMN_COUNT]Q, interaction: [INTERACTION_COUNT]Q, previous: [INTERACTION_COUNT]Q) ![CONSTRAINT_COUNT]Q {
    const witness = integer.Witness.fromColumns(witness_columns);
    var result: [CONSTRAINT_COUNT]Q = undefined;
    var cursor: usize = 0;
    const direct = integer.constraints(pair, witness, self.base_clock);
    if (direct.len != integer.RESIDUAL_COUNT) return error.InvalidExecutionBridgeConstraintCount;
    @memcpy(result[cursor..][0..direct.len], direct.values[0..direct.len]);
    cursor += direct.len;
    const point = transition.Point{
        .active = pair.active,
        .tuple = integer.transitionAtPoint(pair, witness),
        .term = secure(interaction, 0),
        .prefix = secure(interaction, 4),
        .previous_prefix = secure(previous, 4),
        .count_prefix = interaction[8],
        .previous_count_prefix = previous[8],
    };
    const relation = if (self.v5_packed) |word_mode|
        try @import("block_v5_word_execution_transition_v1.zig").constraints(word_mode.elements, .{
            .active = point.active,
            .tuple = point.tuple,
            .term = point.term,
            .prefix = point.prefix,
            .previous_prefix = point.previous_prefix,
            .count_prefix = point.count_prefix,
            .previous_count_prefix = point.previous_count_prefix,
        }, self.transition_claim, self.transition_count, @as(u32, 1) << @intCast(self.log_size))
    else
        try transition.constraints(self.challenges, point, self.transition_claim, self.transition_count, @as(u32, 1) << @intCast(self.log_size));
    @memcpy(result[cursor..][0..3], &relation);
    cursor += 3;
    var current_sums: bytes.Claims = undefined;
    var previous_sums: bytes.Claims = undefined;
    for (&current_sums, &previous_sums, 0..) |*current, *prior, batch| {
        current.* = secure(interaction, transition.COLUMN_COUNT + 4 * batch);
        prior.* = secure(previous, transition.COLUMN_COUNT + 4 * batch);
    }
    const range = try bytes.constraints(self.challenges.universal_prefix.get(.range_check_8_8), pair.active, bytes.bytesAtPoint(pair, witness), current_sums, previous_sums, self.range_claims, @as(u32, 1) << @intCast(self.log_size));
    @memcpy(result[cursor..][0..range.len], &range);
    return result;
}

fn secure(columns: [INTERACTION_COUNT]Q, start: usize) Q {
    return Q.fromPartialEvals(.{ columns[start], columns[start + 1], columns[start + 2], columns[start + 3] });
}

pub fn expectedMainColumns(family: opcode.OpcodeFamily) usize {
    return opcode.nColumnsForFamily(family);
}
