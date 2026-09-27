//! V5 adds an opposite native `memory_access` recurrence to the same opcode
//! slot quotient that proves the local-to-global transition and byte range.
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const old = @import("block_execution_sidecar_stark_eval_v2.zig");
const bridge = @import("block_execution_access_bridge_v2.zig");
const integer = @import("block_execution_integer_bridge_v2.zig");
const universal = @import("block_v5_opcode_memory_interaction_v1.zig");

pub const INTERACTION_COUNT: usize = old.INTERACTION_COUNT + universal.COLUMN_COUNT;
pub const CONSTRAINT_COUNT: usize = old.CONSTRAINT_COUNT + universal.CONSTRAINT_COUNT;

pub fn evaluatePair(self: anytype, pair: bridge.Pair(Q), witness: [integer.COLUMN_COUNT]Q, interaction: [INTERACTION_COUNT]Q, previous: [INTERACTION_COUNT]Q) ![CONSTRAINT_COUNT]Q {
    if (self.v5_packed) |word_mode| {
        const domain = @as(u32, 1) << @intCast(self.log_size);
        if (self.transition_count > domain) return error.InvalidExecutionEventCount;
        const inverse = try core.fields.m31.M31.fromCanonical(domain).inv();
        var ranges: [7]Q = undefined;
        for (&ranges, self.range_claims) |*out, claim| out.* = claim.mulM31(inverse);
        const normalized_count = Q.fromBase(core.fields.m31.M31.fromU64(self.transition_count)).mulM31(inverse);
        return @import("block_v5_native_fused_algebra_v1.zig").Algebra(Q).access(pair, witness, interaction, previous, @import("block_execution_integer_algebra_v1.zig").clockBytes(Q, self.base_clock), word_mode.elements.transition, &word_mode.elements.universal_prefix, self.transition_claim.mulM31(inverse), normalized_count, ranges, self.v5_universal.?.claim.mulM31(inverse));
    }
    var old_interaction: [old.INTERACTION_COUNT]Q = undefined;
    var old_previous: [old.INTERACTION_COUNT]Q = undefined;
    @memcpy(&old_interaction, interaction[0..old.INTERACTION_COUNT]);
    @memcpy(&old_previous, previous[0..old.INTERACTION_COUNT]);
    const old_constraints = try old.evaluatePair(self, pair, witness, old_interaction, old_previous);
    const source = try universal.pointFromPair(pair);
    const start = old.INTERACTION_COUNT;
    const new_constraints = try universal.constraints(self.v5_universal.?.elements, .{
        .active = source.active,
        .consumed = source.consumed,
        .emitted = source.emitted,
        .consume_term = secure(interaction, start),
        .emit_term = secure(interaction, start + 4),
        .prefix = secure(interaction, start + 8),
        .previous_prefix = secure(previous, start + 8),
    }, self.v5_universal.?.claim, @as(u32, 1) << @intCast(self.log_size));
    return old_constraints ++ new_constraints;
}

fn secure(values: [INTERACTION_COUNT]Q, at: usize) Q {
    return Q.fromPartialEvals(.{ values[at], values[at + 1], values[at + 2], values[at + 3] });
}
