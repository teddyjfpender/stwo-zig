//! Record the existing guest caller/provider equations over recursive scalars.
//! Placements come from independently admitted native component assembly.
const core = @import("stwo_core");
const r = @import("composition_graph_recorder.zig");
const S = r.Scalar;
const direct = @import("../../air/guest_precompile/direct_constraints.zig");
const interaction = @import("../../air/guest_precompile/interaction_plan.zig");
const logup = @import("../../air/logup.zig");
const statement = @import("../../prover/blake3_poseidon_statement.zig");
const Placement = @import("../../prover/guest_precompile/component_assembly.zig").PlacementDescriptor;
const GuestRelation = struct {
    z: S,
    powers: [32]S,
    fn init(draw: [2]S) GuestRelation {
        var result = GuestRelation{ .z = draw[0], .powers = undefined };
        var power = S.one();
        for (&result.powers) |*value| {
            value.* = power;
            power = power.mul(draw[1]);
        }
        return result;
    }
    pub fn combine(self: GuestRelation, values: [32]S) S {
        var value = S.zero();
        for (values, self.powers) |word, power| value = value.add(word.mul(power));
        return value.sub(self.z);
    }
};
pub fn record(extension: *const statement.Statement, placements: [2]Placement, samples: anytype, claims: []const S, base_relations: anytype, draw: [2]S, randomness: S, point: core.circle.CirclePoint(S), max_log: u32, cache: *r.DenominatorCache, accumulated: *S) !usize {
    if (claims.len != interaction.total_batch_count) return error.InvalidExecutionComposition;
    const Relations = struct { base: @TypeOf(base_relations), guest_poseidon2_io: GuestRelation };
    const relations = Relations{ .base = base_relations, .guest_poseidon2_io = .init(draw) };
    var claim: usize = 0;
    var count: usize = 0;
    inline for (0..2) |index| {
        const width = if (index == 0) direct.caller_main_column_count else direct.provider_main_column_count;
        const placement = placements[index];
        var row: [width]S = undefined;
        for (&row, 0..) |*value, column| value.* = try samples.at(1, placement.main_offset + column, 0);
        const first = try samples.at(0, placement.preprocessed_offset, 0);
        const active = try samples.at(0, placement.preprocessed_offset + 1, 0);
        const denominator = try r.quotientDenominator(extension.components[index].log_size, max_log, point, cache);
        const constraints = if (index == 0) direct.evaluateCallerGeneric(S, row, active) else direct.evaluateProviderGeneric(S, row, active);
        for (constraints) |value| r.accumulate(accumulated, randomness, value, denominator);
        count += constraints.len;
        const pairs = if (index == 0) try interaction.callerRowPairsGeneric(S, &row, &relations) else try interaction.providerRowPairsGeneric(S, &row, &relations);
        for (pairs, 0..) |pair, batch| {
            const current = try samples.secure(placement.interaction_offset + batch * 4, 0);
            const previous = try samples.secure(placement.interaction_offset + batch * 4, 1);
            r.accumulate(accumulated, randomness, logup.pairConstraintGeneric(S, current, previous, first, claims[claim], pair), denominator);
            claim += 1;
            count += 1;
        }
    }
    return count;
}
