//! Replay the same authenticated typed SHA programs as the native verifier.
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const r = @import("composition_graph_recorder.zig");
const S = r.Scalar;
const sha = @import("../../air/guest_precompile/sha256_component_profile.zig");
const Owner = @import("universal_component_owner.zig").ForRoster(sha.Roster);
const Placement = @import("../../prover/guest_precompile/ethereum_sha_assembly.zig").PlacementDescriptor;
pub fn record(owner: *const Owner, profile: *const sha.Profile, placements: [sha.Airs.len]Placement, samples: anytype, claims: [sha.Airs.len]S, challenges: *const r.ChallengeSet, randomness: S, point: core.circle.CirclePoint(S), max_log: u32, cache: *r.DenominatorCache, accumulated: *S) !usize {
    var constraints: usize = 0;
    inline for (sha.Airs, 0..) |Air, i| {
        const placement = placements[i];
        const Runtime = @import("universal_relation_binding.zig").Binding(Air).Runtime;
        var row: [Runtime.LOGICAL_INPUT_COUNT]S = undefined;
        for (row[0..Air.PHYSICAL_MAIN_COLUMN_COUNT], 0..) |*value, c| value.* = try samples.at(1, placement.main_offset + c, 0);
        for (row[Air.PHYSICAL_MAIN_COLUMN_COUNT..], 0..) |*value, c| value.* = try samples.at(0, placement.preprocessed_offset + c, 0);
        var current: [Runtime.BATCH_COUNT]S = undefined;
        for (&current, 0..) |*value, batch| value.* = try samples.secure(placement.interaction_offset + 4 * batch, if (batch + 1 == Runtime.BATCH_COUNT) 1 else 0);
        const previous = try samples.secure(placement.interaction_offset + 4 * (Runtime.BATCH_COUNT - 1), 0);
        const log = profile.descriptors[i].log_size;
        const denominator = try r.quotientDenominator(log, max_log, point, cache);
        const shift = claims[i].mul(S.fromBase(try M.fromU64(@as(u64, 1) << @intCast(log)).inv()));
        constraints += try r.recordComponent(Runtime, &owner.components[i], row, current, previous, shift, challenges, randomness, denominator, accumulated);
    }
    return constraints;
}
