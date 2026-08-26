const std = @import("std");
const model = @import("materialization_frontier_cost_model.zig");
const frontier_digest = @import("materialization_frontier_digest.zig");
const poseidon = @import("typed_poseidon2_fixed_direct.zig");

test "cost-model identities pin the optional and Poseidon direct programs" {
    const semantic_only = model.semanticOnly();
    try model.validate(semantic_only, 0);
    try std.testing.expectEqual(model.Scope.semantic_equalities_only, semantic_only.scope);
    try std.testing.expect(std.mem.allEqual(
        u8,
        &semantic_only.fixed_program_digest,
        0,
    ));

    const poseidon_model = model.poseidon2PermutationDirect();
    try model.validate(poseidon_model, poseidon.fixed_root_count);
    try std.testing.expectEqual(
        model.Scope.poseidon2_permutation_direct_v1,
        poseidon_model.scope,
    );
    try std.testing.expectEqualSlices(
        u8,
        &poseidon.canonical_digest,
        &poseidon_model.fixed_program_digest,
    );
    try std.testing.expect(!std.mem.eql(
        u8,
        &semantic_only.cost_model_digest,
        &poseidon_model.cost_model_digest,
    ));
}

test "cost-model validation rejects re-sealed scope algebra and geometry drift" {
    var changed = model.poseidon2PermutationDirect();
    changed.fixed_node_count -= 1;
    reseal(&changed);
    try std.testing.expectError(error.InvalidCostModel, model.validate(changed, 4));

    changed = model.poseidon2PermutationDirect();
    changed.fixed_program_digest[0] ^= 1;
    reseal(&changed);
    try std.testing.expectError(error.InvalidCostModel, model.validate(changed, 4));

    changed = model.poseidon2PermutationDirect();
    changed.evaluation_schedule = .candidate_equalities_only;
    reseal(&changed);
    try std.testing.expectError(error.InvalidCostModel, model.validate(changed, 4));

    changed = model.poseidon2PermutationDirect();
    changed.cost_model_digest[0] ^= 1;
    try std.testing.expectError(error.DigestMismatch, model.validate(changed, 4));
    try std.testing.expectError(
        error.InvalidCostModel,
        model.validate(model.poseidon2PermutationDirect(), 3),
    );

    var forged_empty = model.semanticOnly();
    forged_empty.fixed_root_count = 4;
    reseal(&forged_empty);
    try std.testing.expectError(error.InvalidCostModel, model.validate(forged_empty, 4));
}

fn reseal(identity: *model.Identity) void {
    identity.cost_model_digest = frontier_digest.computeCostModel(identity.digestView());
}
