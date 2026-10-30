//! Active-inventory interaction/lookup boundary. Full-roster SHA padding is
//! not part of a zero-SHA active proof, including its otherwise nonzero lookup
//! claims. Never apply this policy to the original full caller protocol.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Profile = @import("blake3_ethereum_sha_profile.zig");
const Columns = @import("guest_precompile/ethereum_sha_columns.zig");
const Witness = @import("block_v5_precompile_witness_v1.zig").Witness;

pub fn interactions(a: std.mem.Allocator, witness: *const Witness, relations: *const Profile.Relations, pool: *engine.work_pool.WorkPool) !Columns.Interaction {
    const layout = try @import("block_v7_caller_active_layout_v1.zig").Layout.derive(&witness.statement, witness.total_steps);
    var result = try Profile.interactions(a, witness, relations, pool);
    // The columns remain owned by result until deinit. Layout.columns omits
    // the entire SHA suffix, and requireClaims rejects any nonzero omitted
    // physical claim on the verifier. No retained constraint is weakened.
    if (!layout.active[14]) result.claim.sha = @splat(core.fields.qm31.QM31.zero());
    return result;
}

pub fn registerLookup(a: std.mem.Allocator, witness: *const Witness, counters: anytype) !void {
    try witness.statement.sha.validate(witness.total_steps);
    if (witness.statement.sha.call_count != witness.sha_rows.geometry.calls) return error.InvalidActiveShaCallCount;
    if (witness.statement.sha.call_count == 0) return;
    try @import("../air/guest_precompile/sha256_lookup_registration.zig").register(a, &witness.sha_rows, counters);
}
