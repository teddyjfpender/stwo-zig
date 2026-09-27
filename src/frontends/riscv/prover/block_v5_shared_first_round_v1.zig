//! Reuse immutable fixed/main commitments across same-root component proofs.
//! Each proof has its own channel, interaction, quotient and opening query.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const suite = core.proof_suites.Blake3;

pub fn copy(comptime Backend: type, a: std.mem.Allocator, source: *engine.pcs.CommitmentSchemeProver(Backend, suite.Hasher, suite.MerkleChannel), channel: *suite.Channel) !engine.pcs.CommitmentSchemeProver(Backend, suite.Hasher, suite.MerkleChannel) {
    return copyExactly(Backend, a, a, source, channel, 2);
}
/// Trees retain the allocator that originally owns their storage. The copied
/// scheme can use a separate bounded allocator for its own descriptors.
pub fn copyWithSourceAllocator(comptime Backend: type, a: std.mem.Allocator, source_allocator: std.mem.Allocator, source: *engine.pcs.CommitmentSchemeProver(Backend, suite.Hasher, suite.MerkleChannel), channel: *suite.Channel) !engine.pcs.CommitmentSchemeProver(Backend, suite.Hasher, suite.MerkleChannel) {
    return copyExactly(Backend, a, source_allocator, source, channel, 2);
}
/// Reuse a deterministic fixed-tree basis across independently sized proofs.
pub fn copyFixed(comptime Backend: type, a: std.mem.Allocator, source: *engine.pcs.CommitmentSchemeProver(Backend, suite.Hasher, suite.MerkleChannel), channel: *suite.Channel) !engine.pcs.CommitmentSchemeProver(Backend, suite.Hasher, suite.MerkleChannel) {
    return copyExactly(Backend, a, a, source, channel, 1);
}
fn copyExactly(comptime Backend: type, a: std.mem.Allocator, source_allocator: std.mem.Allocator, source: *engine.pcs.CommitmentSchemeProver(Backend, suite.Hasher, suite.MerkleChannel), channel: *suite.Channel, expected_trees: usize) !engine.pcs.CommitmentSchemeProver(Backend, suite.Hasher, suite.MerkleChannel) {
    const Scheme = engine.pcs.CommitmentSchemeProver(Backend, suite.Hasher, suite.MerkleChannel);
    // Join any deferred commitment before leasing storage. No interaction tree
    // or proof-local channel state may cross the first-round boundary.
    var roots = try source.roots(a);
    defer roots.deinit(a);
    if (roots.items.len != expected_trees or source.trees.items.len != expected_trees)
        return error.InvalidBlockV5SharedFirstRound;
    var result = try Scheme.init(a, source.config);
    errdefer result.deinit(a);
    result.setCoefficientRetentionPolicy(.never);
    for (source.trees.items) |*tree| {
        try tree.share(source_allocator);
        var lease = tree.retainShared();
        var owns_lease = true;
        defer if (owns_lease) lease.deinit(a);
        try result.appendCommittedTree(a, lease, channel);
        owns_lease = false;
    }
    return result;
}
