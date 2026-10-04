const std = @import("std");
const core = @import("stwo_core");
const tree = @import("../../air/memory_commitment/blake3_state_tree.zig");
const relation = @import("../../air/lang/relation.zig");
const universal = @import("../../recursion/air/universal_challenges.zig");
const source = @import("../block_v5_program_table_v1.zig");
const proof_mod = @import("../block_v5_program_table_proof_v1.zig");

test "block-v5 complete ROM table proves nonzero global counts and closes shared program tuples" {
    const a = std.testing.allocator;
    const Cpu = @import("stwo_cpu_backend").CpuBackend;
    const api = proof_mod.ForBackend(Cpu);
    const M = core.fields.m31.M31;
    const Q = core.fields.qm31.QM31;
    var leaves = [_]tree.Leaf{
        .{ .index = 0, .value = 1 }, .{ .index = 1, .value = 2 },
        .{ .index = 2, .value = 3 }, .{ .index = 3, .value = 4 },
        .{ .index = 4, .value = 5 }, .{ .index = 5, .value = 6 },
        .{ .index = 6, .value = 7 }, .{ .index = 7, .value = 8 },
    };
    const root = try tree.TreeHasher.init(.program).root(&leaves);
    var counts = [_]u64{ 3, 2 };
    const plan = source.Plan{ .program_root = root, .leaves = &leaves, .multiplicities = &counts, .expected_fetches = 5, .log_size = 7 };
    try plan.validate();
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) };
    var first = try api.commitFirstRound(a, plan, config);
    defer first.deinit(a);
    const seal = try proof_mod.Seal.init(plan, @splat(41), @splat(53), first.roots);
    var swapped = seal;
    swapped.source_digest[0] ^= 1;
    const produced = try api.prove(a, &first, plan, seal);
    // A changed source seal is rejected by fresh PCS verification even when
    // the ROM and fixed/main roots are otherwise unchanged.
    // The proof is move-only, so verify the good branch after this structural
    // seal mutation check rather than copying the STARK allocation.
    try std.testing.expect(!std.meta.eql(seal.sharedChannel(), swapped.sharedChannel()));
    const receipt = try api.verifyOwned(a, produced, plan, seal, root, first.roots, config);
    try std.testing.expect(!receipt.claim.isZero());
    var challenge_channel = seal.sharedChannel();
    const relations = try universal.UniversalRelations.draw(a, &challenge_channel);
    const program_relation = relations.get(relation.Domain.program_access);
    var requests = Q.zero();
    for (counts, 0..) |count, i| {
        const tuple = [_]M{
            M.fromCanonical(leaves[4 * i].index),
            M.fromCanonical(leaves[4 * i].value),
            M.fromCanonical(leaves[4 * i + 1].value),
            M.fromCanonical(leaves[4 * i + 2].value),
            M.fromCanonical(leaves[4 * i + 3].value),
        };
        // Native execution requests carry positive multiplicity, and the
        // typed relation compiler negates `.request` at LogUp emission.
        requests = requests.sub(Q.fromBase(M.fromCanonical(@intCast(count))).mul(try (try program_relation.combineBase(&tuple)).inv()));
    }
    var digest_channel = seal.sharedChannel();
    const native = proof_mod.VerifiedNativeRequest{ .claim = requests, .fetch_count = 5, .sealed_channel_digest = digest_channel.digestBytes() };
    try proof_mod.closed(receipt, &.{native}, seal);
    try std.testing.expectError(error.UnclosedProgramRelation, proof_mod.closed(receipt, &.{.{ .claim = requests, .fetch_count = 4, .sealed_channel_digest = native.sealed_channel_digest }}, seal));
    try std.testing.expectError(error.UntrustedProgramTableReceipt, proof_mod.closed(receipt, &.{native}, swapped));
    leaves[1].value ^= 1;
    try std.testing.expectError(error.ProgramRootMismatch, plan.validate());
    leaves[1].value ^= 1;
    counts[1] += 1;
    try std.testing.expectError(error.ProgramFetchCensusMismatch, plan.validate());
    counts[1] -= 1;
    var second = try api.commitFirstRound(a, plan, config);
    defer second.deinit(a);
    const swapped_proof = try api.prove(a, &second, plan, seal);
    const wrong_receipt: ?proof_mod.VerifiedReceipt = api.verifyOwned(a, swapped_proof, plan, swapped, root, second.roots, config) catch null;
    try std.testing.expect(wrong_receipt == null);
}
