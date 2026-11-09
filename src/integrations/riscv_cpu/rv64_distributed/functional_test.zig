const std = @import("std");
const F = @import("functional.zig");
const D = @import("manifest.zig");
const Context = @import("manifest_test.zig");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const a = std.testing.allocator;

test "distributed facts actual q70 proofs bind stage1 peers and all balanced physical claims" {
    const roster = F.diagnosticRoster();
    const context = Context.context();
    var aggregate = try F.produce(a, context, &roster);
    defer aggregate.deinit(a);
    try F.verify(a, context, &roster, &aggregate);
    // Two real FRI/AIR proofs, not native root records or empty proof shells.
    try std.testing.expect(aggregate.proofs[0].bytes.len > 1024);
    try std.testing.expect(aggregate.proofs[1].bytes.len > 1024);
    const original0 = aggregate.proofs[0].claims[0];
    const original1 = aggregate.proofs[1].claims[0];
    aggregate.proofs[0].claims[0] = original0.add(Q.one());
    aggregate.proofs[1].claims[0] = original1.sub(Q.one());
    try std.testing.expect(aggregate.proofs[0].claims[0].add(aggregate.proofs[1].claims[0]).isZero());
    // Aggregate arithmetic alone still closes; each actual proof binds its own
    // physical claim before constraint coefficients and rejects the alteration.
    if (F.verify(a, context, &roster, &aggregate)) |_| return error.AcceptedBalancedClaimForgery else |_| {}
    aggregate.proofs[0].claims[0] = original0;
    aggregate.proofs[1].claims[0] = original1;
    var receipts = aggregate.manifest.receipts[0..2].*;
    receipts[1].shared.value[0] ^= 1;
    var changed = try D.Manifest.init(a, .{ .context = context, .specs = aggregate.manifest.specs }, &receipts);
    defer changed.deinit();
    try std.testing.expect(!std.meta.eql(try aggregate.manifest.derive(), try changed.derive()));
    // Consumer's OWN observed root is unchanged. A peer-root replay must still
    // fail real verification because the complete manifest alters its alpha.
    std.mem.swap(D.Manifest, &aggregate.manifest, &changed);
    if (F.verify(a, context, &roster, &aggregate)) |_| return error.AcceptedPeerRootReplay else |err| {
        try std.testing.expect(err != error.Stage1ProofRootMismatch);
    }
    std.mem.swap(D.Manifest, &aggregate.manifest, &changed);
    try F.verify(a, context, &roster, &aggregate);
    // An actual proof body with the SAME stage1 roots must also fail. This
    // reaches the physical AIR/FRI verifier instead of only root comparison.
    var sampled = try @import("stwo_proof_wire").decodeProofBytesBinary(a, aggregate.proofs[0].bytes);
    defer sampled.deinit(a);
    sampled.commitment_scheme_proof.sampled_values.items[1][0][0] = sampled.commitment_scheme_proof.sampled_values.items[1][0][0].add(Q.one());
    const forged = try @import("stwo_proof_wire").encodeProofBytesBinary(a, sampled);
    defer a.free(forged);
    const saved = aggregate.proofs[0].bytes;
    aggregate.proofs[0].bytes = forged;
    defer aggregate.proofs[0].bytes = saved;
    if (F.verify(a, context, &roster, &aggregate)) |_| return error.AcceptedForgedPhysicalProof else |err| {
        try std.testing.expect(err != error.Stage1ProofRootMismatch);
    }
    aggregate.proofs[0].bytes = saved;
    var other = context;
    other.request_id += @as(u64, 1) << 32;
    try std.testing.expectError(error.DistributedContextMismatch, F.verify(a, other, &roster, &aggregate));
}

test "distributed public roster uses immutable setup and rejects two valid proofs with false global IO" {
    const context = Context.context();
    const roster = F.diagnosticRoster();
    var honest = try F.produce(a, context, &roster);
    defer honest.deinit(a);
    var false_roster = roster;
    false_roster[1][9] = false_roster[1][9].add(M.one());
    var false_io = try F.produce(a, context, &false_roster);
    defer false_io.deinit(a);
    // Preprocessing is geometry-only, public facts are bound as coefficients,
    // MAIN commitments, and statement digests before the manifest challenge.
    try std.testing.expectEqualDeep(honest.manifest.specs[0].expected_fixed, false_io.manifest.specs[0].expected_fixed);
    try std.testing.expect(!std.meta.eql(honest.manifest.receipts[0].shared, false_io.manifest.receipts[0].shared));
    try std.testing.expect(!std.meta.eql(honest.manifest.specs[0].public_statement, false_io.manifest.specs[0].public_statement));
    try std.testing.expectError(error.DistributedInventoryMismatch, F.verify(a, context, &false_roster, &honest));
    // This particular error is reached only AFTER fresh verification of BOTH
    // actual proofs. Each local statement is true, but delegated IO disagrees.
    try std.testing.expectError(error.UnclosedDistributedFunctionalClaims, F.verify(a, context, &false_roster, &false_io));
}

test "distributed functional construction fails without changing borrowed public input" {
    const roster = F.diagnosticRoster();
    for ([_]usize{ 0, 1, 2, 3, 4 }) |index| {
        var failing = std.testing.FailingAllocator.init(a, .{ .fail_index = index });
        try std.testing.expectError(error.OutOfMemory, F.produce(failing.allocator(), Context.context(), &roster));
        try std.testing.expectEqualDeep(F.diagnosticRoster(), roster);
    }
    var bad = roster;
    bad[0][13] = M.fromCanonical(2);
    if (F.produce(a, Context.context(), &bad)) |owned| {
        var unexpected = owned;
        unexpected.deinit(a);
        return error.AcceptedNonBooleanPublicWeight;
    } else |err| try std.testing.expectEqual(error.InvalidWord16RosterWeight, err);
}
