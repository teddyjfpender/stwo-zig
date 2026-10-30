//! Genuine original provider proofs. These remain open relations, not execution
//! admission: a separate integration gate must close authenticated consumers.
const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const E = @import("block_v7_execution_epoch_v1.zig");
const P = @import("block_v7_program_provider_v1.zig");
const L = @import("block_v7_lookup_provider_v1.zig");
const Tables = @import("../air/lookups/tables/mod.zig");
const Tree = @import("../air/memory_commitment/blake3_state_tree.zig");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Program = P.ForBackend(Cpu);
const Lookup = L.ForBackend(Cpu);
fn config() !core.pcs.PcsConfig {
    return .{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8), .lifting_log_size = null };
}
fn epoch(entries: []const E.Entry) !E.Epoch {
    var counts: E.Counts = @splat(0);
    for (entries) |entry| counts[@intFromEnum(entry.family)] += 1;
    return E.Epoch.init(@splat(71), try config(), counts, entries, entries.len);
}
fn roundTrip(a: std.mem.Allocator, proof: *core.proof_suites.Blake3.Proof) !void {
    const wire = @import("interop_postcard");
    var writer = std.Io.Writer.Allocating.init(a);
    defer writer.deinit();
    try wire.serializeProof(core.proof_suites.Blake3.Hasher, &writer.writer, proof.*);
    var reader = std.io.fixedBufferStream(writer.written());
    const fresh = try wire.deserializeProof(core.proof_suites.Blake3.Hasher, a, reader.reader());
    proof.deinit(a);
    proof.* = fresh;
    try std.testing.expectEqual(writer.written().len, reader.pos);
}
test "v7 global providers ROM original proof binds independent table and new epoch" {
    const a = std.testing.allocator;
    const leaves = [_]Tree.Leaf{ .{ .index = 0, .value = 1 }, .{ .index = 1, .value = 2 }, .{ .index = 2, .value = 3 }, .{ .index = 3, .value = 4 }, .{ .index = 4, .value = 5 }, .{ .index = 5, .value = 6 }, .{ .index = 6, .value = 7 }, .{ .index = 7, .value = 8 } };
    const plan = @import("block_v5_program_table_v1.zig").Plan{ .program_root = try Tree.TreeHasher.init(.program).root(&leaves), .leaves = &leaves, .multiplicities = &.{ 3, 2 }, .expected_fetches = 5, .log_size = 7 };
    var first = try Program.commit(a, plan, try config());
    defer first.deinit(a);
    const entries = [_]E.Entry{try P.firstEntry(plan, first.roots)};
    const policy = P.Policy{ .plan = plan, .expected_program_root = plan.program_root, .roots = first.roots, .epoch = try epoch(&entries), .entries = &entries };
    var proof = try Program.prove(a, &first, policy);
    defer proof.deinit(a);
    try roundTrip(a, &proof.stark);
    const verified = try Program.verifyBorrowed(a, &proof, policy);
    try std.testing.expectEqual(@as(u64, 5), verified.fetch_count);
    try std.testing.expect(verified.claim.eql(proof.claim));
    const old = proof.claim;
    proof.claim = old.add(Q.one());
    try std.testing.expectError(error.OodsNotMatching, Program.verifyBorrowed(a, &proof, policy));
    proof.claim = old;
    var wrong = policy;
    wrong.expected_program_root.bytes[0] ^= 1;
    try std.testing.expectError(error.UntrustedV7ProgramRoot, Program.verifyBorrowed(a, &proof, wrong));
    wrong = policy;
    wrong.epoch = try E.Epoch.init(@splat(72), try config(), policy.epoch.counts, &entries, entries.len);
    try std.testing.expectError(error.OodsNotMatching, Program.verifyBorrowed(a, &proof, wrong));
    // A self-consistent alternate roster still cannot choose the fixed table.
    var changed_entries = entries;
    changed_entries[0].roots[0][0] ^= 1;
    wrong = policy;
    wrong.roots[0] = changed_entries[0].roots[0];
    wrong.entries = &changed_entries;
    wrong.epoch = try epoch(&changed_entries);
    const saved_root = proof.stark.commitment_scheme_proof.commitments.items[0];
    proof.stark.commitment_scheme_proof.commitments.items[0] = wrong.roots[0];
    defer proof.stark.commitment_scheme_proof.commitments.items[0] = saved_root;
    try std.testing.expectError(error.UntrustedV7ProgramFixedRoot, Program.verifyBorrowed(a, &proof, wrong));
}
test "v7 global providers lookup original proof binds each physical sum and independent fixed root" {
    const a = std.testing.allocator;
    var counters = try Tables.counter.Set.init(a);
    defer counters.deinit(a);
    for (&counters.counters, 0..) |*counter, i| try counter.registerBase(if (i % 2 == 0) M.one() else M.one().neg(), (try Tables.schema.tupleAt(counter.kind, i)).slice());
    const plan = @import("block_v5_native_lookup_proof_v1.zig").Plan{ .index = 0, .first_execution = 0, .execution_count = 1, .max_requests = @splat(1) };
    var first = try Lookup.commit(a, &counters, plan, try config());
    defer first.deinit(a);
    // A declared consumer permits testing provider admission alone; this test
    // intentionally does not call execution closure or claim a native proof.
    const entries = [_]E.Entry{ try E.Entry.init(.native, 0, @splat(30), &.{@splat(31)}), try L.firstEntry(plan, first.roots) };
    const policy = L.Policy{ .plan = plan, .roots = first.roots, .epoch = try epoch(&entries), .entries = &entries };
    var proof = try Lookup.prove(a, &first, &counters, policy);
    defer proof.deinit(a);
    try roundTrip(a, &proof.stark);
    const verified = try Lookup.verifyBorrowed(a, &proof, policy);
    try std.testing.expectEqualDeep(proof.claims, verified.claims);
    const saved = proof.claims;
    proof.claims[0] = saved[0].add(Q.one());
    proof.claims[1] = saved[1].sub(Q.one());
    try std.testing.expectError(error.OodsNotMatching, Lookup.verifyBorrowed(a, &proof, policy));
    proof.claims = saved;
    var wrong = policy;
    wrong.epoch = try E.Epoch.init(@splat(72), try config(), policy.epoch.counts, &entries, entries.len);
    try std.testing.expectError(error.OodsNotMatching, Lookup.verifyBorrowed(a, &proof, wrong));
    var changed_entries = entries;
    changed_entries[1].roots[0][0] ^= 1;
    wrong = policy;
    wrong.roots[0] = changed_entries[1].roots[0];
    wrong.entries = &changed_entries;
    wrong.epoch = try epoch(&changed_entries);
    const saved_root = proof.stark.commitment_scheme_proof.commitments.items[0];
    proof.stark.commitment_scheme_proof.commitments.items[0] = wrong.roots[0];
    defer proof.stark.commitment_scheme_proof.commitments.items[0] = saved_root;
    try std.testing.expectError(error.UntrustedV7LookupFixedRoot, Lookup.verifyBorrowed(a, &proof, wrong));
}
