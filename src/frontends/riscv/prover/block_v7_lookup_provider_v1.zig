//! Six original lookup AIRs under the v7 source epoch, with every physical claim
//! absorbed before interaction commitment. No aggregate-only admission.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const suite = core.proof_suites.Blake3;
const Q = core.fields.qm31.QM31;
const Column = engine.pcs.ColumnEvaluation;
const Tables = @import("../air/lookups/tables/mod.zig");
const Original = @import("block_v5_native_lookup_proof_v1.zig");
const Assembly = @import("block_v5_native_lookup_assembly_v1.zig");
const Shared = @import("../recursion/air/universal_provider_relations.zig");
const Epoch = @import("block_v7_execution_epoch_v1.zig");
pub const Proof = Original.Proof;
pub fn firstEntry(plan: Original.Plan, roots: [2][32]u8) !Epoch.Entry {
    return Epoch.Entry.init(.lookup, plan.index, try plan.identity(), &roots);
}
pub const Policy = struct {
    plan: Original.Plan,
    roots: [2][32]u8,
    epoch: Epoch.Epoch,
    entries: []const Epoch.Entry,
    pub fn entry(self: Policy) !Epoch.Entry {
        return firstEntry(self.plan, self.roots);
    }
    pub fn admit(self: Policy) !void {
        try self.plan.validate();
        if (try std.math.add(u32, self.plan.first_execution, self.plan.execution_count) > self.epoch.counts[@intFromEnum(Epoch.Family.native)]) return error.InvalidV7LookupExecutionSpan;
        try self.epoch.requireEntry(self.entries, try self.entry());
    }
};
pub const Verified = struct {
    epoch: [32]u8,
    plan: [32]u8,
    roots: [2][32]u8,
    claims: [Assembly.Count]Q,
};
fn channel(policy: Policy, drawn: Epoch.Drawn, claims: [Assembly.Count]Q) !suite.Channel {
    var ch = drawn.channel;
    ch.mixU32s(&.{ 0x42374c54, Epoch.VERSION, Assembly.Count });
    (try policy.entry()).mix(&ch);
    for (claims) |claim| {
        if (!Shared.secureIsCanonical(&claim)) return error.NonCanonicalV7LookupClaim;
        ch.mixFelts(&.{claim});
    }
    return ch;
}
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        const Old = Original.ForBackend(Backend);
        const Verifier = core.pcs.verifier.CommitmentSchemeVerifier(suite.Hasher, suite.MerkleChannel);
        pub const FirstRound = Old.FirstRound;
        pub const FixedBasis = Old.FixedBasis;
        pub const commit = Old.commitFirstRound;
        pub const commitWithBasis = Old.commitFirstRoundWithBasis;

        pub fn prove(a: std.mem.Allocator, first: *FirstRound, counters: *const Tables.counter.Set, policy: Policy) !Proof {
            try policy.admit();
            try Original.validateSourceCounters(counters, policy.plan);
            if (!first.owns_scheme or !std.meta.eql(first.scheme.config, policy.epoch.config) or
                !std.meta.eql(first.roots, policy.roots) or !std.meta.eql(first.plan_id, try policy.plan.identity()) or
                !std.meta.eql(first.counter_snapshots, Original.snapshots(counters))) return error.UntrustedV7LookupFirstRound;
            const drawn = try policy.epoch.draw(a);
            const relations = try Shared.SharedProviderRelations.init(&drawn.word.universal_prefix);
            var interaction: std.ArrayList(Column) = .empty;
            defer {
                for (interaction.items) |column| a.free(column.values);
                interaction.deinit(a);
            }
            var claims: [Assembly.Count]Q = undefined;
            for (&counters.counters, &claims) |*counter, *claim| {
                var generated = try Tables.interaction.generate(a, counter, &relations.native);
                defer generated.deinit(a);
                claim.* = generated.claim;
                for (generated.columns) |values| {
                    const copy = try a.dupe(core.fields.m31.M31, values);
                    interaction.append(a, .{ .log_size = Tables.schema.logSize(counter.kind), .values = copy }) catch |err| {
                        a.free(copy);
                        return err;
                    };
                }
            }
            const owner = try Assembly.Owner.init(a, relations, claims);
            defer owner.destroy(a);
            var ch = try channel(policy, drawn, claims);
            try first.scheme.commitBorrowedStreaming(a, interaction.items, 8, &ch);
            first.owns_scheme = false;
            return .{ .stark = try engine.prove.prove(Backend, suite.Hasher, suite.MerkleChannel, a, &owner.proverHandles(), &ch, first.scheme), .claims = claims };
        }

        pub fn verifyBorrowed(a: std.mem.Allocator, proof: *const Proof, policy: Policy) !Verified {
            try policy.admit();
            const roots = proof.stark.commitment_scheme_proof.commitments.items;
            if (roots.len != 4 or !std.meta.eql(roots[0..2].*, policy.roots) or !std.meta.eql(proof.stark.commitment_scheme_proof.config, policy.epoch.config)) return error.UntrustedV7LookupProof;
            var fixed = try FixedBasis.init(a, policy.epoch.config);
            defer fixed.deinit(a);
            if (!std.meta.eql(fixed.root, roots[0])) return error.UntrustedV7LookupFixedRoot;
            const drawn = try policy.epoch.draw(a);
            const relations = try Shared.SharedProviderRelations.init(&drawn.word.universal_prefix);
            const owner = try Assembly.Owner.init(a, relations, proof.claims);
            defer owner.destroy(a);
            var arena = std.heap.ArenaAllocator.init(a);
            defer arena.deinit();
            const scratch = arena.allocator();
            var verifier = try Verifier.init(a, policy.epoch.config);
            defer verifier.deinit(a);
            var prefix = suite.Channel{};
            try verifier.commit(a, roots[0], try Assembly.logs(scratch, .fixed), &prefix);
            try verifier.commit(a, roots[1], try Assembly.logs(scratch, .main), &prefix);
            var ch = try channel(policy, drawn, proof.claims);
            try verifier.commit(a, roots[2], try Assembly.logs(scratch, .interaction), &ch);
            var capture: core.verifier.ProofCapture(suite.Hasher) = undefined;
            try core.verifier.verifyBorrowedWithProofCapture(suite.Hasher, suite.MerkleChannel, a, &owner.verifierHandles(), &ch, &verifier, &proof.stark, &capture);
            defer capture.deinit(a);
            return .{ .epoch = policy.epoch.digest, .plan = try policy.plan.identity(), .roots = policy.roots, .claims = proof.claims };
        }
    };
}
