//! Explicit full-width BLAKE3 execution proof API. Not a production default.
//! Verification consumes the proof and requires caller-admitted public execution
//! geometry, commitment schedules and security parameters. No proof-supplied key
//! or preprocessing root becomes an authority.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const suite = core.proof_suites.Blake3;
const universal = @import("../recursion/air/universal_challenges.zig");
const providers = @import("../recursion/air/universal_provider_relations.zig");
const statement_mod = @import("../air/statement.zig");
const protocol = @import("blake3_execution_protocol.zig");
pub const Native = @import("blake3_execution_trace.zig").Owner;
pub const Hashes = @import("blake3_commitment_columns.zig").Owner;
const Joined = @import("blake3_execution_components.zig").Owner;
pub const Admission = @import("blake3_commitment_plan.zig").Admission;
pub const commitment_witness = @import("blake3_commitment_witness.zig");
pub const commitment_plan = @import("blake3_commitment_plan.zig");
pub const Statement = statement_mod.Blake3ExecutionStatement;
const N_HASHES = @import("blake3_commitment_components.zig").Airs.len;
const Q = core.fields.qm31.QM31;
const Column = engine.pcs.ColumnEvaluation;
pub const Proof = struct {
    stark: suite.Proof,
    native_claims: *statement_mod.RiscVInteractionClaim,
    hash_claims: [N_HASHES]Q,
    pub fn deinit(self: *Proof, a: std.mem.Allocator) void {
        self.stark.deinit(a);
        a.destroy(self.native_claims);
        self.* = undefined;
    }
};
pub const Proved = struct { proof: Proof, transcript_digest: [32]u8 };
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        const Scheme = engine.pcs.CommitmentSchemeProver(Backend, suite.Hasher, suite.MerkleChannel);
        const Verifier = core.pcs.verifier.CommitmentSchemeVerifier(suite.Hasher, suite.MerkleChannel);
        /// Borrows prepared owners, generating their interactions exactly once.
        /// On an error after interaction generation, rebuild the native owner.
        pub fn prove(a: std.mem.Allocator, native: *Native, hashes: *Hashes, pin: Admission, config: core.pcs.PcsConfig) !Proved {
            if (!native.tables_ready or native.failed or native.interaction_ready) return error.InvalidExecutionPhase;
            if (!std.mem.eql(u8, &hashes.plan_id, &pin.expected_id)) return error.UntrustedCommitmentPlan;
            var channel = suite.Channel{};
            try protocol.mix(&channel, config, &native.statement, pin);
            var arena = std.heap.ArenaAllocator.init(a);
            defer arena.deinit();
            const scratch = arena.allocator();
            var scheme = try Scheme.init(a, config);
            var owns_scheme = true;
            defer if (owns_scheme) scheme.deinit(a);
            var columns: std.ArrayList(Column) = .empty;
            try columns.appendSlice(scratch, native.preprocessed.items);
            try columns.appendSlice(scratch, hashes.preprocessed());
            try scheme.commit(a, columns.items, &channel);
            columns.clearRetainingCapacity();
            try columns.appendSlice(scratch, native.main.items);
            try columns.appendSlice(scratch, try hashes.main());
            try scheme.commit(a, columns.items, &channel);
            const relations = try universal.UniversalRelations.draw(a, &channel);
            const shared = try providers.SharedProviderRelations.init(&relations);
            try native.generateInteractions(&shared.native);
            var hash_interaction = try hashes.interactions(a, &relations);
            defer hash_interaction.deinit();
            const joined = try Joined.init(a, &native.statement, &native.claims, relations, pin);
            defer joined.deinit();
            try joined.bindCommitments(hashes, hash_interaction.claims);
            try requireClosed(joined, hash_interaction.claims);
            try protocol.mixClaims(&channel, &native.statement, &native.claims, &hash_interaction.claims);
            columns.clearRetainingCapacity();
            try columns.appendSlice(scratch, native.interaction.items);
            try columns.appendSlice(scratch, hash_interaction.columns.items);
            try scheme.commit(a, columns.items, &channel);
            var components: std.ArrayList(engine.air.component_prover.ComponentProver) = .empty;
            try components.appendSlice(scratch, joined.proving.components.active());
            try components.appendSlice(scratch, &(try hashes.provers()));
            const claims = try a.create(statement_mod.RiscVInteractionClaim);
            errdefer a.destroy(claims);
            claims.* = native.claims;
            owns_scheme = false;
            const stark = try engine.prove.prove(Backend, suite.Hasher, suite.MerkleChannel, a, components.items, &channel, scheme);
            return .{ .proof = .{ .stark = stark, .native_claims = claims, .hash_claims = hash_interaction.claims }, .transcript_digest = channel.digestBytes() };
        }
        /// Consumes proof on every path. Expected shape/pin/config must come from
        /// verifier admission, independently of the received proof bundle.
        pub fn verifyOwned(a: std.mem.Allocator, received: Proof, shape: *const statement_mod.Blake3ExecutionStatement, pin: Admission, config: core.pcs.PcsConfig) ![32]u8 {
            var proof = received;
            defer a.destroy(proof.native_claims);
            var owns_stark = true;
            defer if (owns_stark) proof.stark.deinit(a);
            if (proof.stark.commitment_scheme_proof.commitments.items.len != 4) return error.InvalidExecutionProof;
            if (proof.native_claims.n_components != shape.n_components or proof.native_claims.n_infra != shape.n_infra) return error.InvalidInteractionClaim;
            var channel = suite.Channel{};
            try protocol.mix(&channel, config, shape, pin);
            const hashes = try Hashes.init(a, pin);
            defer hashes.deinit();
            var arena = std.heap.ArenaAllocator.init(a);
            defer arena.deinit();
            const scratch = arena.allocator();
            var pp: std.ArrayList(Column) = .empty;
            try protocol.nativePreprocessed(scratch, shape, &pp);
            try pp.appendSlice(scratch, hashes.preprocessed());
            var fixed = try Scheme.init(a, config);
            defer fixed.deinit(a);
            var fixed_channel = channel;
            try fixed.commit(a, pp.items, &fixed_channel);
            var roots = try fixed.roots(a);
            defer roots.deinit(a);
            const expected_root = roots.items[0];
            try admitPreprocessedRoot(expected_root, proof.stark.commitment_scheme_proof.commitments.items[0]);
            var verifier = try Verifier.init(a, config);
            defer verifier.deinit(a);
            try verifier.commit(a, expected_root, try @import("../recursion/air/blake3_row_columns.zig").columnLogs(scratch, pp.items), &channel);
            try verifier.commit(a, proof.stark.commitment_scheme_proof.commitments.items[1], try protocol.columnLogs(scratch, shape, hashes.logs, .main), &channel);
            const relations = try universal.UniversalRelations.draw(a, &channel);
            const joined = try Joined.init(a, shape, proof.native_claims, relations, pin);
            defer joined.deinit();
            try joined.bindCommitments(hashes, proof.hash_claims);
            try requireClosed(joined, proof.hash_claims);
            try protocol.mixClaims(&channel, shape, proof.native_claims, &proof.hash_claims);
            try verifier.commit(a, proof.stark.commitment_scheme_proof.commitments.items[2], try protocol.columnLogs(scratch, shape, hashes.logs, .interaction), &channel);
            var components: std.ArrayList(core.air.components.Component) = .empty;
            try components.appendSlice(scratch, joined.verifying.components.active());
            try components.appendSlice(scratch, &(try hashes.verifiers()));
            owns_stark = false;
            try core.verifier.verify(suite.Hasher, suite.MerkleChannel, a, components.items, &channel, &verifier, proof.stark);
            return channel.digestBytes();
        }
    };
}
pub fn admitPreprocessedRoot(expected: suite.Hasher.Hash, supplied: suite.Hasher.Hash) !void {
    if (!std.mem.eql(u8, &expected, &supplied)) return error.UntrustedBlake3Preprocessing;
}
fn requireClosed(joined: *const Joined, hashes: [N_HASHES]Q) !void {
    if (joined.claims.n_components != joined.statement.n_components or joined.claims.n_infra != joined.statement.n_infra) return error.InvalidInteractionClaim;
    var total = try joined.publicCompensation();
    for (joined.statement.component_descs[0..joined.statement.n_components], 0..) |desc, i| total = total.add(try joined.claims.opcodeClaimTotal(desc.family, i));
    for (joined.statement.infra_descs[0..joined.statement.n_infra], 0..) |desc, i| total = total.add(try joined.claims.infraClaimTotal(desc.kind, i));
    for (hashes) |claim| total = total.add(claim);
    if (!total.isZero()) return error.UnclosedExecutionRelations;
}
