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
pub const codec = @import("blake3_execution_codec.zig");
pub const commitment_plan = @import("blake3_commitment_plan.zig");
pub const Statement = statement_mod.Blake3ExecutionStatement;
const N_HASHES = @import("blake3_commitment_components.zig").Airs.len;
const Q = core.fields.qm31.QM31;
const Column = engine.pcs.ColumnEvaluation;
pub const Proof = struct {
    stark: suite.Proof,
    key_id: [32]u8,
    native_claims: *statement_mod.RiscVInteractionClaim,
    hash_claims: [N_HASHES]Q,
    pub fn deinit(self: *Proof, a: std.mem.Allocator) void {
        self.stark.deinit(a);
        a.destroy(self.native_claims);
        self.* = undefined;
    }
};
pub const Verified = @import("blake3_execution_capture.zig").Verified;
pub const Proved = struct { proof: Proof, transcript_digest: [32]u8 };
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        const Scheme = engine.pcs.CommitmentSchemeProver(Backend, suite.Hasher, suite.MerkleChannel);
        pub const PreparedVerifier = @import("blake3_execution_prepared.zig").ForBackend(Backend);
        const Verifier = core.pcs.verifier.CommitmentSchemeVerifier(suite.Hasher, suite.MerkleChannel);
        /// Non-consuming admission shared by one-shot and paired proving.
        pub fn validateForProving(native: *const Native, hashes: *const Hashes, pin: Admission) !void {
            if (!native.tables_ready or native.failed or native.interaction_ready) return error.InvalidExecutionPhase;
            if (!std.mem.eql(u8, &hashes.plan_id, &pin.expected_id)) return error.UntrustedCommitmentPlan;
        }
        /// Borrows prepared owners, generating their interactions exactly once.
        /// On an error after interaction generation, rebuild the native owner.
        pub fn prove(a: std.mem.Allocator, native: *Native, hashes: *Hashes, pin: Admission, config: core.pcs.PcsConfig) !Proved {
            try validateForProving(native, hashes, pin);
            var channel = suite.Channel{};
            try protocol.mix(&channel, config, &native.statement, pin);
            var arena = std.heap.ArenaAllocator.init(a);
            defer arena.deinit();
            const scratch = arena.allocator();
            var scheme = try Scheme.init(a, config);
            // Sampled openings can use the LDE; do not retain duplicate coefficients.
            scheme.setCoefficientRetentionPolicy(.never);
            var owns_scheme = true;
            defer if (owns_scheme) scheme.deinit(a);
            var columns: std.ArrayList(Column) = .empty;
            try columns.appendSlice(scratch, native.preprocessed.items);
            try columns.appendSlice(scratch, hashes.preprocessed());
            try scheme.commitBorrowedStreaming(a, columns.items, 8, &channel);
            var roots = try scheme.roots(a);
            defer roots.deinit(a);
            const key = @import("blake3_execution_key.zig").Key{ .preprocessed_root = roots.items[0], .hash_logs = hashes.logs };
            const key_id = try key.identity(&native.statement, pin, config);
            columns.clearRetainingCapacity();
            try columns.appendSlice(scratch, native.main.items);
            try columns.appendSlice(scratch, try hashes.main());
            try scheme.commitBorrowedStreaming(a, columns.items, 8, &channel);
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
            try scheme.commitBorrowedStreaming(a, columns.items, 8, &channel);
            var components: std.ArrayList(engine.air.component_prover.ComponentProver) = .empty;
            try components.appendSlice(scratch, joined.proving.components.active());
            try components.appendSlice(scratch, &(try hashes.provers()));
            const claims = try a.create(statement_mod.RiscVInteractionClaim);
            errdefer a.destroy(claims);
            claims.* = native.claims;
            owns_scheme = false;
            const stark = try engine.prove.prove(Backend, suite.Hasher, suite.MerkleChannel, a, components.items, &channel, scheme);
            return .{ .proof = .{ .stark = stark, .key_id = key_id, .native_claims = claims, .hash_claims = hash_interaction.claims }, .transcript_digest = channel.digestBytes() };
        }
        /// Consumes proof on every path. Expected shape/pin/config must come from
        /// verifier admission, independently of the received proof bundle.
        pub fn verifyOwned(a: std.mem.Allocator, received: Proof, shape: *const statement_mod.Blake3ExecutionStatement, pin: Admission, config: core.pcs.PcsConfig) ![32]u8 {
            var proof = received;
            const prepared = PreparedVerifier.init(a, shape, pin, config) catch |err| {
                proof.deinit(a);
                return err;
            };
            defer prepared.deinit();
            return verifyPreparedOwned(a, proof, prepared, prepared.id);
        }
        /// Reuses authenticated plans and geometry without rebuilding fixed
        /// trace columns. The caller supplies the expected ID independently.
        pub fn verifyPreparedOwned(a: std.mem.Allocator, received: Proof, prepared: *PreparedVerifier, expected_id: [32]u8) ![32]u8 {
            return verifyPreparedInternal(false, a, received, prepared, expected_id);
        }
        pub fn verifyPreparedCaptureOwned(a: std.mem.Allocator, received: Proof, prepared: *PreparedVerifier, expected_id: [32]u8) !Verified {
            return verifyPreparedInternal(true, a, received, prepared, expected_id);
        }
        fn verifyPreparedInternal(comptime capture_mode: bool, a: std.mem.Allocator, received: Proof, prepared: *PreparedVerifier, expected_id: [32]u8) !(if (capture_mode) Verified else [32]u8) {
            var proof = received;
            var owns_claims = true;
            defer if (owns_claims) a.destroy(proof.native_claims);
            var owns_stark = true;
            defer if (owns_stark) proof.stark.deinit(a);
            try prepared.validate(expected_id);
            if (!std.mem.eql(u8, &proof.key_id, &expected_id)) return error.UntrustedExecutionKey;
            const shape = &prepared.shape;
            const pin = prepared.admission();
            const config = prepared.config;
            if (proof.stark.commitment_scheme_proof.commitments.items.len != 4) return error.InvalidExecutionProof;
            if (!std.meta.eql(proof.stark.commitment_scheme_proof.config, config)) return error.InvalidExecutionConfig;
            if (proof.native_claims.n_components != shape.n_components or proof.native_claims.n_infra != shape.n_infra) return error.InvalidInteractionClaim;
            var channel = suite.Channel{};
            try protocol.mix(&channel, config, shape, pin);
            const hashes = prepared.hashes.?;
            var arena = std.heap.ArenaAllocator.init(a);
            defer arena.deinit();
            const scratch = arena.allocator();
            const expected_root = prepared.key.preprocessed_root;
            try admitPreprocessedRoot(expected_root, proof.stark.commitment_scheme_proof.commitments.items[0]);
            var verifier = try Verifier.init(a, config);
            defer verifier.deinit(a);
            try verifier.commit(a, expected_root, prepared.logs[0], &channel);
            try verifier.commit(a, proof.stark.commitment_scheme_proof.commitments.items[1], prepared.logs[1], &channel);
            const relations = try universal.UniversalRelations.draw(a, &channel);
            const joined = try Joined.init(a, shape, proof.native_claims, relations, pin);
            defer joined.deinit();
            try joined.bindCommitments(hashes, proof.hash_claims);
            try requireClosed(joined, proof.hash_claims);
            try protocol.mixClaims(&channel, shape, proof.native_claims, &proof.hash_claims);
            try verifier.commit(a, proof.stark.commitment_scheme_proof.commitments.items[2], prepared.logs[2], &channel);
            var components: std.ArrayList(core.air.components.Component) = .empty;
            try components.appendSlice(scratch, joined.verifying.components.active());
            try components.appendSlice(scratch, &(try hashes.verifiers()));
            owns_stark = false;
            if (capture_mode) {
                var capture: core.verifier.ProofCapture(suite.Hasher) = undefined;
                try core.verifier.verifyWithProofCapture(suite.Hasher, suite.MerkleChannel, a, components.items, &channel, &verifier, proof.stark, &capture);
                errdefer capture.deinit(a);
                var result = Verified{ .allocator = a, .key_id = expected_id, .proof = capture, .native_claims = proof.native_claims, .hash_claims = proof.hash_claims, .relations = relations, .final_channel = channel, .seal = undefined };
                result.seal = try result.identity(shape);
                owns_claims = false;
                return result;
            } else {
                try core.verifier.verify(suite.Hasher, suite.MerkleChannel, a, components.items, &channel, &verifier, proof.stark);
                return channel.digestBytes();
            }
        }
    };
}
pub fn admitPreprocessedRoot(expected: suite.Hasher.Hash, supplied: suite.Hasher.Hash) !void {
    if (!std.mem.eql(u8, &expected, &supplied)) return error.UntrustedBlake3Preprocessing;
}
fn requireClosed(joined: *const Joined, hashes: [N_HASHES]Q) !void {
    return requireClosedWithExternal(joined, hashes, Q.zero());
}
pub fn requireClosedWithExternal(joined: *const Joined, hashes: [N_HASHES]Q, external_sum: Q) !void {
    if (joined.claims.n_components != joined.statement.n_components or joined.claims.n_infra != joined.statement.n_infra) return error.InvalidInteractionClaim;
    var total = (try joined.publicCompensation()).add(external_sum);
    for (joined.statement.component_descs[0..joined.statement.n_components], 0..) |desc, i| total = total.add(try joined.claims.opcodeClaimTotal(desc.family, i));
    for (joined.statement.infra_descs[0..joined.statement.n_infra], 0..) |desc, i| total = total.add(try joined.claims.infraClaimTotal(desc.kind, i));
    for (hashes) |claim| total = total.add(claim);
    if (!total.isZero()) return error.UnclosedExecutionRelations;
}
