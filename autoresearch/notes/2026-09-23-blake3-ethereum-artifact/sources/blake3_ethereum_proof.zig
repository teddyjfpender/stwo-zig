//! Full-width BLAKE3 Ethereum proof with independent caller-owned key admission.
//! Explicit API with bounded artifacts and successful-verification capture.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const suite = core.proof_suites.Blake3;
const Q = core.fields.qm31.QM31;
const Column = engine.pcs.ColumnEvaluation;
const native_mod = @import("../air/statement.zig");
const protocol = @import("blake3_ethereum_protocol.zig");
const base_protocol = @import("blake3_execution_protocol.zig");
const execution = @import("blake3_execution_proof.zig");
const Joined = @import("blake3_execution_components.zig").Owner;
const Witness = @import("blake3_ethereum_witness.zig").Owner;
const universal = @import("../recursion/air/universal_challenges.zig");
const shared = @import("../recursion/air/universal_provider_relations.zig");
const transcript = @import("guest_precompile/ethereum_transcript.zig");
const Assembly = @import("guest_precompile/ethereum_assembly.zig").Assembly;
const ExtensionClaim = @import("guest_precompile/ethereum_types.zig").ExtensionClaim;
const N_HASHES = @import("blake3_commitment_components.zig").Airs.len;
pub const Proof = struct {
    stark: suite.Proof,
    key_id: [32]u8,
    native_claims: *native_mod.RiscVInteractionClaim,
    hash_claims: [N_HASHES]Q,
    extension_claims: ExtensionClaim,
    pub fn deinit(self: *Proof, a: std.mem.Allocator) void {
        self.stark.deinit(a);
        a.destroy(self.native_claims);
        self.* = undefined;
    }
};
pub const Verified = @import("blake3_ethereum_capture.zig").Verified;
pub const codec = @import("blake3_ethereum_codec.zig");
pub const Proved = struct { proof: Proof, transcript_digest: [32]u8 };
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        pub const PreparedVerifier = @import("blake3_ethereum_prepared.zig").ForBackend(Backend);
        const Scheme = engine.pcs.CommitmentSchemeProver(Backend, suite.Hasher, suite.MerkleChannel);
        const Verifier = core.pcs.verifier.CommitmentSchemeVerifier(suite.Hasher, suite.MerkleChannel);
        /// Owner is single-use after interaction generation. Prepared admission
        /// is reusable and must come from independently selected source inputs.
        pub fn prove(a: std.mem.Allocator, owner: *Witness, prepared: *PreparedVerifier, expected: [32]u8, pool: *engine.work_pool.WorkPool) !Proved {
            try prepared.validate(expected);
            const native = owner.native;
            const hashes = owner.hashes;
            const pin = try owner.admission();
            if (!native.tables_ready or native.failed or native.interaction_ready) return error.InvalidExecutionPhase;
            const actual = try protocol.identity(prepared.config, &native.statement, &owner.statement, pin, hashes.logs, prepared.root);
            if (!std.mem.eql(u8, &actual, &expected) or !std.mem.eql(u8, &hashes.plan_id, &pin.expected_id)) return error.UntrustedExecutionKey;
            var arena = std.heap.ArenaAllocator.init(a);
            defer arena.deinit();
            const scratch = arena.allocator();
            var channel = suite.Channel{};
            try protocol.mix(&channel, prepared.config, &native.statement, &owner.statement, pin, hashes.logs);
            var scheme = try Scheme.init(a, prepared.config);
            var owns_scheme = true;
            defer if (owns_scheme) scheme.deinit(a);
            var columns: std.ArrayList(Column) = .empty;
            try columns.appendSlice(scratch, native.preprocessed.items);
            try columns.appendSlice(scratch, hashes.preprocessed());
            try columns.appendSlice(scratch, try @import("guest_precompile/ethereum_preprocessed.zig").generateExtension(scratch, &owner.statement));
            try scheme.commit(a, columns.items, &channel);
            var roots = try scheme.roots(a);
            defer roots.deinit(a);
            try execution.admitPreprocessedRoot(prepared.root, roots.items[0]);
            var main = try @import("guest_precompile/ethereum_main_columns.zig").generate(a, &owner.extension);
            defer main.deinit(a);
            columns.clearRetainingCapacity();
            try columns.appendSlice(scratch, native.main.items);
            try columns.appendSlice(scratch, try hashes.main());
            try columns.appendSlice(scratch, main.columns);
            try scheme.commit(a, columns.items, &channel);
            const relations = try universal.UniversalRelations.draw(a, &channel);
            const providers = try shared.SharedProviderRelations.init(&relations);
            const extension_relations = try transcript.Relations.drawAfterBase(a, &channel, providers.native);
            try native.generateInteractions(&providers.native);
            var hash_interaction = try hashes.interactions(a, &relations);
            defer hash_interaction.deinit();
            var extension = try @import("guest_precompile/ethereum_interaction.zig").generate(a, &owner.extension, &extension_relations, pool);
            defer extension.deinit(a);
            const joined = try Joined.initWithExternal(a, &native.statement, &native.claims, relations, pin, owner.statement.counts.external_retirements);
            defer joined.deinit();
            try joined.bindCommitments(hashes, hash_interaction.claims);
            try execution.requireClosedWithExternal(joined, hash_interaction.claims, extension.claim.componentSum());
            try mixClaims(&channel, &native.statement, &native.claims, &hash_interaction.claims, &extension.claim);
            columns.clearRetainingCapacity();
            try columns.appendSlice(scratch, native.interaction.items);
            try columns.appendSlice(scratch, hash_interaction.columns.items);
            try columns.appendSlice(scratch, extension.columns);
            try scheme.commit(a, columns.items, &channel);
            var prefix: std.ArrayList(engine.air.component_prover.ComponentProver) = .empty;
            try prefix.appendSlice(scratch, joined.proving.components.active());
            try prefix.appendSlice(scratch, &(try hashes.provers()));
            const components = try Assembly(.prover).createBlake3(a, &native.statement, &owner.statement, pin, hashes.logs, &extension_relations, prefix.items, &extension.claim);
            defer components.destroy(a);
            const claims = try a.create(native_mod.RiscVInteractionClaim);
            errdefer a.destroy(claims);
            claims.* = native.claims;
            owns_scheme = false;
            const stark = try engine.prove.prove(Backend, suite.Hasher, suite.MerkleChannel, a, components.active(), &channel, scheme);
            return .{ .proof = .{ .stark = stark, .key_id = expected, .native_claims = claims, .hash_claims = hash_interaction.claims, .extension_claims = extension.claim }, .transcript_digest = channel.digestBytes() };
        }
        /// Consumes proof on every path. No received claim selects its own key.
        pub fn verifyOwned(a: std.mem.Allocator, received: Proof, prepared: *PreparedVerifier, expected: [32]u8) ![32]u8 {
            return verifyInternal(false, a, received, prepared, expected);
        }
        pub fn verifyCaptureOwned(a: std.mem.Allocator, received: Proof, prepared: *PreparedVerifier, expected: [32]u8) !Verified {
            return verifyInternal(true, a, received, prepared, expected);
        }
        fn verifyInternal(comptime capture_mode: bool, a: std.mem.Allocator, received: Proof, prepared: *PreparedVerifier, expected: [32]u8) !(if (capture_mode) Verified else [32]u8) {
            var proof = received;
            var owns_claims = true;
            defer if (owns_claims) a.destroy(proof.native_claims);
            var owns_stark = true;
            defer if (owns_stark) proof.stark.deinit(a);
            try prepared.validate(expected);
            if (!std.mem.eql(u8, &proof.key_id, &expected)) return error.UntrustedExecutionKey;
            if (!std.meta.eql(proof.stark.commitment_scheme_proof.config, prepared.config) or proof.stark.commitment_scheme_proof.commitments.items.len != 4) return error.InvalidExecutionProof;
            try proof.extension_claims.validateCanonicalFields();
            try proof.extension_claims.validate(&prepared.extension);
            try execution.admitPreprocessedRoot(prepared.root, proof.stark.commitment_scheme_proof.commitments.items[0]);
            var arena = std.heap.ArenaAllocator.init(a);
            defer arena.deinit();
            const scratch = arena.allocator();
            const pin = prepared.admission();
            const hashes = prepared.hashes.?;
            var channel = suite.Channel{};
            try protocol.mix(&channel, prepared.config, &prepared.native, &prepared.extension, pin, hashes.logs);
            var verifier = try Verifier.init(a, prepared.config);
            defer verifier.deinit(a);
            try verifier.commit(a, prepared.root, prepared.logs[0], &channel);
            try verifier.commit(a, proof.stark.commitment_scheme_proof.commitments.items[1], prepared.logs[1], &channel);
            const relations = try universal.UniversalRelations.draw(a, &channel);
            const providers = try shared.SharedProviderRelations.init(&relations);
            const extension_relations = try transcript.Relations.drawAfterBase(a, &channel, providers.native);
            const joined = try Joined.initWithExternal(a, &prepared.native, proof.native_claims, relations, pin, prepared.extension.counts.external_retirements);
            defer joined.deinit();
            try joined.bindCommitments(hashes, proof.hash_claims);
            try execution.requireClosedWithExternal(joined, proof.hash_claims, proof.extension_claims.componentSum());
            try mixClaims(&channel, &prepared.native, proof.native_claims, &proof.hash_claims, &proof.extension_claims);
            try verifier.commit(a, proof.stark.commitment_scheme_proof.commitments.items[2], prepared.logs[2], &channel);
            var prefix: std.ArrayList(core.air.components.Component) = .empty;
            try prefix.appendSlice(scratch, joined.verifying.components.active());
            try prefix.appendSlice(scratch, &(try hashes.verifiers()));
            const components = try Assembly(.verifier).createBlake3(a, &prepared.native, &prepared.extension, pin, hashes.logs, &extension_relations, prefix.items, &proof.extension_claims);
            defer components.destroy(a);
            owns_stark = false;
            if (capture_mode) {
                var capture: core.verifier.ProofCapture(suite.Hasher) = undefined;
                try core.verifier.verifyWithProofCapture(suite.Hasher, suite.MerkleChannel, a, components.active(), &channel, &verifier, proof.stark, &capture);
                errdefer capture.deinit(a);
                var result = Verified{ .allocator = a, .key_id = expected, .proof = capture, .native_claims = proof.native_claims, .hash_claims = proof.hash_claims, .extension_claims = proof.extension_claims, .relations = relations, .extension_draws = extension_relations.draws(), .extension_placements = components.extensionPlacements(), .final_channel = channel, .seal = undefined };
                result.seal = try result.identity(&prepared.native);
                owns_claims = false;
                return result;
            }
            try core.verifier.verify(suite.Hasher, suite.MerkleChannel, a, components.active(), &channel, &verifier, proof.stark);
            return channel.digestBytes();
        }
    };
}
fn mixClaims(channel: anytype, shape: *const native_mod.Blake3ExecutionStatement, claims: *const native_mod.RiscVInteractionClaim, hashes: []const Q, extension: *const ExtensionClaim) !void {
    try base_protocol.mixClaims(channel, shape, claims, hashes);
    extension.mixInto(channel);
}
