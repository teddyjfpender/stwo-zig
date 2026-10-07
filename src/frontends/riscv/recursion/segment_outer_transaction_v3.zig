//! Strong-profile 39-row outer child, separate from the V2 development proof.
//!
//! This transaction proves with q193/PCS-PoW16/fold4 and grinds a 10-bit
//! interaction nonce before any relation draw. A fresh verifier decodes the
//! canonical proof, recomputes the immutable key and exact 47-domain closure,
//! and verifies the STARK. It does not mint a V2 publication: those receipts
//! deliberately encode the old q3/zero-PoW profile and nonce zero.

pub fn ForBackend(comptime Backend: type) type {
    return struct {
        const std = @import("std");
        const core = @import("stwo_core");
        const postcard = @import("interop_postcard");
        const prover_engine = @import("stwo_prover_engine");
        const engine_mod = @import("engine.zig");
        const manifest_mod = @import("air/segment_outer_adapter_manifest_v2.zig");
        const universal = @import("air/universal_challenges.zig");
        const shared_provider = @import("air/universal_shared_provider.zig");
        const storage = @import("transaction_storage_v2.zig");
        const support = @import("segment_outer_transaction_support_v2.zig");
        const identity_mod = @import("canonical_proof_identity_v1.zig");
        const provider_field = @import("segment_outer_shared_provider_field_authority_v1.zig");
        const protocol = @import("segment_outer_protocol_v3.zig");
        const channel_mod = @import("poseidon2_channel.zig");
        const verifier_tree = @import("verifier_tree.zig");

        pub const Engine = engine_mod.ProverEngineForBackend(Backend);
        pub const VerifierScheme = core.pcs.verifier.CommitmentSchemeVerifier(
            engine_mod.Hasher,
            engine_mod.MerkleChannel,
        );
        pub const Capture = core.pcs.verifier.VerifiedProofCapture(engine_mod.Hasher);
        pub const TreeStorage = storage.TreeStorageFor(Engine);
        pub const PRODUCES_V2_PUBLICATION = false;
        pub const PRODUCTION_PROOF_ACTIVATION = false;
        pub const FORMAT_VERSION: u16 = 3;

        pub const Artifact = struct {
            format_version: u16 = FORMAT_VERSION,
            query_count: u32 = @intCast(protocol.PCS_CONFIG.fri_config.n_queries),
            pcs_pow_bits: u32 = protocol.PCS_CONFIG.pow_bits,
            fold_step: u32 = protocol.PCS_CONFIG.fri_config.fold_step,
            interaction_pow_bits: u32 = protocol.INTERACTION_POW_BITS,
            profile_id: channel_mod.Digest,
            verification_key_id: channel_mod.Digest,
            manifest_seal: [32]u8,
            preprocessed_root: channel_mod.Digest,
            interaction_pow_nonce: u64,
            proof_id: channel_mod.Digest,
            proof_sha256: [32]u8,
            proof_bytes: []u8,

            pub fn deinit(self: *Artifact, allocator: std.mem.Allocator) void {
                allocator.free(self.proof_bytes);
                self.* = undefined;
            }

            pub fn validateEncoding(self: *const Artifact) !void {
                if (self.format_version != FORMAT_VERSION or
                    self.query_count != protocol.PCS_CONFIG.fri_config.n_queries or
                    self.pcs_pow_bits != protocol.PCS_CONFIG.pow_bits or
                    self.fold_step != protocol.PCS_CONFIG.fri_config.fold_step or
                    self.interaction_pow_bits != protocol.INTERACTION_POW_BITS or
                    self.proof_bytes.len == 0)
                    return error.InvalidV3OuterArtifact;
                const actual = try identity_mod.CanonicalProofIdentityV1.fromBytes(self.proof_bytes);
                if (!std.meta.eql(actual.proof_id, self.proof_id) or
                    !std.meta.eql(actual.canonical_proof_sha_id, self.proof_sha256))
                    return error.InvalidV3OuterArtifact;
            }
        };

        /// Nested phase timings permit cold setup and the actual proof/verifier
        /// cost to be compared without charging the verifier to the prover.
        pub const Receipt = struct {
            format_version: u16 = FORMAT_VERSION,
            producer_prepare_ns: u64,
            prover_ns: u64,
            serialize_ns: u64,
            producer_destroy_ns: u64,
            fresh_verifier_ns: u64,
            transaction_ns: u64,
            producer_peak_bytes: usize,
            producer_live_bytes_after_destroy: usize,
            proof_bytes: usize,
            transcript_draws: usize,

            pub fn validate(self: Receipt) !void {
                if (self.format_version != FORMAT_VERSION or self.proof_bytes == 0 or
                    self.producer_live_bytes_after_destroy != 0)
                    return error.InvalidV3OuterReceipt;
            }
        };

        /// Host-side field preparation minted only after fresh verification of
        /// this strong child. The future 49-row wrapper must prove these words
        /// came from its verifier rows; this value alone is not recursive AIR.
        pub const FieldSnapshotV3 = struct {
            manifest_seal: [32]u8,
            profile_id: channel_mod.Digest,
            verification_key_id: channel_mod.Digest,
            preprocessed_root: channel_mod.Digest,
            proof_id: channel_mod.Digest,
            claims: manifest_mod.ClaimVector,
            relations: universal.UniversalRelations,
            poseidon2_partials: [2]core.fields.qm31.QM31,
            provider: provider_field.AuthorityV1,

            pub fn deinit(self: *FieldSnapshotV3) void {
                self.provider.deinit();
                self.* = undefined;
            }

            pub fn validateAgainst(
                self: *const FieldSnapshotV3,
                manifest: *const manifest_mod.Manifest,
                artifact: *const Artifact,
            ) !void {
                try manifest.validate();
                try self.claims.validate(manifest);
                try self.relations.validate();
                if (!std.meta.eql(self.manifest_seal, manifest.seal) or
                    !std.meta.eql(self.profile_id, artifact.profile_id) or
                    !std.meta.eql(self.verification_key_id, artifact.verification_key_id) or
                    !std.meta.eql(self.preprocessed_root, artifact.preprocessed_root) or
                    !std.meta.eql(self.proof_id, artifact.proof_id))
                    return error.InvalidV3OuterFieldSnapshot;
                try self.provider.validateAgainst(
                    manifest,
                    &self.claims,
                    &self.relations,
                    self.poseidon2_partials,
                );
            }
        };

        pub const Verified = struct {
            artifact: Artifact,
            capture: Capture,
            field_snapshot: FieldSnapshotV3,
            receipt: Receipt,

            pub fn deinit(self: *Verified, allocator: std.mem.Allocator) void {
                self.field_snapshot.deinit();
                self.capture.deinit(allocator);
                self.artifact.deinit(allocator);
                self.* = undefined;
            }
        };

        pub fn EngineKernel(comptime Cohort: type) type {
            assertCohort(Cohort);
            return struct {
                pub fn proveAndVerify(
                    allocator: std.mem.Allocator,
                    authority_inputs: Cohort.AuthorityInputs,
                ) !Verified {
                    var timer = try std.time.Timer.start();
                    var producer_memory = prover_engine.tracked_smp_allocator.TrackedSmpAllocator{};
                    defer std.debug.assert(producer_memory.isEmpty());
                    const producer_allocator = producer_memory.allocator();

                    var phase = try std.time.Timer.start();
                    var prover = try Cohort.init(producer_allocator, authority_inputs);
                    var prover_owned = true;
                    defer if (prover_owned) prover.deinit();
                    const manifest = prover.manifest();
                    try manifest.validate();
                    const profile_id = try protocol.protocolId(manifest);
                    const manifest_seal = manifest.seal;
                    const producer_prepare_ns = phase.read();

                    phase.reset();
                    var proved = try prove(producer_allocator, &prover);
                    var proof_owned = true;
                    defer if (proof_owned) proved.proof.deinit(producer_allocator);
                    const prover_ns = phase.read();

                    phase.reset();
                    var encoded: std.ArrayList(u8) = .empty;
                    defer encoded.deinit(allocator);
                    try postcard.serializeProof(engine_mod.Hasher, encoded.writer(allocator), proved.proof);
                    const proof_bytes = try encoded.toOwnedSlice(allocator);
                    errdefer allocator.free(proof_bytes);
                    const proof_identity = try identity_mod.CanonicalProofIdentityV1.fromBytes(proof_bytes);
                    const verification_key_id = try protocol.verificationKeyId(
                        manifest,
                        proved.preprocessed_root,
                    );
                    const serialize_ns = phase.read();

                    phase.reset();
                    proved.proof.deinit(producer_allocator);
                    proof_owned = false;
                    prover.deinit();
                    prover_owned = false;
                    try producer_memory.requireEmpty();
                    const producer_destroy_ns = phase.read();

                    const artifact = Artifact{
                        .profile_id = profile_id,
                        .verification_key_id = verification_key_id,
                        .manifest_seal = manifest_seal,
                        .preprocessed_root = proved.preprocessed_root,
                        .interaction_pow_nonce = proved.interaction_pow_nonce,
                        .proof_id = proof_identity.proof_id,
                        .proof_sha256 = proof_identity.canonical_proof_sha_id,
                        .proof_bytes = proof_bytes,
                    };
                    phase.reset();
                    var capture: Capture = undefined;
                    var field_snapshot: FieldSnapshotV3 = undefined;
                    try verifyArtifactAndFields(
                        allocator,
                        authority_inputs,
                        &artifact,
                        &capture,
                        &field_snapshot,
                    );
                    errdefer capture.deinit(allocator);
                    errdefer field_snapshot.deinit();
                    const fresh_verifier_ns = phase.read();
                    const receipt = Receipt{
                        .producer_prepare_ns = producer_prepare_ns,
                        .prover_ns = prover_ns,
                        .serialize_ns = serialize_ns,
                        .producer_destroy_ns = producer_destroy_ns,
                        .fresh_verifier_ns = fresh_verifier_ns,
                        .transaction_ns = timer.read(),
                        .producer_peak_bytes = producer_memory.peakBytes(),
                        .producer_live_bytes_after_destroy = producer_memory.snapshot().active_bytes,
                        .proof_bytes = proof_bytes.len,
                        .transcript_draws = proved.transcript_draws,
                    };
                    try receipt.validate();
                    return .{
                        .artifact = artifact,
                        .capture = capture,
                        .field_snapshot = field_snapshot,
                        .receipt = receipt,
                    };
                }

                const Proved = struct {
                    proof: engine_mod.Proof,
                    preprocessed_root: channel_mod.Digest,
                    interaction_pow_nonce: u64,
                    transcript_draws: usize,
                };

                fn prove(allocator: std.mem.Allocator, cohort: *Cohort) !Proved {
                    const manifest = cohort.manifest();
                    try manifest.validate();
                    var scheme = try Engine.init(allocator, protocol.PCS_CONFIG);
                    var scheme_moved = false;
                    defer if (!scheme_moved) Engine.deinit(&scheme, allocator);
                    var channel = Engine.Channel{};
                    var preprocessed = try TreeStorage.init(allocator, manifest, manifest_mod.PREPROCESSED_TREE_INDEX);
                    defer preprocessed.deinit();
                    try cohort.fillPreprocessedInto(manifest, preprocessed.columns);
                    try preprocessed.commit(&scheme, &channel);
                    try Engine.flushPendingCommit(&scheme, allocator, &channel);
                    var roots = try scheme.roots(allocator);
                    defer roots.deinit(allocator);
                    if (roots.items.len != 1) return error.InvalidV3OuterProofShape;
                    const preprocessed_root = roots.items[0];

                    var main = try TreeStorage.init(allocator, manifest, manifest_mod.MAIN_TREE_INDEX);
                    defer main.deinit();
                    try cohort.fillMainInto(manifest, main.columns);
                    try main.commit(&scheme, &channel);
                    try Engine.flushPendingCommit(&scheme, allocator, &channel);
                    try manifest.mixStatementPrefix(&channel);
                    try cohort.mixAuthority(&channel);
                    const nonce = channel.grind(protocol.INTERACTION_POW_BITS);
                    channel.mixU64(nonce);
                    const relations = try universal.UniversalRelations.draw(allocator, &channel);
                    const provider_relations = try shared_provider.SharedProviderRelations.init(&relations);
                    var interaction = try TreeStorage.init(allocator, manifest, manifest_mod.INTERACTION_TREE_INDEX);
                    defer interaction.deinit();
                    const generated = try cohort.fillInteractionInto(
                        manifest,
                        &relations,
                        &provider_relations,
                        interaction.columns,
                    );
                    var claims = try cohort.claimVector(&generated);
                    _ = try cohort.auditGlobalClosure(
                        &generated,
                        &claims,
                        &relations,
                        &provider_relations,
                    );
                    try claims.mixInteractionClaims(manifest, &channel);
                    try cohort.mixPublicWireBoundary(&channel, &relations);
                    try interaction.commit(&scheme, &channel);
                    var components = try cohort.initComponents(
                        &generated,
                        &relations,
                        &provider_relations,
                    );
                    defer components.deinit();
                    var gate = try manifest_mod.ProofGate.init(manifest);
                    try components.appendToGate(manifest, &gate);
                    try gate.sealGate(manifest);
                    scheme_moved = true;
                    var extended = try Engine.prove(allocator, try gate.proverSlice(), &channel, scheme, .{});
                    defer extended.aux.deinit(allocator);
                    const proof = extended.proof;
                    extended.proof = undefined;
                    return .{
                        .proof = proof,
                        .preprocessed_root = preprocessed_root,
                        .interaction_pow_nonce = nonce,
                        .transcript_draws = channel.n_draws,
                    };
                }

                /// The output is written only after all verifier checks pass.
                pub fn verifyArtifact(
                    allocator: std.mem.Allocator,
                    authority_inputs: Cohort.AuthorityInputs,
                    artifact: *const Artifact,
                    capture_out: *Capture,
                ) !void {
                    return verifyArtifactInternal(
                        allocator,
                        authority_inputs,
                        artifact,
                        capture_out,
                        null,
                    );
                }

                /// Freshly verifies one strong child and also returns the
                /// bounded field inputs needed by a future wrapper witness.
                pub fn verifyArtifactAndFields(
                    allocator: std.mem.Allocator,
                    authority_inputs: Cohort.AuthorityInputs,
                    artifact: *const Artifact,
                    capture_out: *Capture,
                    fields_out: *FieldSnapshotV3,
                ) !void {
                    return verifyArtifactInternal(
                        allocator,
                        authority_inputs,
                        artifact,
                        capture_out,
                        fields_out,
                    );
                }

                fn verifyArtifactInternal(
                    allocator: std.mem.Allocator,
                    authority_inputs: Cohort.AuthorityInputs,
                    artifact: *const Artifact,
                    capture_out: *Capture,
                    fields_out: ?*FieldSnapshotV3,
                ) !void {
                    try artifact.validateEncoding();
                    var cohort = try Cohort.init(allocator, authority_inputs);
                    defer cohort.deinit();
                    const manifest = cohort.manifest();
                    try manifest.validate();
                    if (!std.mem.eql(u8, &manifest.seal, &artifact.manifest_seal) or
                        !std.meta.eql(try protocol.protocolId(manifest), artifact.profile_id))
                        return error.InvalidV3OuterProfile;
                    if (!std.meta.eql(
                        try protocol.verificationKeyId(manifest, artifact.preprocessed_root),
                        artifact.verification_key_id,
                    )) return error.InvalidV3OuterKey;

                    var stream = std.io.fixedBufferStream(artifact.proof_bytes);
                    var proof = try postcard.deserializeProof(engine_mod.Hasher, allocator, stream.reader());
                    var proof_owned = true;
                    defer if (proof_owned) proof.deinit(allocator);
                    if (stream.pos != artifact.proof_bytes.len) return error.InvalidV3OuterProofShape;
                    // The STARK verifier uses the pinned configuration, while
                    // postcard also carries a configuration in the proof. Do
                    // not admit bytes that describe a different protocol.
                    if (!std.meta.eql(proof.commitment_scheme_proof.config, protocol.PCS_CONFIG))
                        return error.InvalidV3OuterProofShape;
                    const commitments = proof.commitment_scheme_proof.commitments.items;
                    if (commitments.len != manifest_mod.TREE_COUNT + 1 or
                        !std.meta.eql(commitments[manifest_mod.PREPROCESSED_TREE_INDEX], artifact.preprocessed_root))
                        return error.InvalidV3OuterProofShape;
                    try assertPreprocessedRoot(allocator, &cohort, artifact.preprocessed_root);

                    var scheme = try VerifierScheme.init(allocator, protocol.PCS_CONFIG);
                    defer scheme.deinit(allocator);
                    var channel = Engine.Channel{};
                    try support.commitVerifierTree(allocator, &scheme, manifest, manifest_mod.PREPROCESSED_TREE_INDEX, commitments[manifest_mod.PREPROCESSED_TREE_INDEX], &channel);
                    try support.commitVerifierTree(allocator, &scheme, manifest, manifest_mod.MAIN_TREE_INDEX, commitments[manifest_mod.MAIN_TREE_INDEX], &channel);
                    try manifest.mixStatementPrefix(&channel);
                    try cohort.mixAuthority(&channel);
                    if (!channel.verifyPowNonce(protocol.INTERACTION_POW_BITS, artifact.interaction_pow_nonce))
                        return error.InvalidV3OuterInteractionPow;
                    channel.mixU64(artifact.interaction_pow_nonce);
                    const relations = try universal.UniversalRelations.draw(allocator, &channel);
                    const provider_relations = try shared_provider.SharedProviderRelations.init(&relations);
                    const generated = try cohort.rebuildGeneratedInteractions(&relations, &provider_relations);
                    var claims = try cohort.claimVector(&generated);
                    _ = try cohort.auditGlobalClosure(
                        &generated,
                        &claims,
                        &relations,
                        &provider_relations,
                    );
                    try claims.mixInteractionClaims(manifest, &channel);
                    try cohort.mixPublicWireBoundary(&channel, &relations);
                    try support.commitVerifierTree(allocator, &scheme, manifest, manifest_mod.INTERACTION_TREE_INDEX, commitments[manifest_mod.INTERACTION_TREE_INDEX], &channel);
                    const components = try cohort.initVerifierComponents(
                        &relations,
                        &claims,
                        generated.core.poseidon2_partials,
                    );
                    defer components.deinit();
                    const proof_for_verifier = verifier_tree.moveOwnedForVerifier(
                        engine_mod.Proof,
                        &proof,
                        &proof_owned,
                    );
                    var capture: Capture = undefined;
                    try core.verifier.verifyWithProofCapture(
                        engine_mod.Hasher,
                        engine_mod.MerkleChannel,
                        allocator,
                        try components.verifierComponents(),
                        &channel,
                        &scheme,
                        proof_for_verifier,
                        &capture,
                    );
                    errdefer capture.deinit(allocator);
                    if (fields_out) |out| {
                        var provider = try provider_field.AuthorityV1.init(
                            allocator,
                            manifest,
                            &claims,
                            &relations,
                            generated.core.poseidon2_partials,
                        );
                        errdefer provider.deinit();
                        const fields = FieldSnapshotV3{
                            .manifest_seal = manifest.seal,
                            .profile_id = artifact.profile_id,
                            .verification_key_id = artifact.verification_key_id,
                            .preprocessed_root = artifact.preprocessed_root,
                            .proof_id = artifact.proof_id,
                            .claims = claims,
                            .relations = relations,
                            .poseidon2_partials = generated.core.poseidon2_partials,
                            .provider = provider,
                        };
                        try fields.validateAgainst(manifest, artifact);
                        out.* = fields;
                    }
                    capture_out.* = capture;
                }

                fn assertPreprocessedRoot(
                    allocator: std.mem.Allocator,
                    cohort: *Cohort,
                    actual: channel_mod.Digest,
                ) !void {
                    const manifest = cohort.manifest();
                    var scheme = try Engine.init(allocator, protocol.PCS_CONFIG);
                    defer Engine.deinit(&scheme, allocator);
                    var channel = Engine.Channel{};
                    var tree = try TreeStorage.init(allocator, manifest, manifest_mod.PREPROCESSED_TREE_INDEX);
                    defer tree.deinit();
                    try cohort.fillPreprocessedInto(manifest, tree.columns);
                    try tree.commit(&scheme, &channel);
                    try Engine.flushPendingCommit(&scheme, allocator, &channel);
                    var roots = try scheme.roots(allocator);
                    defer roots.deinit(allocator);
                    if (roots.items.len != 1 or !std.meta.eql(roots.items[0], actual))
                        return error.PreprocessedRootMismatch;
                }
            };
        }

        fn assertCohort(comptime Cohort: type) void {
            inline for (.{ "AuthorityInputs", "init", "deinit", "manifest", "fillPreprocessedInto", "fillMainInto", "fillInteractionInto", "mixAuthority", "mixPublicWireBoundary", "claimVector", "auditGlobalClosure", "initComponents", "initVerifierComponents", "rebuildGeneratedInteractions" }) |name|
                if (!@hasDecl(Cohort, name))
                    @compileError("V3 strong outer cohort lacks " ++ name);
        }
    };
}
