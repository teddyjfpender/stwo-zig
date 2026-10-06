//! Fail-closed transaction kernel for the direct 47-row V3 leaf wrapper.
//!
//! The first 39 rows verify the native SegmentV2 proof in this transaction;
//! no separate 39-row outer proof or PFD1 digest is admitted. A concrete
//! direct cohort and full 47-domain closure are required for activation.
const std = @import("std");
const core = @import("stwo_core");
const postcard = @import("interop_postcard");
const prover_engine = @import("stwo_prover_engine");
const engine_mod = @import("engine.zig");
const storage = @import("transaction_storage_v2.zig");
const universal = @import("air/universal_challenges.zig");
const shared_provider = @import("air/universal_shared_provider.zig");
const identity_mod = @import("canonical_proof_identity_v1.zig");
const channel_mod = @import("poseidon2_channel.zig");
const verifier_tree = @import("verifier_tree.zig");
const Geometry = @import("air/segment_leaf_wrapper_roster_direct_v4.zig");
const Protocol = @import("segment_leaf_wrapper_protocol_direct_v4.zig");
const admission = @import("segment_leaf_wrapper_direct_admission_v4.zig");

pub const FORMAT_VERSION: u16 = 4;
pub const WRAPPER_PROOF_AVAILABLE = false;
pub const PRODUCTION_PROOF_ACTIVATION = false;
pub const REQUIRED_COMPONENT_COUNT: usize = 47;
pub const REQUIRED_DOMAIN_COUNT: usize = 47;

/// `Contract` supplies the concrete native-verifier cohort and proof gate.
/// PlanV4 and its VPR5/VPK5 key namespace are pinned by this module, never
/// selected by a prover or artifact. The cohort must derive native child
/// authority from a fresh verified SegmentV2 proof, not supplied metadata.
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        pub const Engine = engine_mod.ProverEngineForBackend(Backend);
        pub const VerifierScheme = core.pcs.verifier.CommitmentSchemeVerifier(
            engine_mod.Hasher,
            engine_mod.MerkleChannel,
        );
        pub const Capture = core.pcs.verifier.VerifiedProofCapture(engine_mod.Hasher);

        pub fn EngineKernel(comptime Contract: type) type {
            const Cohort = Contract.Cohort;
            const TreeStorage = storage.TreeStorageForManifest(Engine, Geometry);

            comptime {
                if (Geometry.COMPONENT_COUNT != REQUIRED_COMPONENT_COUNT or
                    Geometry.TREE_COUNT != 3 or
                    Contract.DOMAIN_COUNT != REQUIRED_DOMAIN_COUNT)
                    @compileError("direct V3 wrapper kernel requires 47 committed rows and all 47 closure domains");
                if (WRAPPER_PROOF_AVAILABLE and (!@hasDecl(Contract, "QUALIFIED") or !Contract.QUALIFIED))
                    @compileError("V3 wrapper transaction requires a qualified concrete cohort");
            }

            return struct {
                pub const Artifact = struct {
                    format_version: u16 = FORMAT_VERSION,
                    query_count: u32 = @intCast(Protocol.PCS_CONFIG.fri_config.n_queries),
                    pcs_pow_bits: u32 = Protocol.PCS_CONFIG.pow_bits,
                    fold_step: u32 = Protocol.PCS_CONFIG.fri_config.fold_step,
                    interaction_pow_bits: u32 = Protocol.INTERACTION_POW_BITS,
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
                            self.query_count != Protocol.PCS_CONFIG.fri_config.n_queries or
                            self.pcs_pow_bits != Protocol.PCS_CONFIG.pow_bits or
                            self.fold_step != Protocol.PCS_CONFIG.fri_config.fold_step or
                            self.interaction_pow_bits != Protocol.INTERACTION_POW_BITS or
                            self.proof_bytes.len == 0)
                            return error.InvalidV3WrapperArtifact;
                        const identity = try identity_mod.CanonicalProofIdentityV1.fromBytes(self.proof_bytes);
                        if (!std.meta.eql(identity.proof_id, self.proof_id) or
                            !std.meta.eql(identity.canonical_proof_sha_id, self.proof_sha256))
                            return error.InvalidV3WrapperArtifact;
                    }
                };

                pub const Receipt = struct {
                    prover_ns: u64,
                    fresh_verifier_ns: u64,
                    transaction_ns: u64,
                    producer_peak_bytes: usize,
                    proof_bytes: usize,
                    transcript_draws: usize,
                };

                pub const Verified = struct {
                    artifact: Artifact,
                    capture: Capture,
                    receipt: Receipt,

                    pub fn deinit(self: *Verified, allocator: std.mem.Allocator) void {
                        self.capture.deinit(allocator);
                        self.artifact.deinit(allocator);
                        self.* = undefined;
                    }
                };

                pub fn proveAndVerify(
                    allocator: std.mem.Allocator,
                    expected_native: admission.ExpectedNative,
                    authority_inputs: Cohort.AuthorityInputs,
                ) !Verified {
                    if (comptime !WRAPPER_PROOF_AVAILABLE) {
                        return error.V3WrapperProofUnavailable;
                    } else return proveAndVerifyReady(allocator, expected_native, authority_inputs);
                }

                /// No detached artifact can bypass the same activation gate.
                pub fn verifyArtifact(
                    allocator: std.mem.Allocator,
                    expected_native: admission.ExpectedNative,
                    authority_inputs: Cohort.AuthorityInputs,
                    artifact: *const Artifact,
                    capture_out: *Capture,
                ) !void {
                    if (comptime !WRAPPER_PROOF_AVAILABLE) {
                        return error.V3WrapperProofUnavailable;
                    } else return verifyArtifactReady(allocator, expected_native, authority_inputs, artifact, capture_out);
                }

                const Proved = struct {
                    proof: engine_mod.Proof,
                    preprocessed_root: channel_mod.Digest,
                    interaction_pow_nonce: u64,
                    transcript_draws: usize,
                };

                fn proveAndVerifyReady(
                    allocator: std.mem.Allocator,
                    expected_native: admission.ExpectedNative,
                    authority_inputs: Cohort.AuthorityInputs,
                ) !Verified {
                    var timer = try std.time.Timer.start();
                    var producer_memory = prover_engine.tracked_smp_allocator.TrackedSmpAllocator{};
                    defer std.debug.assert(producer_memory.isEmpty());
                    const producer_allocator = producer_memory.allocator();
                    var producer = try Cohort.init(producer_allocator, authority_inputs);
                    var producer_owned = true;
                    defer if (producer_owned) producer.deinit();
                    // Both checks must derive from an externally admitted
                    // SegmentV2 proof and the pinned compiler, never a plan
                    // or field snapshot supplied by the proof producer.
                    try producer.requireFreshNativeChild();
                    try producer.validatePlanSource();
                    try admission.requireExpectedNative(expected_native, producer.nativeIdentity());
                    const plan = producer.plan();
                    try plan.validate();
                    const profile_id = try Protocol.protocolId(plan);
                    const manifest_seal = plan.seal;

                    var phase = try std.time.Timer.start();
                    var proved = try prove(producer_allocator, &producer);
                    var proof_owned = true;
                    defer if (proof_owned) proved.proof.deinit(producer_allocator);
                    const prover_ns = phase.read();
                    var encoded: std.ArrayList(u8) = .empty;
                    defer encoded.deinit(allocator);
                    try postcard.serializeProof(engine_mod.Hasher, encoded.writer(allocator), proved.proof);
                    const proof_bytes = try encoded.toOwnedSlice(allocator);
                    errdefer allocator.free(proof_bytes);
                    const identity = try identity_mod.CanonicalProofIdentityV1.fromBytes(proof_bytes);
                    const key_id = try Protocol.verificationKeyId(plan, proved.preprocessed_root);

                    proved.proof.deinit(producer_allocator);
                    proof_owned = false;
                    producer.deinit();
                    producer_owned = false;
                    try producer_memory.requireEmpty();
                    const artifact = Artifact{
                        .profile_id = profile_id,
                        .verification_key_id = key_id,
                        .manifest_seal = manifest_seal,
                        .preprocessed_root = proved.preprocessed_root,
                        .interaction_pow_nonce = proved.interaction_pow_nonce,
                        .proof_id = identity.proof_id,
                        .proof_sha256 = identity.canonical_proof_sha_id,
                        .proof_bytes = proof_bytes,
                    };
                    phase.reset();
                    var capture: Capture = undefined;
                    try verifyArtifactReady(allocator, expected_native, authority_inputs, &artifact, &capture);
                    errdefer capture.deinit(allocator);
                    return .{
                        .artifact = artifact,
                        .capture = capture,
                        .receipt = .{
                            .prover_ns = prover_ns,
                            .fresh_verifier_ns = phase.read(),
                            .transaction_ns = timer.read(),
                            .producer_peak_bytes = producer_memory.peakBytes(),
                            .proof_bytes = proof_bytes.len,
                            .transcript_draws = proved.transcript_draws,
                        },
                    };
                }

                fn prove(allocator: std.mem.Allocator, cohort: *Cohort) !Proved {
                    const plan = cohort.plan();
                    try plan.validate();
                    const geometry = plan;
                    try geometry.validate();
                    var scheme = try Engine.init(allocator, Protocol.PCS_CONFIG);
                    var scheme_moved = false;
                    defer if (!scheme_moved) Engine.deinit(&scheme, allocator);
                    var channel = Engine.Channel{};
                    var preprocessed = try TreeStorage.init(allocator, geometry, Geometry.PREPROCESSED_TREE_INDEX);
                    defer preprocessed.deinit();
                    try cohort.fillPreprocessedInto(geometry, preprocessed.columns);
                    try preprocessed.commit(&scheme, &channel);
                    try Engine.flushPendingCommit(&scheme, allocator, &channel);
                    var roots = try scheme.roots(allocator);
                    defer roots.deinit(allocator);
                    if (roots.items.len != 1) return error.InvalidV3WrapperProofShape;
                    const preprocessed_root = roots.items[0];

                    var main = try TreeStorage.init(allocator, geometry, Geometry.MAIN_TREE_INDEX);
                    defer main.deinit();
                    try cohort.fillMainInto(geometry, main.columns);
                    try main.commit(&scheme, &channel);
                    try Engine.flushPendingCommit(&scheme, allocator, &channel);
                    try plan.mixGeometryPrefix(&channel);
                    try cohort.mixAuthority(&channel);
                    const nonce = channel.grind(Protocol.INTERACTION_POW_BITS);
                    channel.mixU64(nonce);
                    const relations = try universal.UniversalRelations.draw(allocator, &channel);
                    const provider_relations = try shared_provider.SharedProviderRelations.init(&relations);
                    var interaction = try TreeStorage.init(allocator, geometry, Geometry.INTERACTION_TREE_INDEX);
                    defer interaction.deinit();
                    const generated = try cohort.fillInteractionInto(geometry, &relations, &provider_relations, interaction.columns);
                    var claims = try cohort.claimVector(&generated);
                    try Contract.auditCompleteClosure(cohort, &generated, &claims, &relations, &provider_relations);
                    try claims.mixInteractionClaims(geometry, &channel);
                    try cohort.mixPublicWireBoundary(&channel, &relations);
                    try interaction.commit(&scheme, &channel);
                    var components = try cohort.initComponents(&generated, &relations, &provider_relations);
                    defer components.deinit();
                    var gate = try Contract.ProofGate.init(geometry);
                    try components.appendToGate(geometry, &gate);
                    try gate.sealGate(geometry);
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

                fn verifyArtifactReady(
                    allocator: std.mem.Allocator,
                    expected_native: admission.ExpectedNative,
                    authority_inputs: Cohort.AuthorityInputs,
                    artifact: *const Artifact,
                    capture_out: *Capture,
                ) !void {
                    try artifact.validateEncoding();
                    var cohort = try Cohort.init(allocator, authority_inputs);
                    defer cohort.deinit();
                    try cohort.requireFreshNativeChild();
                    try cohort.validatePlanSource();
                    const plan = cohort.plan();
                    try plan.validate();
                    const geometry = plan;
                    try geometry.validate();
                    const independently_recomputed_root = try recomputePreprocessedRoot(allocator, &cohort);
                    const binding = try admission.IndependentBinding.fromVerifiedSources(
                        plan,
                        expected_native,
                        independently_recomputed_root,
                    );
                    try admission.admit(expected_native, cohort.nativeIdentity(), binding, artifact);
                    var stream = std.io.fixedBufferStream(artifact.proof_bytes);
                    var proof = try postcard.deserializeProof(engine_mod.Hasher, allocator, stream.reader());
                    var proof_owned = true;
                    defer if (proof_owned) proof.deinit(allocator);
                    if (stream.pos != artifact.proof_bytes.len or
                        !std.meta.eql(proof.commitment_scheme_proof.config, Protocol.PCS_CONFIG))
                        return error.InvalidV3WrapperProofShape;
                    const commitments = proof.commitment_scheme_proof.commitments.items;
                    if (commitments.len != Geometry.TREE_COUNT + 1 or
                        !std.meta.eql(commitments[Geometry.PREPROCESSED_TREE_INDEX], artifact.preprocessed_root))
                        return error.InvalidV3WrapperProofShape;

                    var scheme = try VerifierScheme.init(allocator, Protocol.PCS_CONFIG);
                    defer scheme.deinit(allocator);
                    var channel = Engine.Channel{};
                    try verifier_tree.commitVerifierTreeForManifest(Geometry, allocator, &scheme, geometry, Geometry.PREPROCESSED_TREE_INDEX, commitments[Geometry.PREPROCESSED_TREE_INDEX], &channel);
                    try verifier_tree.commitVerifierTreeForManifest(Geometry, allocator, &scheme, geometry, Geometry.MAIN_TREE_INDEX, commitments[Geometry.MAIN_TREE_INDEX], &channel);
                    try plan.mixGeometryPrefix(&channel);
                    try cohort.mixAuthority(&channel);
                    if (!channel.verifyPowNonce(Protocol.INTERACTION_POW_BITS, artifact.interaction_pow_nonce))
                        return error.InvalidV3WrapperInteractionPow;
                    channel.mixU64(artifact.interaction_pow_nonce);
                    const relations = try universal.UniversalRelations.draw(allocator, &channel);
                    const provider_relations = try shared_provider.SharedProviderRelations.init(&relations);
                    const generated = try cohort.rebuildGeneratedInteractions(&relations, &provider_relations);
                    var claims = try cohort.claimVector(&generated);
                    try Contract.auditCompleteClosure(&cohort, &generated, &claims, &relations, &provider_relations);
                    try claims.mixInteractionClaims(geometry, &channel);
                    try cohort.mixPublicWireBoundary(&channel, &relations);
                    try verifier_tree.commitVerifierTreeForManifest(Geometry, allocator, &scheme, geometry, Geometry.INTERACTION_TREE_INDEX, commitments[Geometry.INTERACTION_TREE_INDEX], &channel);
                    const components = try cohort.initVerifierComponents(&relations, &claims, generated.core.poseidon2_partials);
                    defer components.deinit();
                    const proof_for_verifier = verifier_tree.moveOwnedForVerifier(engine_mod.Proof, &proof, &proof_owned);
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
                    capture_out.* = capture;
                }

                fn recomputePreprocessedRoot(
                    allocator: std.mem.Allocator,
                    cohort: *Cohort,
                ) !channel_mod.Digest {
                    const plan = cohort.plan();
                    const geometry = plan;
                    var scheme = try Engine.init(allocator, Protocol.PCS_CONFIG);
                    defer Engine.deinit(&scheme, allocator);
                    var channel = Engine.Channel{};
                    var tree = try TreeStorage.init(allocator, geometry, Geometry.PREPROCESSED_TREE_INDEX);
                    defer tree.deinit();
                    try cohort.fillPreprocessedInto(geometry, tree.columns);
                    try tree.commit(&scheme, &channel);
                    try Engine.flushPendingCommit(&scheme, allocator, &channel);
                    var roots = try scheme.roots(allocator);
                    defer roots.deinit(allocator);
                    if (roots.items.len != 1)
                        return error.V3WrapperPreprocessedRootMismatch;
                    return roots.items[0];
                }
            };
        }
    };
}

comptime {
    if (WRAPPER_PROOF_AVAILABLE or PRODUCTION_PROOF_ACTIVATION)
        @compileError("direct V3 wrapper kernel requires a concrete qualified cohort before activation");
}

test "direct V3 wrapper kernel rejects fake cohort and detached artifact before activation" {
    const CpuBackend = struct {};
    const Fake = struct {
        pub const Cohort = struct {
            pub const AuthorityInputs = struct {};
        };
        pub const DOMAIN_COUNT = REQUIRED_DOMAIN_COUNT;
    };
    const Kernel = ForBackend(CpuBackend).EngineKernel(Fake);
    const expected = admission.ExpectedNative{ .program_identity = .{0} ** 8, .tree0_root = .{0} ** 8 };
    try std.testing.expectError(error.V3WrapperProofUnavailable, Kernel.proveAndVerify(std.testing.allocator, expected, .{}));
    var artifact: Kernel.Artifact = undefined;
    var capture: ForBackend(CpuBackend).Capture = undefined;
    try std.testing.expectError(
        error.V3WrapperProofUnavailable,
        Kernel.verifyArtifact(std.testing.allocator, expected, .{}, &artifact, &capture),
    );
}
