//! Verifier-custody bridge from one binary proof into the shared V3 graph ABI.
//!
//! No sampled value, claim, relation, statement, or provider partial is
//! accepted independently.  The bridge re-admits the append-only verifier
//! sidecar against its dynamic capture and frozen V2 publication, then joins
//! both to an independently initialized exact 36-row cohort.  The selected
//! binary program writes claims 0..35, canonical zeros 36..38, and the two
//! verifier-minted Poseidon partials at 39..40.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const artifact_mod = @import("recursive_binary_v3_verified_artifact.zig");

const QM31 = stwo_core.fields.qm31.QM31;
const recursion = frontend.recursion;
const protocol = recursion.protocol;
const pair_node = recursion.pair_node;
const universal = recursion.air.universal_challenges;
const manifest_mod = recursion.air.universal_adapter_manifest;
const composition_v3 = recursion.recursion_air_composition_circuit_v3;
const capture_layout_v3 = composition_v3.capture_layout_v3;

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 1;
pub const BRIDGE_ID_DOMAIN =
    "stwo-zig/recursive-binary-v3-composition-bridge/v1\x00";
pub const HEAP_ALLOCATIONS_PER_INIT: usize = capture_layout_v3.TREE_COUNT;
pub const HOT_HEAP_ALLOCATIONS: usize = 0;
pub const HEAP_ALLOCATIONS_PER_BEGIN_RECORDER: usize = 0;
pub const BINARY_SOURCE_CLAIM_COUNT: usize = artifact_mod.CLAIM_COUNT;
pub const COMPOSITION_CLAIM_COUNT: usize =
    composition_v3.COMPOSITION_CLAIM_INPUT_COUNT;
pub const BINARY_INACTIVE_TAIL_START: usize =
    composition_v3.UNIVERSAL_PHYSICAL_CLAIM_COUNT;
pub const BINARY_INACTIVE_TAIL_END: usize = composition_v3.POSEIDON_AUX_START;

pub const Error = artifact_mod.Error || capture_layout_v3.Error ||
    composition_v3.Error || pair_node.Error || error{
    ArtifactMismatch,
    BridgeIdentityMismatch,
    CohortAuthorityMismatch,
    CohortContractMismatch,
    LayoutMismatch,
    ProgramDescriptorMismatch,
};

pub fn Bridge(comptime Cohort: type) type {
    assertCohortContract(Cohort);
    return struct {
        const Self = @This();

        allocator: std.mem.Allocator,
        format_version: u16 = FORMAT_VERSION,
        schema_version: u16 = SCHEMA_VERSION,
        descriptor: composition_v3.ProgramDescriptorV3,
        layout: capture_layout_v3.CaptureLayoutV3,
        publication_id: protocol.Digest,
        artifact_id: protocol.Digest,
        capture_id: protocol.Digest,
        cohort_authority_sha_id: [32]u8,
        claim_inputs: [COMPOSITION_CLAIM_COUNT]QM31,
        relations: universal.UniversalRelations,
        composition_randomness: QM31,
        oods_seed: QM31,
        identity: [32]u8,

        pub fn init(
            allocator: std.mem.Allocator,
            cohort: *const Cohort,
            capture: *const artifact_mod.OuterProofCapture,
            publication: *const artifact_mod.Publication,
            artifact: *const artifact_mod.VerifiedBinaryArtifactV3,
            descriptor: composition_v3.ProgramDescriptorV3,
        ) !Self {
            try validateCohortArtifact(
                cohort,
                capture,
                publication,
                artifact,
                descriptor,
            );
            const manifest = cohort.manifest();
            var layout = try capture_layout_v3.CaptureLayoutV3.initBinary(
                allocator,
                manifest,
                capture,
            );
            errdefer layout.deinit();

            var claim_inputs: [COMPOSITION_CLAIM_COUNT]QM31 = undefined;
            try composition_v3.writeClaimInputs(
                .binary_node,
                &artifact.claimed_sums,
                &artifact.poseidon2_partials,
                &claim_inputs,
            );
            const relations = universal.UniversalRelations.fromDraws(
                &artifact.relation_draws,
            );
            try relations.validate();

            var result = Self{
                .allocator = allocator,
                .descriptor = descriptor,
                .layout = layout,
                .publication_id = artifact.publication_id,
                .artifact_id = artifact.artifact_id,
                .capture_id = artifact.capture_id,
                .cohort_authority_sha_id = artifact.cohort_authority_sha_id,
                .claim_inputs = claim_inputs,
                .relations = relations,
                .composition_randomness = capture.composition_randomness,
                .oods_seed = capture.oods_seed,
                .identity = undefined,
            };
            result.identity = bridgeIdentity(&result);
            try result.validateSelfConsistency(manifest);
            layout = undefined;
            return result;
        }

        pub fn deinit(self: *Self) void {
            self.layout.deinit();
            self.* = undefined;
        }

        pub fn validateSelfConsistency(
            self: *const Self,
            manifest: *const manifest_mod.Manifest,
        ) !void {
            try artifact_mod.validateBinaryDescriptor(self.descriptor, manifest);
            try self.layout.validateAgainstBinary(manifest);
            try composition_v3.validateClaimInputs(
                .binary_node,
                &self.claim_inputs,
            );
            try self.relations.validate();
            if (self.format_version != FORMAT_VERSION or
                self.schema_version != SCHEMA_VERSION or
                self.descriptor.proof_kind != .binary_node or
                digestIsZero(self.publication_id) or
                digestIsZero(self.artifact_id) or
                digestIsZero(self.capture_id) or
                std.mem.allEqual(u8, &self.cohort_authority_sha_id, 0) or
                !std.mem.eql(u8, &self.identity, &bridgeIdentity(self)))
            {
                return error.BridgeIdentityMismatch;
            }
        }

        /// Cold mutation-sensitive re-admission.  Rebuilding the owned layout
        /// catches every changed sample geometry before a shared input buffer
        /// can be written.
        pub fn validateAgainst(
            self: *const Self,
            cohort: *const Cohort,
            capture: *const artifact_mod.OuterProofCapture,
            publication: *const artifact_mod.Publication,
            artifact: *const artifact_mod.VerifiedBinaryArtifactV3,
        ) !void {
            try self.validateSelfConsistency(cohort.manifest());
            try validateCohortArtifact(
                cohort,
                capture,
                publication,
                artifact,
                self.descriptor,
            );
            var expected_layout = try capture_layout_v3.CaptureLayoutV3.initBinary(
                self.allocator,
                cohort.manifest(),
                capture,
            );
            defer expected_layout.deinit();
            var expected_claims: [COMPOSITION_CLAIM_COUNT]QM31 = undefined;
            try composition_v3.writeClaimInputs(
                .binary_node,
                &artifact.claimed_sums,
                &artifact.poseidon2_partials,
                &expected_claims,
            );
            const expected_relations = universal.UniversalRelations.fromDraws(
                &artifact.relation_draws,
            );
            try expected_relations.validate();
            if (!std.mem.eql(
                u8,
                &expected_layout.identity,
                &self.layout.identity,
            ) or !std.meta.eql(expected_claims, self.claim_inputs) or
                !std.meta.eql(expected_relations, self.relations) or
                !std.meta.eql(artifact.publication_id, self.publication_id) or
                !std.meta.eql(artifact.artifact_id, self.artifact_id) or
                !std.meta.eql(artifact.capture_id, self.capture_id) or
                !std.mem.eql(
                    u8,
                    &artifact.cohort_authority_sha_id,
                    &self.cohort_authority_sha_id,
                ) or !capture.composition_randomness.eql(
                self.composition_randomness,
            ) or !capture.oods_seed.eql(self.oods_seed)) {
                return error.ArtifactMismatch;
            }
        }

        /// Writes the binary samples into the one max-sized heterogeneous ABI.
        /// The sample authority is accepted only with both retained layouts;
        /// inactive storage is zeroed by the frontend authority after every
        /// fallible check succeeds.
        pub fn writeSharedSamples(
            self: *const Self,
            cohort: *const Cohort,
            capture: *const artifact_mod.OuterProofCapture,
            publication: *const artifact_mod.Publication,
            artifact: *const artifact_mod.VerifiedBinaryArtifactV3,
            segment_layout: *const capture_layout_v3.CaptureLayoutV3,
            sample_authority: capture_layout_v3.SampleInputAuthorityV3,
            destination: []QM31,
        ) !void {
            try self.validateAgainst(cohort, capture, publication, artifact);
            try sample_authority.validateAgainstLayouts(
                segment_layout,
                &self.layout,
            );
            try sample_authority.writePaddedSamples(
                .binary_node,
                capture.sampled_values,
                destination,
            );
        }

        pub fn concreteWitness(
            self: *const Self,
            cohort: *const Cohort,
            capture: *const artifact_mod.OuterProofCapture,
            publication: *const artifact_mod.Publication,
            artifact: *const artifact_mod.VerifiedBinaryArtifactV3,
            segment_layout: *const capture_layout_v3.CaptureLayoutV3,
            sample_authority: capture_layout_v3.SampleInputAuthorityV3,
            padded_samples: []QM31,
        ) !composition_v3.WitnessV3 {
            try self.writeSharedSamples(
                cohort,
                capture,
                publication,
                artifact,
                segment_layout,
                sample_authority,
                padded_samples,
            );
            return .{
                .parent_binary_selector = true,
                .proof_kind = .binary_node,
                .statement_words = &artifact.statement_words,
                .sampled_values = padded_samples,
                .claim_inputs = &self.claim_inputs,
                .relations = &self.relations,
                .composition_randomness = self.composition_randomness,
                .oods_seed = self.oods_seed,
            };
        }

        /// Allocation-free handoff to the exact 36-row universal recorder.
        /// The cold bridge already owns and authenticates the binary layout,
        /// claims, and relations; this method can only borrow that retained
        /// layout while the graph session supplies its corresponding symbolic
        /// input nodes. It does not mint heterogeneous circuit authority.
        pub fn beginRecorder(
            self: *const Self,
            manifest: *const manifest_mod.Manifest,
            builder: *composition_v3.segment_recorder_v3.graph_recorder.Builder,
            sampled_values: []const composition_v3.segment_recorder_v3.graph_recorder.Scalar,
            claim_inputs: *const [COMPOSITION_CLAIM_COUNT]composition_v3.segment_recorder_v3.graph_recorder.Scalar,
            challenges: *const composition_v3.segment_recorder_v3.graph_recorder.ChallengeSet,
            composition_randomness: composition_v3.segment_recorder_v3.graph_recorder.Scalar,
            oods_point: stwo_core.circle.CirclePoint(
                composition_v3.segment_recorder_v3.graph_recorder.Scalar,
            ),
            denominator_cache: *composition_v3.segment_recorder_v3.graph_recorder.DenominatorCache,
        ) !composition_v3.segment_recorder_v3.UniversalProgramRecorderV3 {
            try self.validateSelfConsistency(manifest);
            return composition_v3.segment_recorder_v3.UniversalProgramRecorderV3.init(
                builder,
                manifest,
                &self.layout,
                sampled_values,
                claim_inputs,
                challenges,
                composition_randomness,
                oods_point,
                denominator_cache,
            );
        }

        fn validateCohortArtifact(
            cohort: *const Cohort,
            capture: *const artifact_mod.OuterProofCapture,
            publication: *const artifact_mod.Publication,
            artifact: *const artifact_mod.VerifiedBinaryArtifactV3,
            descriptor: composition_v3.ProgramDescriptorV3,
        ) !void {
            try cohort.validateColdAuthority();
            const manifest = cohort.manifest();
            try artifact.validateAgainst(
                capture,
                publication,
                manifest,
                descriptor,
            );
            const authority = try cohort.publicationAuthority();
            if (!std.mem.eql(
                u8,
                &authority.cohort_authority_sha_id,
                &publication.cohort_authority_sha_id,
            ) or !std.meta.eql(
                authority.authority.context,
                publication.verifier_context,
            )) return error.CohortAuthorityMismatch;
            const authenticated = try pair_node.authenticateRoot(
                authority.authority,
                authority.record,
                authority.root_pin,
            );
            if (!std.meta.eql(authenticated, publication.authenticated_pair))
                return error.CohortAuthorityMismatch;
        }
    };
}

/// Canonical empty branch for the same 41-slot graph ABI.  No caller-supplied
/// empty claim or partial slice exists.
pub fn writeCanonicalEmptyClaimInputs(
    destination: *[COMPOSITION_CLAIM_COUNT]QM31,
) !void {
    const no_claims = [_]QM31{};
    const no_partials = [_]QM31{};
    try composition_v3.writeClaimInputs(
        .empty_leaf,
        &no_claims,
        &no_partials,
        destination,
    );
}

fn bridgeIdentity(bridge: anytype) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(BRIDGE_ID_DOMAIN);
    hashInt(&hash, u16, bridge.format_version);
    hashInt(&hash, u16, bridge.schema_version);
    hash.update(&bridge.descriptor.identity);
    hash.update(&bridge.layout.identity);
    hashDigest(&hash, bridge.publication_id);
    hashDigest(&hash, bridge.artifact_id);
    hashDigest(&hash, bridge.capture_id);
    hash.update(&bridge.cohort_authority_sha_id);
    for (bridge.claim_inputs) |value| hashQm31(&hash, value);
    for (bridge.relations.elements) |element| {
        hashInt(&hash, u8, element.arity);
        hashQm31(&hash, element.z);
        hashQm31(&hash, element.alpha);
    }
    hashQm31(&hash, bridge.composition_randomness);
    hashQm31(&hash, bridge.oods_seed);
    return hash.finalResult();
}

fn hashDigest(hash: anytype, value: protocol.Digest) void {
    for (value) |word| hashInt(hash, u32, word);
}

fn hashQm31(hash: anytype, value: QM31) void {
    for (value.toM31Array()) |word| hashInt(hash, u32, word.toU32());
}

fn hashInt(hash: anytype, comptime T: type, value: T) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, value, .little);
    hash.update(&encoded);
}

fn digestIsZero(value: protocol.Digest) bool {
    var aggregate: u32 = 0;
    for (value) |word| aggregate |= word;
    return aggregate == 0;
}

fn assertCohortContract(comptime Cohort: type) void {
    inline for (.{
        "validateColdAuthority",
        "manifest",
        "publicationAuthority",
    }) |name| if (!@hasDecl(Cohort, name))
        @compileError("binary V3 cohort contract missing " ++ name);
}

comptime {
    if (FORMAT_VERSION != 1 or SCHEMA_VERSION != 1 or
        HEAP_ALLOCATIONS_PER_INIT != 4 or HOT_HEAP_ALLOCATIONS != 0 or
        HEAP_ALLOCATIONS_PER_BEGIN_RECORDER != 0 or
        BINARY_SOURCE_CLAIM_COUNT != 36 or COMPOSITION_CLAIM_COUNT != 41 or
        BINARY_INACTIVE_TAIL_START != 36 or BINARY_INACTIVE_TAIL_END != 39)
    {
        @compileError("binary V3 composition bridge ABI drifted");
    }
}
