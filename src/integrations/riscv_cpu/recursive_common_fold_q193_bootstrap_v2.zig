//! Isolated q193 bootstrap for the field-native common fold.
//!
//! This transaction exists only to exercise the genuine common-fold prover,
//! retained artifact codec, independent cold verifier, and query/graph remint
//! before the schema-4 real-leaf wrapper can mint its production geometry.
//! It accepts exactly two independently cold-opened canonical-empty proofs.
//! Its common geometry is minted only from its own successful cold verifier;
//! it cannot construct parity, a production authority, or a routable child.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const canonical_manifest =
    @import("recursive_common_canonical_empty_universal_manifest_v2.zig");
const canonical_proof =
    @import("recursive_common_canonical_empty_universal_proof_v2.zig");
const canonical_worker =
    @import("recursive_pipeline_worker_canonical_empty_v2.zig");
const composition_capture =
    @import("recursive_common_fold_composition_capture_v2.zig");
const composition_graph =
    @import("recursive_common_fold_composition_graph_v2.zig");
const field_public = @import("recursive_common_fold_field_public_v2.zig");
const fixed_source = @import("recursive_common_fold_fixed_wire_v2.zig");
const geometry_support =
    @import("recursive_common_fold_q193_bootstrap_geometry_v2.zig");
const input_mod = @import("recursive_common_fold_input_v2.zig");
const live_mod = @import("recursive_common_fold_universal_cohort_v2.zig");
const manifest_mod =
    @import("recursive_common_fold_universal_manifest_v2.zig");
const node_mod = @import("recursive_node_artifact_v2.zig");
const output_support =
    @import("recursive_common_fold_q193_bootstrap_output_v2.zig");
const registry_mod = @import("recursive_circuit_registry_v1.zig");
const secure_artifact =
    @import("recursive_temporal_secure_parent_artifact_v1.zig");
const secure_cohort = @import("recursive_common_fold_secure_cohort_v2.zig");
const secure_engine =
    @import("recursive_temporal_secure_parent_native_engine_v1.zig");
const process_validation =
    @import("recursive_process_local_validation_token_v1.zig");
const cold_token = @import("recursive_common_fold_cold_token_v2.zig");

const recursion = frontend.recursion;
const M31 = stwo_core.fields.m31.M31;
const Sha256 = std.crypto.hash.sha2.Sha256;
const geometryFromFresh = geometry_support.geometryFromFresh;
const validateChildShape = geometry_support.validateChildShape;
const logSizes = geometry_support.logSizes;
const buildNodeArtifact = output_support.buildNodeArtifact;
const validateUnrouteable = output_support.validateUnrouteable;

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const PRODUCTION_ACTIVATION = false;
pub const ROUTER_ACTIVATION = false;
pub const REGISTRY_PARITY_MINTED = false;
pub const REAL_LEAF_ROLE_AVAILABLE = false;
pub const SERIALIZABLE_FRESH_CAPABILITY = false;
pub const CHILD_COUNT: usize = 2;
pub const DIMENSIONS = geometry_support.DIMENSIONS;
pub const FRI_FOLD_WIDTHS = geometry_support.FRI_FOLD_WIDTHS;
pub const FRI_PATH_DEPTHS = geometry_support.FRI_PATH_DEPTHS;
pub const bootstrapRegistry = geometry_support.bootstrapRegistry;

const BOOTSTRAP_LIVE_DOMAIN =
    "stwo-zig/recursive-common-fold-q193-bootstrap-live/v2\x00";
const BOOTSTRAP_ROOT_PIN_DOMAIN =
    "stwo-zig/recursive-common-fold-q193-bootstrap-root-pin/v2\x00";
const BOOTSTRAP_MANIFEST_AUTHORITY_DOMAIN =
    "stwo-zig/recursive-common-fold-q193-bootstrap-manifest/v2\x00";

pub const Error = canonical_proof.Error || registry_mod.Error || error{
    BootstrapCanonicalChildAlias,
    BootstrapCanonicalChildMismatch,
    BootstrapCommonGeometryMismatch,
    BootstrapCommonOutputMismatch,
    BootstrapDimensionMismatch,
    BootstrapManifestMismatch,
    BootstrapRegistryMismatch,
};

/// Owns one canonical verifier admission without the production worker's
/// three-role parity lease. The registry is a bootstrap-only structural
/// container whose canonical-empty entry exactly matches the cold geometry.
pub const CanonicalChildLeaseV2 = struct {
    admission: canonical_proof.FreshAdmissionV2,

    pub fn initOwned(
        cold: canonical_proof.OwnedColdProofV2,
        registry: registry_mod.RecursiveCircuitRegistryV1,
        campaign_namespace_sha256: [32]u8,
    ) !CanonicalChildLeaseV2 {
        const evidence = try canonical_proof.EvidenceV2.initOwned(
            cold,
            &registry,
            campaign_namespace_sha256,
        );
        return .{ .admission = try canonical_proof.FreshAdmissionV2.initOwned(
            evidence,
            registry,
        ) };
    }

    pub fn deinit(self: *CanonicalChildLeaseV2) void {
        self.admission.deinit();
        self.* = undefined;
    }

    pub fn validate(
        self: *const CanonicalChildLeaseV2,
        registry: *const registry_mod.RecursiveCircuitRegistryV1,
    ) !void {
        try self.admission.validate();
        if (!std.meta.eql(self.admission.registry, registry.*))
            return error.BootstrapRegistryMismatch;
    }

    pub fn requireFoldChild(
        self: *const CanonicalChildLeaseV2,
        registry: *const registry_mod.RecursiveCircuitRegistryV1,
    ) !canonical_worker.FreshFoldChildV2 {
        try self.validate(registry);
        const wrapper = self.admission.view();
        const ingress = try self.admission.evidence.ingressView();
        const graph = try self.admission.evidence.foldGraphView();
        const result = canonical_worker.FreshFoldChildV2{
            .wrapper = wrapper,
            .ingress = ingress,
            .graph = graph,
            .query_words = ingress.query_words,
            .query_log_size = ingress.query_log_size,
            .final_transcript_digest = ingress.final_transcript_digest,
            .final_transcript_draw_count = ingress.final_transcript_draw_count,
            .query_words_identity_sha256 = ingress.query_words_identity_sha256,
        };
        try result.validateBorrowed();
        return result;
    }
};

/// Live two-empty source. It has no production geometry/parity field.
pub const BootstrapLiveV2 = struct {
    pub const FreshFoldChildV2 = live_mod.FreshFoldChildV2;
    pub const FoldChild = FreshFoldChildV2;
    pub const CapturedFriPair = live_mod.CapturedFriPairV2;

    input: *const input_mod.FreshFoldInputV2,
    children: [CHILD_COUNT]FreshFoldChildV2,
    registry_value: *const registry_mod.RecursiveCircuitRegistryV1,
    public_schedule: field_public.PoseidonScheduleV2,
    identity_sha256: [32]u8,

    pub fn init(
        input: *const input_mod.FreshFoldInputV2,
        canonical_children: [CHILD_COUNT]*const canonical_worker.FreshFoldChildV2,
        registry_authority: *const registry_mod.RecursiveCircuitRegistryV1,
    ) !BootstrapLiveV2 {
        const children = [CHILD_COUNT]FreshFoldChildV2{
            try FreshFoldChildV2.fromCanonical(
                canonical_children[0],
                registry_authority,
            ),
            try FreshFoldChildV2.fromCanonical(
                canonical_children[1],
                registry_authority,
            ),
        };
        const left = try children[0].projection(registry_authority);
        const right = try children[1].projection(registry_authority);
        var result = BootstrapLiveV2{
            .input = input,
            .children = children,
            .registry_value = registry_authority,
            .public_schedule = try field_public.PoseidonScheduleV2.build(
                left.node_public,
                right.node_public,
                input.parent_coordinate,
            ),
            .identity_sha256 = undefined,
        };
        result.identity_sha256 = try liveIdentity(&result);
        try result.validate();
        return result;
    }

    pub fn registry(
        self: *const BootstrapLiveV2,
    ) *const registry_mod.RecursiveCircuitRegistryV1 {
        return self.registry_value;
    }

    pub fn validate(self: *const BootstrapLiveV2) !void {
        try self.registry_value.validate();
        try self.input.validateAgainst(self.registry_value);
        for (self.children, self.input.child_views, 0..) |child, expected, index| {
            if (child.role() != .canonical_empty_field_v2)
                return error.BootstrapCanonicalChildMismatch;
            const projection = try child.projection(self.registry_value);
            if (projection.wrapper.artifact != expected.artifact or
                projection.wrapper.geometry != expected.geometry or
                projection.wrapper.capture != expected.capture or
                !std.meta.eql(
                    try projection.wrapper.reference(),
                    self.input.child_refs[index],
                )) return error.BootstrapCanonicalChildMismatch;
        }
        const left = try self.children[0].projection(self.registry_value);
        const right = try self.children[1].projection(self.registry_value);
        if (left.capture == right.capture or
            left.graph.lane.graph.nodes.ptr == right.graph.lane.graph.nodes.ptr or
            left.graph.evaluation.values.ptr == right.graph.evaluation.values.ptr)
        {
            return error.BootstrapCanonicalChildAlias;
        }
        const expected_schedule = try field_public.PoseidonScheduleV2.build(
            left.node_public,
            right.node_public,
            self.input.parent_coordinate,
        );
        if (!std.meta.eql(self.public_schedule, expected_schedule) or
            !std.mem.eql(u8, &self.identity_sha256, &try liveIdentity(self)))
        {
            return error.BootstrapCanonicalChildMismatch;
        }
    }

    pub fn requireFixedWireSource(self: *const BootstrapLiveV2) !void {
        try self.validate();
        for (self.children) |child| {
            const projection = try child.projection(self.registry_value);
            try validateChildShape(projection.geometry);
        }
    }

    pub fn initCapturedFriPair(
        self: *const BootstrapLiveV2,
        allocator: std.mem.Allocator,
    ) !live_mod.CapturedFriPairV2 {
        try self.requireFixedWireSource();
        const left_projection = try self.children[0].projection(
            self.registry_value,
        );
        const right_projection = try self.children[1].projection(
            self.registry_value,
        );
        var left = try recursion.captured_fri.Owned.init(
            allocator,
            childProfile(left_projection),
            left_projection.capture,
        );
        errdefer left.deinit();
        var right = try recursion.captured_fri.Owned.init(
            allocator,
            childProfile(right_projection),
            right_projection.capture,
        );
        errdefer right.deinit();
        return .{ .children = .{ left, right } };
    }

    pub fn authenticatedCompositionLanes(
        self: *const BootstrapLiveV2,
    ) ![CHILD_COUNT]recursion.binary_fri_outer_source.AuthenticatedCompositionLane {
        try self.validate();
        var result: [CHILD_COUNT]recursion.binary_fri_outer_source
            .AuthenticatedCompositionLane = undefined;
        for (self.children, &result, 0..) |child, *destination, index| {
            const projection = try child.projection(self.registry_value);
            destination.* = .{
                .circuit_id = if (index == 0)
                    live_mod.LEFT_POSITION_CIRCUIT_ID
                else
                    live_mod.RIGHT_POSITION_CIRCUIT_ID,
                .circuit_identity = projection.graph.lane.graph.identity_digest,
                .graph = projection.graph.lane.graph,
                .evaluation = projection.graph.evaluation,
            };
            try destination.validate();
        }
        return result;
    }
};

pub const BootstrapRootPinV2 = struct {
    live_identity_sha256: [32]u8,
    dimensions_identity_sha256: [32]u8,
    identity_sha256: [32]u8,

    fn init(live: *const BootstrapLiveV2) !BootstrapRootPinV2 {
        try live.requireFixedWireSource();
        var result = BootstrapRootPinV2{
            .live_identity_sha256 = live.identity_sha256,
            .dimensions_identity_sha256 = dimensionsIdentity(),
            .identity_sha256 = undefined,
        };
        result.identity_sha256 = bootstrapRootPinIdentity(&result);
        return result;
    }

    pub fn validateAgainst(
        self: BootstrapRootPinV2,
        live: *const BootstrapLiveV2,
    ) !void {
        if (!std.meta.eql(self, try init(live)))
            return error.BootstrapDimensionMismatch;
    }
};

pub const BootstrapFixedPolicyV2 = struct {
    pub const RootPin = BootstrapRootPinV2;

    pub fn initRootPin(live: *const BootstrapLiveV2) !RootPin {
        return RootPin.init(live);
    }

    pub fn validateRootPin(
        pin: RootPin,
        live: *const BootstrapLiveV2,
    ) !void {
        return pin.validateAgainst(live);
    }

    pub fn validateDimensions(
        comptime dimensions: recursion.fixed_wire.Dimensions,
        live: *const BootstrapLiveV2,
    ) !void {
        try live.requireFixedWireSource();
        if (!std.meta.eql(dimensions, DIMENSIONS))
            return error.BootstrapDimensionMismatch;
    }

    pub fn projectChild(
        child: live_mod.FreshFoldChildV2,
        live: *const BootstrapLiveV2,
    ) !@import("recursive_common_fold_child_capability_v2.zig").ProjectionV2 {
        return child.projection(live.registry_value);
    }

    pub fn validateChildCustody(
        actual: @import("recursive_common_fold_child_capability_v2.zig").ProjectionV2,
        expected: @import("recursive_common_fold_child_capability_v2.zig").ProjectionV2,
        _: *const BootstrapLiveV2,
    ) !void {
        if (actual.wrapper.artifact != expected.wrapper.artifact or
            actual.node_public != expected.node_public or
            actual.geometry != expected.geometry or
            actual.capture != expected.capture)
        {
            return error.BootstrapCanonicalChildMismatch;
        }
    }
};

pub const Fixed = fixed_source.TypesForLive(
    DIMENSIONS,
    BootstrapLiveV2,
    BootstrapFixedPolicyV2,
);

pub const BootstrapManifestPolicyV2 = struct {
    pub fn initManifest(
        live: *const BootstrapLiveV2,
        source_owner: *const Fixed.OwnerV2,
    ) !manifest_mod.Manifest {
        try live.requireFixedWireSource();
        try source_owner.validate();
        var logs = [_]u32{canonical_manifest.LOGICAL_LOG_SIZE} **
            manifest_mod.COMPONENT_COUNT;
        try source_owner.source().installLogSizes(&logs);
        logs[manifest_mod.RANGE_ROW] = canonical_manifest.RANGE_LOG_SIZE;
        return manifest_mod.buildForDerivedLogSizes(logs);
    }

    pub fn validateManifest(
        value: *const manifest_mod.Manifest,
        live: *const BootstrapLiveV2,
        source_owner: *const Fixed.OwnerV2,
    ) !void {
        const expected = try initManifest(live, source_owner);
        if (!std.meta.eql(value.*, expected))
            return error.BootstrapManifestMismatch;
    }

    pub fn contractIdentity(
        _: *const BootstrapLiveV2,
        manifest: *const manifest_mod.Manifest,
    ) ![32]u8 {
        return manifest_mod.contractIdentityForDerivedManifest(
            manifest,
            try logSizes(manifest),
        );
    }

    pub fn profileIdentity(
        _: *const BootstrapLiveV2,
        manifest: *const manifest_mod.Manifest,
    ) ![32]u8 {
        return manifest_mod.profileIdentityForDerivedManifest(
            manifest,
            try logSizes(manifest),
        );
    }

    pub fn programIdentity(
        _: *const BootstrapLiveV2,
        manifest: *const manifest_mod.Manifest,
    ) ![32]u8 {
        return manifest_mod.programIdentityForDerivedManifest(
            manifest,
            try logSizes(manifest),
        );
    }

    pub fn paddingLayoutIdentity(
        _: *const BootstrapLiveV2,
        manifest: *const manifest_mod.Manifest,
    ) ![32]u8 {
        return manifest_mod.paddingIdentityForDerivedManifest(
            manifest,
            try logSizes(manifest),
        );
    }

    pub fn tableLayoutIdentity(
        _: *const BootstrapLiveV2,
        manifest: *const manifest_mod.Manifest,
    ) ![32]u8 {
        return manifest_mod.tableLayoutIdentityForDerivedManifest(
            manifest,
            try logSizes(manifest),
        );
    }

    pub fn verificationKeyId(
        _: *const BootstrapLiveV2,
        manifest: *const manifest_mod.Manifest,
    ) !recursion.poseidon2_channel.Digest {
        return manifest_mod.verificationKeyIdForDerivedManifest(
            manifest,
            try logSizes(manifest),
        );
    }

    pub fn nextParentVkId(
        _: *const BootstrapLiveV2,
        manifest: *const manifest_mod.Manifest,
    ) !recursion.poseidon2_channel.Digest {
        return manifest_mod.nextParentVkIdForDerivedManifest(
            manifest,
            try logSizes(manifest),
        );
    }

    pub fn airProgramId(
        _: *const BootstrapLiveV2,
        manifest: *const manifest_mod.Manifest,
    ) !recursion.poseidon2_channel.Digest {
        return manifest_mod.airProgramIdForDerivedManifest(
            manifest,
            try logSizes(manifest),
        );
    }

    pub fn authorityIdentity(
        live: *const BootstrapLiveV2,
        manifest: *const manifest_mod.Manifest,
    ) [32]u8 {
        var hash = Sha256.init(.{});
        hash.update(BOOTSTRAP_MANIFEST_AUTHORITY_DOMAIN);
        hash.update(&live.identity_sha256);
        hash.update(&manifest.seal);
        return hash.finalResult();
    }
};

pub const SecureCohort = secure_cohort.CohortForLiveV2(
    DIMENSIONS,
    BootstrapLiveV2,
    Fixed,
    BootstrapManifestPolicyV2,
);
pub const Graph = composition_graph.TypesForCohort(DIMENSIONS, SecureCohort);
pub const CaptureTypes = composition_capture.TypesForGraph(DIMENSIONS, Graph);
pub const Kernel = Graph.KernelV2;

/// Live-only remint from an independently verified bootstrap proof.  This is
/// deliberately not the role-neutral production child type.
pub const FreshBootstrapRemintV2 = struct {
    node_artifact: *const node_mod.RecursiveNodeArtifactV2,
    geometry: *const registry_mod.AuthenticatedGeometryV1,
    graph: composition_capture.FreshGraphViewV2,
    query_words: *const [canonical_proof.QUERY_WORD_COUNT]M31,
    query_log_size: u32,
    final_transcript_digest: *const canonical_proof.TranscriptDigestV2,
    final_transcript_draw_count: u32,
    query_words_identity_sha256: *const [32]u8,

    pub fn validateBorrowed(self: FreshBootstrapRemintV2) !void {
        try self.node_artifact.validate();
        try self.geometry.validate();
        try self.graph.lane.graph.validate();
        if (self.geometry.role != .common_fold_field_v2 or
            self.query_words != self.graph.query_words or
            self.query_log_size != self.graph.query_log_size or
            self.final_transcript_digest != self.graph.final_transcript_digest or
            self.final_transcript_draw_count !=
                self.graph.final_transcript_draw_count or
            self.query_words_identity_sha256 !=
                self.graph.query_words_identity_sha256 or
            self.graph.evaluation.values.len != self.graph.lane.graph.nodes.len)
        {
            return error.BootstrapCommonOutputMismatch;
        }
    }
};

pub const OwnedBootstrapProofV2 = struct {
    allocator: std.mem.Allocator,
    live: *const BootstrapLiveV2,
    live_identity_sha256: [32]u8,
    session: secure_artifact.SessionV1,
    artifact_value: secure_artifact.OwnedArtifactV1,
    artifact_bytes: []u8,
    fresh: secure_engine.FreshVerificationV1,
    composition_capture: CaptureTypes.CaptureV2,
    query_authority: CaptureTypes.VerifierQueryAuthorityV2,
    claims: manifest_mod.ClaimVector,
    geometry_value: registry_mod.AuthenticatedGeometryV1,
    node_artifact: node_mod.RecursiveNodeArtifactV2,
    validation: *process_validation.ValidatedOwnerV1,

    pub fn deinit(self: *OwnedBootstrapProofV2) void {
        self.allocator.destroy(self.validation);
        self.composition_capture.deinit();
        self.fresh.deinit();
        self.artifact_value.deinit();
        self.allocator.free(self.artifact_bytes);
        self.* = undefined;
    }

    pub fn validate(self: *const OwnedBootstrapProofV2) !void {
        var timer = startTimer();
        defer self.validation.counters.recordTimed(
            .token_check,
            readTimer(&timer),
        );
        try self.live.validate();
        if (!std.mem.eql(
            u8,
            &self.live_identity_sha256,
            &self.live.identity_sha256,
        )) return error.BootstrapCommonOutputMismatch;
        try self.composition_capture.validateProcessLocalClosure(
            &self.validation.token,
        );
        try self.validation.token.validateAgainst(
            try cold_token.snapshot(self),
        );
        try self.artifact_value.validateCustody();
        try self.artifact_value.statement.validateAgainstSession(&self.session);
        try self.geometry_value.validate();
        try validateUnrouteable(self.live, &self.node_artifact);
        if (!std.meta.eql(
            self.fresh.statement,
            self.artifact_value.statement,
        )) return error.BootstrapCommonOutputMismatch;
    }

    pub fn fullAudit(self: *const OwnedBootstrapProofV2) !void {
        var full_timer = startTimer();
        defer self.validation.counters.recordTimed(
            .full_audit,
            readTimer(&full_timer),
        );
        try self.live.validate();
        if (!std.mem.eql(
            u8,
            &self.live_identity_sha256,
            &self.live.identity_sha256,
        )) return error.BootstrapCommonOutputMismatch;
        var cohort = try SecureCohort.init(
            self.allocator,
            .{ .live = self.live },
        );
        defer cohort.deinit();
        const expected_session = try cohort.session();
        try self.artifact_value.validateCustody();
        try self.artifact_value.statement.validateAgainstSession(&self.session);
        var replay_timer = startTimer();
        const replay = try Kernel.reconstructVerifiedReplayWithCohort(
            self.allocator,
            &cohort,
            &self.session,
            &self.fresh,
        );
        self.validation.counters.recordTimed(
            .transcript_replay,
            readTimer(&replay_timer),
        );
        try replay.validateQueryWordsAgainst(&self.fresh);
        try self.query_authority.validateAgainstReplay(&replay);
        try self.composition_capture.validateAgainst(
            &cohort,
            &self.session,
            &self.fresh.statement,
            &self.fresh.capture,
            &replay,
            false,
        );
        const expected_geometry = try geometryFromFresh(
            cohort.manifest(),
            &self.fresh,
        );
        const canonical = try self.artifact_value.encodeCanonicalAlloc(
            self.allocator,
        );
        defer self.allocator.free(canonical);
        const expected_node = try buildNodeArtifact(
            self.live,
            &expected_geometry,
            self.artifact_bytes,
        );
        if (!std.meta.eql(self.session, expected_session) or
            !std.meta.eql(self.fresh.statement, self.artifact_value.statement) or
            !std.meta.eql(self.claims, replay.claims) or
            !std.meta.eql(self.geometry_value, expected_geometry) or
            !std.mem.eql(u8, canonical, self.artifact_bytes) or
            !std.meta.eql(self.node_artifact, expected_node))
        {
            return error.BootstrapCommonOutputMismatch;
        }
        try validateUnrouteable(self.live, &self.node_artifact);
        try self.validate();
    }

    pub fn performanceSnapshot(
        self: *const OwnedBootstrapProofV2,
    ) process_validation.CounterSnapshotV1 {
        return self.validation.counters.snapshot();
    }

    pub fn proofBytes(self: *const OwnedBootstrapProofV2) []const u8 {
        return self.artifact_bytes;
    }

    pub fn nodeArtifact(
        self: *const OwnedBootstrapProofV2,
    ) *const node_mod.RecursiveNodeArtifactV2 {
        return &self.node_artifact;
    }

    pub fn requireRemint(
        self: *const OwnedBootstrapProofV2,
    ) !FreshBootstrapRemintV2 {
        try self.validate();
        var timer = startTimer();
        const graph = try self.composition_capture.borrowProcessLocalView(
            &self.query_authority,
            &self.validation.token,
        );
        self.validation.counters.recordTimed(
            .graph_view_borrow,
            readTimer(&timer),
        );
        const result = FreshBootstrapRemintV2{
            .node_artifact = &self.node_artifact,
            .geometry = &self.geometry_value,
            .graph = graph,
            .query_words = &self.query_authority.query_words,
            .query_log_size = self.query_authority.query_log_size,
            .final_transcript_digest = &self.query_authority.final_transcript_digest,
            .final_transcript_draw_count = self.query_authority.final_transcript_draw_count,
            .query_words_identity_sha256 = &self.query_authority.query_words_identity_sha256,
        };
        try result.validateBorrowed();
        return result;
    }
};

pub fn proveAndColdVerify(
    allocator: std.mem.Allocator,
    live: *const BootstrapLiveV2,
    execution: secure_engine.ExecutionOptions,
) !OwnedBootstrapProofV2 {
    try live.validate();
    var cohort = try SecureCohort.init(allocator, .{ .live = live });
    defer cohort.deinit();
    const session = try cohort.session();
    var proved = try Kernel.proveAndColdVerify(
        allocator,
        .{ .live = live },
        session,
        execution,
    );
    errdefer proved.deinit();
    var result = try ownResult(
        allocator,
        live,
        session,
        proved.artifact,
        proved.fresh,
        null,
        proved.receipt.cold_verify_ns,
    );
    proved.artifact = undefined;
    proved.fresh = undefined;
    errdefer result.deinit();
    return result;
}

pub fn coldOpen(
    allocator: std.mem.Allocator,
    live: *const BootstrapLiveV2,
    proof_bytes: []const u8,
    node_bytes: []const u8,
) !OwnedBootstrapProofV2 {
    try live.validate();
    const retained_node = try node_mod.RecursiveNodeArtifactV2.decodeCanonical(
        node_bytes,
    );
    try validateUnrouteable(live, &retained_node);
    var cohort = try SecureCohort.init(allocator, .{ .live = live });
    defer cohort.deinit();
    const session = try cohort.session();
    var artifact_value = try secure_artifact.OwnedArtifactV1.decodeCanonical(
        allocator,
        proof_bytes,
    );
    errdefer artifact_value.deinit();
    var cold_timer = startTimer();
    var verified = try Kernel.verifyColdWithReplay(
        allocator,
        &cohort,
        &session,
        &artifact_value,
    );
    const verifier_and_replay_ns = readTimer(&cold_timer);
    errdefer verified.deinit();
    try verified.validateBorrowed(&cohort, &session);
    const result = try ownPreparedResult(
        allocator,
        live,
        session,
        artifact_value,
        verified.fresh,
        &cohort,
        verified.replay,
        &retained_node,
        verifier_and_replay_ns -| verified.replay_finalize_ns,
        verified.replay_finalize_ns,
    );
    verified.fresh = undefined;
    return result;
}

fn ownResult(
    allocator: std.mem.Allocator,
    live: *const BootstrapLiveV2,
    session: secure_artifact.SessionV1,
    artifact_value: secure_artifact.OwnedArtifactV1,
    fresh: secure_engine.FreshVerificationV1,
    retained_node: ?*const node_mod.RecursiveNodeArtifactV2,
    cold_verify_ns: u64,
) !OwnedBootstrapProofV2 {
    var cohort = try SecureCohort.init(allocator, .{ .live = live });
    defer cohort.deinit();
    var replay_timer = startTimer();
    // Retain the exact cohort prepared by verifier replay. Common-fold row 34
    // begins with a boundary-only Poseidon schedule and becomes complete only
    // while Tree 1 is rebuilt; minting the graph against a different fresh
    // cohort would correctly fail `RowsNotPrepared`.
    const replay = try Kernel.reconstructVerifiedReplayWithCohort(
        allocator,
        &cohort,
        &session,
        &fresh,
    );
    const replay_ns = readTimer(&replay_timer);
    return ownPreparedResult(
        allocator,
        live,
        session,
        artifact_value,
        fresh,
        &cohort,
        replay,
        retained_node,
        cold_verify_ns,
        replay_ns,
    );
}

fn ownPreparedResult(
    allocator: std.mem.Allocator,
    live: *const BootstrapLiveV2,
    session: secure_artifact.SessionV1,
    artifact_value: secure_artifact.OwnedArtifactV1,
    fresh: secure_engine.FreshVerificationV1,
    cohort: *SecureCohort,
    replay: Kernel.VerifiedReplay,
    retained_node: ?*const node_mod.RecursiveNodeArtifactV2,
    cold_verify_ns: u64,
    replay_ns: u64,
) !OwnedBootstrapProofV2 {
    const query_authority = try CaptureTypes.VerifierQueryAuthorityV2.init(
        &replay,
    );
    var graph_timer = startTimer();
    var graph = try CaptureTypes.CaptureV2.init(
        allocator,
        cohort,
        &session,
        &fresh.statement,
        &fresh.capture,
        &replay,
    );
    const graph_record_ns = readTimer(&graph_timer);
    errdefer graph.deinit();
    const geometry = try geometryFromFresh(cohort.manifest(), &fresh);
    const artifact_bytes = try artifact_value.encodeCanonicalAlloc(allocator);
    errdefer allocator.free(artifact_bytes);
    const node = try buildNodeArtifact(live, &geometry, artifact_bytes);
    if (retained_node) |expected| if (!std.meta.eql(expected.*, node))
        return error.BootstrapCommonOutputMismatch;
    const validation = try allocator.create(
        process_validation.ValidatedOwnerV1,
    );
    errdefer allocator.destroy(validation);
    validation.* = undefined;
    var result = OwnedBootstrapProofV2{
        .allocator = allocator,
        .live = live,
        .live_identity_sha256 = live.identity_sha256,
        .session = session,
        .artifact_value = artifact_value,
        .artifact_bytes = artifact_bytes,
        .fresh = fresh,
        .composition_capture = graph,
        .query_authority = query_authority,
        .claims = replay.claims,
        .geometry_value = geometry,
        .node_artifact = node,
        .validation = validation,
    };
    try cold_token.validateConstructed(&result, cohort, &replay);
    validation.* = try process_validation.ValidatedOwnerV1.init(
        try cold_token.snapshot(&result),
    );
    validation.counters.recordTimed(
        .q193_cold_verification,
        cold_verify_ns,
    );
    validation.counters.recordTimed(.transcript_replay, replay_ns);
    validation.counters.recordTimed(.graph_record, graph_record_ns);
    try result.validate();
    return result;
}

fn startTimer() ?std.time.Timer {
    return std.time.Timer.start() catch null;
}

fn readTimer(timer: *?std.time.Timer) u64 {
    if (timer.*) |*active| return active.read();
    return 0;
}

fn childProfile(
    child: @import("recursive_common_fold_child_capability_v2.zig").ProjectionV2,
) recursion.captured_fri.ProfileConfig {
    const pcs = child.wrapper.geometry.pcs;
    return .{
        .log_blowup_factor = pcs.fri_log_blowup_factor,
        .log_last_layer_degree_bound = pcs.fri_log_last_layer_degree_bound,
        .interaction_pow_bits = pcs.interaction_pow_bits,
        .pcs_pow_bits = pcs.pcs_pow_bits,
        .claimed_sum_count = @intCast(child.wrapper.geometry.component_count),
    };
}

fn liveIdentity(value: *const BootstrapLiveV2) ![32]u8 {
    var hash = Sha256.init(.{});
    hash.update(BOOTSTRAP_LIVE_DOMAIN);
    hash.update(&value.input.identity_sha256);
    hash.update(&value.registry_value.identity_sha256);
    for (value.children) |child| {
        const projection = try child.projection(value.registry_value);
        hash.update(projection.query_words_identity_sha256);
        hash.update(projection.graph.capture_identity_sha256);
    }
    return hash.finalResult();
}

fn dimensionsIdentity() [32]u8 {
    var hash = Sha256.init(.{});
    inline for (std.meta.fields(recursion.fixed_wire.Dimensions)) |field|
        hashInt(&hash, @TypeOf(@field(DIMENSIONS, field.name)), @field(
            DIMENSIONS,
            field.name,
        ));
    hash.update(&FRI_FOLD_WIDTHS);
    hash.update(&FRI_PATH_DEPTHS);
    return hash.finalResult();
}

fn bootstrapRootPinIdentity(value: *const BootstrapRootPinV2) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(BOOTSTRAP_ROOT_PIN_DOMAIN);
    hash.update(&value.live_identity_sha256);
    hash.update(&value.dimensions_identity_sha256);
    return hash.finalResult();
}

fn hashInt(hash: *Sha256, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

comptime {
    DIMENSIONS.validate();
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 1 or
        PRODUCTION_ACTIVATION or ROUTER_ACTIVATION or
        REGISTRY_PARITY_MINTED or REAL_LEAF_ROLE_AVAILABLE or
        SERIALIZABLE_FRESH_CAPABILITY or CHILD_COUNT != 2 or
        DIMENSIONS.query_count != 193 or FRI_FOLD_WIDTHS.len != 4 or
        FRI_PATH_DEPTHS.len != 4)
    {
        @compileError("common-fold q193 bootstrap contract drifted");
    }
}
