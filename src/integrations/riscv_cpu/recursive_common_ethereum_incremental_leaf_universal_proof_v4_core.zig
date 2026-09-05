//! Genuine q193 proof and cold verifier owner for the schema-3 role-0 cohort.
//!
//! The durable value is the ordinary secure-parent proof artifact.  Claims,
//! full query words, graph evaluation, and registry geometry are retained only
//! after canonical decode and `verifyColdWithReplay` in the current process.

const std = @import("std");
const builtin = @import("builtin");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const campaign_materializer =
    @import("recursive_common_ethereum_incremental_leaf_campaign_materializer_v4.zig");
const capture_owner =
    @import("recursive_common_ethereum_incremental_leaf_composition_capture_owner_v4.zig");
const cold_geometry =
    @import("recursive_common_ethereum_incremental_leaf_cold_geometry_v4.zig");
const manifest_mod =
    @import("recursive_common_ethereum_incremental_leaf_universal_manifest_v4.zig");
const common_authority = @import("recursive_common_wrapper_authority_v2.zig");
const artifact_ref_mod = @import("recursive_node_artifact_v1.zig");
const registry_mod = @import("recursive_circuit_registry_v1.zig");
const padding_target_mod =
    @import("recursive_pipeline_campaign_padding_target_v2.zig");
const secure_artifact =
    @import("recursive_temporal_secure_parent_artifact_v1.zig");
const secure_engine =
    @import("recursive_temporal_secure_parent_native_engine_v1.zig");

const recursion = frontend.recursion;
const M31 = stwo_core.fields.m31.M31;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const FORMAT_VERSION: u16 = 4;
pub const SCHEMA_VERSION: u16 = 3;
pub const ROLE = registry_mod.CircuitRoleV4
    .ethereum_incremental_leaf_wrapper_v4;
pub const QUERY_WORD_COUNT: usize = 193;
pub const PROOF_ARTIFACT_KIND: u32 = common_authority.PROOF_ARTIFACT_KIND;
pub const PROOF_ARTIFACT_SCHEMA_VERSION: u16 = 1;
pub const PRODUCTION_ACTIVATION = false;
pub const COLD_VERIFICATION_BEFORE_CAPABILITY = true;
pub const SERIALIZABLE_FRESH_CAPABILITY = false;

pub const Error = registry_mod.Error || error{
    EthereumIncrementalUniversalColdProofMismatchV4,
};

pub fn Types(comptime Engine: type) type {
    comptime requireRecursionEngine(Engine);
    const Materialized =
        campaign_materializer.PreparedOwnedCampaignCaptureV4(Engine);
    const CaptureTypes = capture_owner.Types(Engine);
    const Cohort = CaptureTypes.SecureCohortV4;
    const Kernel = CaptureTypes.KernelV4;

    return struct {
        pub const EngineType = Engine;
        pub const MaterializedV4 = Materialized;
        pub const SecureCohortV4 = Cohort;
        pub const KernelV4 = Kernel;
        pub const CaptureV4 = CaptureTypes.CaptureV4;
        pub const VerifierQueryAuthorityV4 =
            CaptureTypes.VerifierQueryAuthorityV4;
        pub const Graph = capture_owner.FreshGraphViewV4;
        pub const Ingress = FreshRecursiveIngressV4;

        pub const ProveResultV4 = struct {
            proof: OwnedColdProofV4,
            receipt: secure_engine.ReceiptV1,

            pub fn deinit(self: *ProveResultV4) void {
                self.proof.deinit();
                self.* = undefined;
            }
        };

        pub const FreshRecursiveIngressV4 = struct {
            node_public: *const @import("recursive_node_artifact_v2.zig").NodePublicV2,
            claims: *const manifest_mod.ClaimVector,
            session: *const secure_artifact.SessionV1,
            statement: *const secure_artifact.StatementV1,
            geometry: *const registry_mod.AuthenticatedGeometryV1,
            capture: *const common_authority.ProofCapture,
            query_words: *const [QUERY_WORD_COUNT]M31,
            query_log_size: u32,
            final_transcript_digest: *const recursion.poseidon2_channel.Digest,
            final_transcript_draw_count: u32,
            query_words_identity_sha256: *const [32]u8,
            manifest: *const manifest_mod.Manifest,

            pub fn validate(self: FreshRecursiveIngressV4) !void {
                try self.node_public.validate();
                try self.manifest.validate();
                try self.claims.validate(self.manifest);
                try self.session.validate();
                try self.statement.validateAgainstSession(self.session);
                try self.geometry.validate();
                if (self.geometry.role != ROLE or
                    self.claims.values.len != manifest_mod.COMPONENT_COUNT or
                    self.capture.commitments.len !=
                        common_authority.COMMITMENT_TREE_COUNT or
                    self.capture.queries.raw.len != QUERY_WORD_COUNT or
                    self.query_log_size == 0 or self.query_log_size >= 31 or
                    try captureQueryLogSize(self.capture) !=
                        self.query_log_size or
                    !std.mem.eql(
                        u8,
                        &self.claims.seal,
                        &self.statement.claims_sha256,
                    ) or !std.meta.eql(
                    self.geometry.preprocessed_root,
                    self.capture.commitments[0],
                ) or !std.meta.eql(
                    self.statement.transcript_id,
                    recursion.protocol.transcriptId(
                        self.final_transcript_digest.*,
                        self.final_transcript_draw_count,
                    ),
                ) or std.mem.allEqual(
                    u8,
                    self.query_words_identity_sha256,
                    0,
                )) return error.EthereumIncrementalUniversalColdProofMismatchV4;
                const mask = (@as(u32, 1) <<
                    @intCast(self.query_log_size)) - 1;
                for (self.query_words.*, self.capture.queries.raw) |
                    full,
                    projected,
                | {
                    const projected_u32 = std.math.cast(u32, projected) orelse
                        return error.EthereumIncrementalUniversalColdProofMismatchV4;
                    if ((full.toU32() & mask) != projected_u32)
                        return error.EthereumIncrementalUniversalColdProofMismatchV4;
                }
                const shape = try registry_mod.sealProofShapeFromCapture(
                    self.capture,
                    self.geometry.component_count,
                    self.geometry.proof_shape.column_log_degree,
                    self.geometry.proof_shape.table_layout_identity_sha256,
                );
                if (!std.meta.eql(shape, self.geometry.proof_shape))
                    return error.EthereumIncrementalUniversalColdProofMismatchV4;
            }
        };

        /// Stable current-process owner. The cohort is heap allocated because
        /// `VerifiedColdReplayV1` seals its exact address.
        pub const OwnedColdProofV4 = struct {
            allocator: std.mem.Allocator,
            materialized: *const Materialized,
            materialized_identity_sha256: [32]u8,
            cohort: *Cohort,
            session: secure_artifact.SessionV1,
            artifact_value: secure_artifact.OwnedArtifactV1,
            artifact_bytes: []u8,
            artifact_sha256: [32]u8,
            cold: Kernel.VerifiedColdReplayV1,
            composition_capture: CaptureTypes.CaptureV4,
            query_authority: CaptureTypes.VerifierQueryAuthorityV4,
            claims: manifest_mod.ClaimVector,
            geometry_value: registry_mod.AuthenticatedGeometryV1,
            node_public: @import("recursive_node_artifact_v2.zig").NodePublicV2,

            pub const ROLE = @import("recursive_circuit_registry_v1.zig")
                .CircuitRoleV4.ethereum_incremental_leaf_wrapper_v4;

            pub fn deinit(self: *OwnedColdProofV4) void {
                self.composition_capture.deinit();
                self.cold.deinit();
                self.artifact_value.deinit();
                self.cohort.deinit();
                self.allocator.destroy(self.cohort);
                self.allocator.free(self.artifact_bytes);
                self.* = undefined;
            }

            pub fn validateBorrowed(self: *const OwnedColdProofV4) !void {
                try self.materialized.validate();
                try self.cohort.validate();
                try self.cohort.validateSession(&self.session);
                try self.artifact_value.validateCustody();
                try self.artifact_value.statement.validateAgainstSession(
                    &self.session,
                );
                try self.cold.validateBorrowed(self.cohort, &self.session);
                try self.query_authority.validateAgainstCold(&self.cold);
                try self.composition_capture.validateAgainstCold(
                    self.cohort,
                    &self.session,
                    &self.cold,
                    false,
                );
                const geometry = try cold_geometry.geometryFromCold(
                    self.cohort,
                    &self.session,
                    &self.cold,
                );
                if (self.materialized != self.cohort.inputs.materialized or
                    !std.mem.eql(
                        u8,
                        &self.materialized_identity_sha256,
                        &self.materialized.identity_sha256,
                    ) or !std.meta.eql(
                    self.cold.fresh.statement,
                    self.artifact_value.statement,
                ) or !std.meta.eql(
                    self.claims,
                    self.cold.replay.claims,
                ) or !std.meta.eql(self.geometry_value, geometry) or
                    !std.meta.eql(
                        self.node_public,
                        self.materialized.schedule.node_public,
                    ) or self.artifact_bytes.len == 0 or
                    !std.mem.eql(
                        u8,
                        &self.artifact_sha256,
                        &sha256(self.artifact_bytes),
                    )) return error.EthereumIncrementalUniversalColdProofMismatchV4;
            }

            pub fn validateColdGeometry(
                self: *const OwnedColdProofV4,
            ) !void {
                try self.validateBorrowed();
            }

            pub fn geometryForPaddingTarget(
                self: *const OwnedColdProofV4,
            ) *const registry_mod.AuthenticatedGeometryV1 {
                return &self.geometry_value;
            }

            pub fn validateForPaddingTarget(
                self: *const OwnedColdProofV4,
                target: *const padding_target_mod.CampaignPaddingTargetV2,
            ) !void {
                try self.validateBorrowed();
                if (self.cohort.padding_target != target)
                    return error.EthereumIncrementalUniversalColdProofMismatchV4;
                try target.validateRemintedGeometry(
                    OwnedColdProofV4.ROLE,
                    &self.geometry_value,
                );
            }

            pub fn ingressView(
                self: *const OwnedColdProofV4,
            ) !FreshRecursiveIngressV4 {
                try self.validateBorrowed();
                const result = FreshRecursiveIngressV4{
                    .node_public = &self.node_public,
                    .claims = &self.claims,
                    .session = &self.session,
                    .statement = &self.cold.fresh.statement,
                    .geometry = &self.geometry_value,
                    .capture = &self.cold.fresh.capture,
                    .query_words = &self.query_authority.query_words,
                    .query_log_size = self.query_authority.query_log_size,
                    .final_transcript_digest = &self.query_authority.final_transcript_digest,
                    .final_transcript_draw_count = self.query_authority.final_transcript_draw_count,
                    .query_words_identity_sha256 = &self.query_authority.query_words_identity_sha256,
                    .manifest = self.cohort.manifest(),
                };
                try result.validate();
                return result;
            }

            pub fn foldGraphView(self: *const OwnedColdProofV4) !Graph {
                try self.validateBorrowed();
                return self.composition_capture.validatedView(
                    &self.query_authority,
                );
            }

            pub fn proofArtifactRef(
                self: *const OwnedColdProofV4,
            ) !artifact_ref_mod.ArtifactRefV1 {
                try self.validateBorrowed();
                const result = artifact_ref_mod.ArtifactRefV1{
                    .kind = PROOF_ARTIFACT_KIND,
                    .format_version = artifact_ref_mod.ARTIFACT_REF_FORMAT_VERSION,
                    .schema_version = PROOF_ARTIFACT_SCHEMA_VERSION,
                    .byte_count = @intCast(self.artifact_bytes.len),
                    .sha256 = self.artifact_sha256,
                };
                try result.validate();
                return result;
            }
        };

        pub fn proveAndColdVerify(
            allocator: std.mem.Allocator,
            materialized: *const Materialized,
            execution: secure_engine.ExecutionOptions,
        ) !ProveResultV4 {
            return proveAtTarget(
                allocator,
                materialized,
                null,
                execution,
            );
        }

        /// Genuine target-native role-0 remint. The target is authenticated
        /// against all three active cold sources before any trace is built.
        pub fn proveAndColdVerifyPreFinal(
            allocator: std.mem.Allocator,
            target: *const padding_target_mod.CampaignPaddingTargetV2,
            active_sources: anytype,
            materialized: *const Materialized,
            execution: secure_engine.ExecutionOptions,
        ) !ProveResultV4 {
            try target.validateAgainstActive(active_sources);
            return proveAtTarget(
                allocator,
                materialized,
                target,
                execution,
            );
        }

        fn proveAtTarget(
            allocator: std.mem.Allocator,
            materialized: *const Materialized,
            target: ?*const padding_target_mod.CampaignPaddingTargetV2,
            execution: secure_engine.ExecutionOptions,
        ) !ProveResultV4 {
            try materialized.validate();
            var cohort = if (target) |padding_target|
                try Cohort.initForPaddingTarget(
                    allocator,
                    .{ .materialized = materialized },
                    padding_target,
                )
            else
                try Cohort.init(
                    allocator,
                    .{ .materialized = materialized },
                );
            defer cohort.deinit();
            const session = try cohort.session();
            var proved = if (target != null)
                Kernel.proveAndColdVerifyWithCohort(
                    allocator,
                    &cohort,
                    session,
                    execution,
                ) catch |err| return stageFailure(
                    "role0.padded-engine",
                    err,
                )
            else
                Kernel.proveAndColdVerify(
                    allocator,
                    .{ .materialized = materialized },
                    session,
                    execution,
                ) catch |err| return stageFailure("role0.engine", err);
            const receipt = proved.receipt;
            const encoded = proved.artifact.encodeCanonicalAlloc(allocator) catch |err| {
                proved.deinit();
                return stageFailure("role0.encode", err);
            };
            proved.deinit();
            defer allocator.free(encoded);
            var proof = if (target) |padding_target|
                coldOpenAtTarget(
                    allocator,
                    materialized,
                    padding_target,
                    encoded,
                ) catch |err| return stageFailure(
                    "role0.padded-cold-open",
                    err,
                )
            else
                coldOpenAtTarget(
                    allocator,
                    materialized,
                    null,
                    encoded,
                ) catch |err| return stageFailure("role0.cold-open", err);
            errdefer proof.deinit();
            return .{ .proof = proof, .receipt = receipt };
        }

        /// Canonical decode followed by one independent q193 verifier and
        /// same-transaction replay retention.
        pub fn coldOpen(
            allocator: std.mem.Allocator,
            materialized: *const Materialized,
            retained_artifact_bytes: []const u8,
        ) !OwnedColdProofV4 {
            return coldOpenAtTarget(
                allocator,
                materialized,
                null,
                retained_artifact_bytes,
            );
        }

        pub fn coldOpenPreFinal(
            allocator: std.mem.Allocator,
            target: *const padding_target_mod.CampaignPaddingTargetV2,
            active_sources: anytype,
            materialized: *const Materialized,
            retained_artifact_bytes: []const u8,
        ) !OwnedColdProofV4 {
            try target.validateAgainstActive(active_sources);
            return coldOpenAtTarget(
                allocator,
                materialized,
                target,
                retained_artifact_bytes,
            );
        }

        fn coldOpenAtTarget(
            allocator: std.mem.Allocator,
            materialized: *const Materialized,
            target: ?*const padding_target_mod.CampaignPaddingTargetV2,
            retained_artifact_bytes: []const u8,
        ) !OwnedColdProofV4 {
            try materialized.validate();
            var artifact_value = try secure_artifact.OwnedArtifactV1
                .decodeCanonical(allocator, retained_artifact_bytes);
            errdefer artifact_value.deinit();
            const cohort = try allocator.create(Cohort);
            var cohort_initialized = false;
            errdefer {
                if (cohort_initialized) cohort.deinit();
                allocator.destroy(cohort);
            }
            cohort.* = if (target) |padding_target|
                try Cohort.initForPaddingTarget(
                    allocator,
                    .{ .materialized = materialized },
                    padding_target,
                )
            else
                try Cohort.init(
                    allocator,
                    .{ .materialized = materialized },
                );
            cohort_initialized = true;
            const session = try cohort.session();
            var cold = try Kernel.verifyColdWithReplay(
                allocator,
                cohort,
                &session,
                &artifact_value,
            );
            errdefer cold.deinit();
            const query_authority = try CaptureTypes.VerifierQueryAuthorityV4
                .init(&cold.replay);
            var graph = try CaptureTypes.CaptureV4.initFromColdReplay(
                allocator,
                cohort,
                &session,
                &cold,
            );
            errdefer graph.deinit();
            const geometry = try cold_geometry.geometryFromCold(
                cohort,
                &session,
                &cold,
            );
            const artifact_bytes = try allocator.dupe(
                u8,
                retained_artifact_bytes,
            );
            errdefer allocator.free(artifact_bytes);
            var result = OwnedColdProofV4{
                .allocator = allocator,
                .materialized = materialized,
                .materialized_identity_sha256 = materialized.identity_sha256,
                .cohort = cohort,
                .session = session,
                .artifact_value = artifact_value,
                .artifact_bytes = artifact_bytes,
                .artifact_sha256 = sha256(artifact_bytes),
                .cold = cold,
                .composition_capture = graph,
                .query_authority = query_authority,
                .claims = cold.replay.claims,
                .geometry_value = geometry,
                .node_public = materialized.schedule.node_public,
            };
            try result.validateBorrowed();
            return result;
        }
    };
}

fn captureQueryLogSize(
    capture: *const common_authority.ProofCapture,
) !u32 {
    if (capture.column_log_sizes.len !=
        common_authority.COMMITMENT_TREE_COUNT or
        capture.trace_paths.len != common_authority.COMMITMENT_TREE_COUNT)
    {
        return error.EthereumIncrementalUniversalColdProofMismatchV4;
    }
    const composition_index = common_authority.COMMITMENT_TREE_COUNT - 1;
    const logs = capture.column_log_sizes[composition_index];
    if (logs.len == 0)
        return error.EthereumIncrementalUniversalColdProofMismatchV4;
    var query_log_size: u32 = 0;
    for (logs) |log_size| {
        if (log_size == 0 or log_size >= 31)
            return error.EthereumIncrementalUniversalColdProofMismatchV4;
        query_log_size = @max(query_log_size, log_size);
    }
    if (capture.trace_paths[composition_index].path_depth != query_log_size)
        return error.EthereumIncrementalUniversalColdProofMismatchV4;
    return query_log_size;
}

fn sha256(bytes: []const u8) [32]u8 {
    var result: [32]u8 = undefined;
    Sha256.hash(bytes, &result, .{});
    return result;
}

fn requireRecursionEngine(comptime Engine: type) void {
    if (Engine.Hasher.Hash != recursion.poseidon2_channel.Digest or
        Engine.Channel != recursion.poseidon2_channel.Channel)
    {
        @compileError("role-0 universal proof requires q193 Poseidon2 engine");
    }
}

fn stageFailure(comptime stage: []const u8, err: anyerror) anyerror {
    if (builtin.is_test) std.debug.print(
        "ETHEREUM_INCREMENTAL_ROLE0_Q193_STAGE={s} error={s}\n",
        .{ stage, @errorName(err) },
    );
    return err;
}

comptime {
    if (FORMAT_VERSION != 4 or SCHEMA_VERSION != 3 or
        @intFromEnum(ROLE) != 0 or QUERY_WORD_COUNT != 193 or
        PROOF_ARTIFACT_KIND != 8 or PROOF_ARTIFACT_SCHEMA_VERSION != 1 or
        PRODUCTION_ACTIVATION or !COLD_VERIFICATION_BEFORE_CAPABILITY or
        SERIALIZABLE_FRESH_CAPABILITY)
    {
        @compileError("role-0 universal proof core V4 drifted");
    }
}
