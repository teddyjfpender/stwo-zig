//! Genuine target-native q193 proof owner for pre-final common-fold geometry.
//!
//! The transaction consumes two nominal role-0/role-1 pre-final children
//! bound to one authenticated campaign padding target.  Its own role-2
//! geometry is minted only from the independently cold-verified capture.  The
//! owner is intentionally unrouteable and has no durable node until all three
//! role geometries mint FinalRemint.

const std = @import("std");
const builtin = @import("builtin");
const frontend = @import("stwo_riscv_frontend");

const live_mod =
    @import("recursive_common_fold_campaign_prefinal_live_v2.zig");
const fixed_source = @import("recursive_common_fold_fixed_wire_v2.zig");
const secure_cohort = @import("recursive_common_fold_secure_cohort_v2.zig");
const graph_mod = @import("recursive_common_fold_composition_graph_v2.zig");
const capture_mod = @import("recursive_common_fold_composition_capture_v2.zig");
const geometry_mod =
    @import("recursive_common_fold_campaign_prefinal_geometry_v2.zig");
const manifest_mod = @import("recursive_common_fold_universal_manifest_v2.zig");
const target_mod = @import("recursive_pipeline_campaign_padding_target_v2.zig");
const prefinal =
    @import("recursive_pipeline_campaign_prefinal_fold_lease_v2.zig");
const registry_mod = @import("recursive_circuit_registry_v1.zig");
const artifact_v1 = @import("recursive_node_artifact_v1.zig");
const common_authority = @import("recursive_common_wrapper_authority_v2.zig");
const secure_artifact =
    @import("recursive_temporal_secure_parent_artifact_v1.zig");
const secure_engine =
    @import("recursive_temporal_secure_parent_native_engine_v1.zig");
const process_validation =
    @import("recursive_process_local_validation_token_v1.zig");
const cold_token = @import("recursive_common_fold_cold_token_v2.zig");

const recursion = frontend.recursion;

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const ROLE = registry_mod.CircuitRoleV1.common_fold_field_v2;
pub const FRI_QUERY_COUNT: u32 = 193;
pub const PRODUCTION_ACTIVATION = false;
pub const ROUTER_ACTIVATION = false;
pub const SERIALIZABLE_FRESH_CAPABILITY = false;
pub const DURABLE_PREFINAL_NODE_AVAILABLE = false;

pub fn Types(
    comptime dimensions: recursion.fixed_wire.Dimensions,
    comptime RealLease: type,
    comptime EmptyLease: type,
) type {
    const LiveTypes = live_mod.Types(RealLease, EmptyLease);
    return TypesForLive(dimensions, LiveTypes);
}

/// Shared q193 owner used both to mint the initial role-2 geometry and to
/// prove later all-role campaign folds. `LiveTypes` supplies the nominally
/// typed, target-bound children; proof bytes and cold verification remain the
/// same secure-engine transaction.
pub fn TypesForLive(
    comptime dimensions: recursion.fixed_wire.Dimensions,
    comptime LiveTypes: type,
) type {
    dimensions.validate();
    const Live = LiveTypes.LiveV2;
    const Fixed = fixed_source.TypesForLive(
        dimensions,
        Live,
        LiveTypes.FixedPolicyV2,
    );
    const ManifestPolicy = LiveTypes.ManifestPolicyV2(Fixed);
    const SecureCohort = secure_cohort.CohortForLiveV2(
        dimensions,
        Live,
        Fixed,
        ManifestPolicy,
    );
    const Graph = graph_mod.TypesForCohort(dimensions, SecureCohort);
    const CaptureTypes = capture_mod.TypesForGraph(dimensions, Graph);
    const Kernel = Graph.KernelV2;

    return struct {
        pub const LiveTypesV2 = LiveTypes;
        pub const LiveV2 = Live;
        pub const FixedV2 = Fixed;
        pub const SecureCohortV2 = SecureCohort;
        pub const GraphV2 = Graph;
        pub const CaptureTypesV2 = CaptureTypes;
        pub const KernelV2 = Kernel;
        pub const ExecutionOptions = secure_engine.ExecutionOptions;

        pub const ProveResultV2 = struct {
            proof: OwnedColdProofV2,
            receipt: secure_engine.ReceiptV1,

            pub fn deinit(self: *ProveResultV2) void {
                self.proof.deinit();
                self.* = undefined;
            }
        };

        pub const OwnedColdProofV2 = struct {
            pub const ROLE = registry_mod.CircuitRoleV1.common_fold_field_v2;

            allocator: std.mem.Allocator,
            padding_target: *const target_mod.CampaignPaddingTargetV2,
            live: *const Live,
            live_identity_sha256: [32]u8,
            session: secure_artifact.SessionV1,
            artifact_value: secure_artifact.OwnedArtifactV1,
            artifact_bytes: []u8,
            fresh: secure_engine.FreshVerificationV1,
            composition_capture: CaptureTypes.CaptureV2,
            query_authority: CaptureTypes.VerifierQueryAuthorityV2,
            claims: manifest_mod.ClaimVector,
            manifest_value: manifest_mod.Manifest,
            geometry_value: registry_mod.AuthenticatedGeometryV1,
            node_public: @import("recursive_node_artifact_v2.zig").NodePublicV2,
            validation: *process_validation.ValidatedOwnerV1,

            pub fn deinit(self: *OwnedColdProofV2) void {
                self.allocator.destroy(self.validation);
                self.composition_capture.deinit();
                self.fresh.deinit();
                self.artifact_value.deinit();
                self.allocator.free(self.artifact_bytes);
                self.* = undefined;
            }

            pub fn validateForPaddingTarget(
                self: *const OwnedColdProofV2,
                target: *const target_mod.CampaignPaddingTargetV2,
            ) !void {
                var timer = startTimer();
                defer self.validation.counters.recordTimed(
                    .token_check,
                    readTimer(&timer),
                );
                if (self.padding_target != target or
                    self.live.padding_target != target or
                    !std.mem.eql(
                        u8,
                        &self.live_identity_sha256,
                        &self.live.identity_sha256,
                    )) return error.CampaignPreFinalCommonProofMismatch;
                try target.validateSelf();
                try self.live.validate();
                try self.composition_capture.validateProcessLocalClosure(
                    &self.validation.token,
                );
                try self.validation.token.validateAgainst(
                    try cold_token.snapshot(self),
                );
                try self.artifact_value.validateCustody();
                try self.artifact_value.statement.validateAgainstSession(
                    &self.session,
                );
                try self.claims.validate(&self.manifest_value);
                try geometry_mod.validateFreshGeometry(
                    target,
                    &self.manifest_value,
                    &self.fresh,
                    &self.geometry_value,
                );
                if (!std.meta.eql(
                    self.fresh.statement,
                    self.artifact_value.statement,
                ) or !std.meta.eql(
                    self.node_public,
                    self.live.input.parent_node_public,
                )) return error.CampaignPreFinalCommonProofMismatch;
            }

            pub fn validateColdGeometry(
                self: *const OwnedColdProofV2,
            ) !void {
                try self.validateForPaddingTarget(self.padding_target);
            }

            pub fn geometryForPaddingTarget(
                self: *const OwnedColdProofV2,
            ) *const registry_mod.AuthenticatedGeometryV1 {
                return &self.geometry_value;
            }

            pub fn proofBytes(self: *const OwnedColdProofV2) []const u8 {
                return self.artifact_bytes;
            }

            /// Typed transport reference for the proof bytes owned and
            /// canonically encoded by this Zig cold verifier. This SHA is CAS
            /// custody only; it never substitutes for the q193 capability.
            pub fn proofArtifactRef(
                self: *const OwnedColdProofV2,
            ) !artifact_v1.ArtifactRefV1 {
                try self.validateForPaddingTarget(self.padding_target);
                var digest: [32]u8 = undefined;
                std.crypto.hash.sha2.Sha256.hash(
                    self.artifact_bytes,
                    &digest,
                    .{},
                );
                const result = artifact_v1.ArtifactRefV1{
                    .kind = common_authority.PROOF_ARTIFACT_KIND,
                    .format_version = artifact_v1
                        .ARTIFACT_REF_FORMAT_VERSION,
                    .schema_version = 1,
                    .byte_count = @intCast(self.artifact_bytes.len),
                    .sha256 = digest,
                };
                try result.validate();
                return result;
            }

            pub fn preFinalFoldProjection(
                self: *const OwnedColdProofV2,
                target: *const target_mod.CampaignPaddingTargetV2,
            ) !prefinal.ProjectionV2 {
                try self.validateForPaddingTarget(target);
                const graph = try self.composition_capture
                    .borrowProcessLocalView(
                    &self.query_authority,
                    &self.validation.token,
                );
                const result = prefinal.ProjectionV2{
                    .role = OwnedColdProofV2.ROLE,
                    .padding_target = target,
                    .geometry = &self.geometry_value,
                    .node_public = &self.node_public,
                    .claimed_sums = &self.claims.values,
                    .claims_seal = &self.claims.seal,
                    .session = &self.session,
                    .statement = &self.fresh.statement,
                    .capture = &self.fresh.capture,
                    .query_words = &self.query_authority.query_words,
                    .query_log_size = self.query_authority.query_log_size,
                    .final_transcript_digest = &self.query_authority
                        .final_transcript_digest,
                    .final_transcript_draw_count = self.query_authority
                        .final_transcript_draw_count,
                    .query_words_identity_sha256 = &self.query_authority
                        .query_words_identity_sha256,
                    .graph = .{
                        .capture_identity_sha256 = graph.capture_identity_sha256,
                        .layout_identity_sha256 = graph.layout_identity_sha256,
                        .query_words = graph.query_words,
                        .query_log_size = graph.query_log_size,
                        .final_transcript_digest = graph.final_transcript_digest,
                        .final_transcript_draw_count = graph
                            .final_transcript_draw_count,
                        .query_words_identity_sha256 = graph
                            .query_words_identity_sha256,
                        .lane = graph.lane,
                        .evaluation = graph.evaluation,
                    },
                };
                try result.validateAgainstPaddingTarget(target);
                return result;
            }

            pub fn performanceSnapshot(
                self: *const OwnedColdProofV2,
            ) process_validation.CounterSnapshotV1 {
                return self.validation.counters.snapshot();
            }
        };

        pub fn proveAndColdVerify(
            allocator: std.mem.Allocator,
            target: *const target_mod.CampaignPaddingTargetV2,
            live: *const Live,
            execution: ExecutionOptions,
        ) !ProveResultV2 {
            try validateLiveTarget(target, live);
            var cohort = try SecureCohort.init(allocator, .{ .live = live });
            defer cohort.deinit();
            const session = try cohort.session();
            var proved = Kernel.proveAndColdVerify(
                allocator,
                .{ .live = live },
                session,
                execution,
            ) catch |err| return stageFailure("role2.engine", err);
            errdefer proved.deinit();
            const receipt = proved.receipt;
            var proof = try ownResult(
                allocator,
                target,
                live,
                session,
                proved.artifact,
                proved.fresh,
                receipt.cold_verify_ns,
            );
            proved.artifact = undefined;
            proved.fresh = undefined;
            errdefer proof.deinit();
            return .{ .proof = proof, .receipt = receipt };
        }

        pub fn coldOpen(
            allocator: std.mem.Allocator,
            target: *const target_mod.CampaignPaddingTargetV2,
            live: *const Live,
            proof_bytes: []const u8,
        ) !OwnedColdProofV2 {
            try validateLiveTarget(target, live);
            var artifact_value = try secure_artifact.OwnedArtifactV1
                .decodeCanonical(allocator, proof_bytes);
            errdefer artifact_value.deinit();
            var cohort = try SecureCohort.init(allocator, .{ .live = live });
            defer cohort.deinit();
            const session = try cohort.session();
            var timer = startTimer();
            var verified = try Kernel.verifyColdWithReplay(
                allocator,
                &cohort,
                &session,
                &artifact_value,
            );
            const verify_and_replay_ns = readTimer(&timer);
            errdefer verified.deinit();
            try verified.validateBorrowed(&cohort, &session);
            const result = try ownPreparedResult(
                allocator,
                target,
                live,
                session,
                artifact_value,
                verified.fresh,
                &cohort,
                verified.replay,
                verify_and_replay_ns -| verified.replay_finalize_ns,
                verified.replay_finalize_ns,
            );
            verified.fresh = undefined;
            return result;
        }

        fn ownResult(
            allocator: std.mem.Allocator,
            target: *const target_mod.CampaignPaddingTargetV2,
            live: *const Live,
            session: secure_artifact.SessionV1,
            artifact_value: secure_artifact.OwnedArtifactV1,
            fresh: secure_engine.FreshVerificationV1,
            cold_verify_ns: u64,
        ) !OwnedColdProofV2 {
            var cohort = try SecureCohort.init(allocator, .{ .live = live });
            defer cohort.deinit();
            var replay_timer = startTimer();
            const replay = try Kernel.reconstructVerifiedReplayWithCohort(
                allocator,
                &cohort,
                &session,
                &fresh,
            );
            const replay_ns = readTimer(&replay_timer);
            return ownPreparedResult(
                allocator,
                target,
                live,
                session,
                artifact_value,
                fresh,
                &cohort,
                replay,
                cold_verify_ns,
                replay_ns,
            );
        }

        fn ownPreparedResult(
            allocator: std.mem.Allocator,
            target: *const target_mod.CampaignPaddingTargetV2,
            live: *const Live,
            session: secure_artifact.SessionV1,
            artifact_value: secure_artifact.OwnedArtifactV1,
            fresh: secure_engine.FreshVerificationV1,
            cohort: *SecureCohort,
            replay: Kernel.VerifiedReplay,
            cold_verify_ns: u64,
            replay_ns: u64,
        ) !OwnedColdProofV2 {
            const query_authority = try CaptureTypes.VerifierQueryAuthorityV2
                .init(&replay);
            var graph_timer = startTimer();
            var graph = try CaptureTypes.CaptureV2.init(
                allocator,
                cohort,
                &session,
                &fresh.statement,
                &fresh.capture,
                &replay,
            );
            const graph_ns = readTimer(&graph_timer);
            errdefer graph.deinit();
            const geometry = try geometry_mod.geometryFromFresh(
                target,
                cohort.manifest(),
                &fresh,
            );
            const artifact_bytes = try artifact_value.encodeCanonicalAlloc(
                allocator,
            );
            errdefer allocator.free(artifact_bytes);
            const validation = try allocator.create(
                process_validation.ValidatedOwnerV1,
            );
            errdefer allocator.destroy(validation);
            validation.* = undefined;
            var result = OwnedColdProofV2{
                .allocator = allocator,
                .padding_target = target,
                .live = live,
                .live_identity_sha256 = live.identity_sha256,
                .session = session,
                .artifact_value = artifact_value,
                .artifact_bytes = artifact_bytes,
                .fresh = fresh,
                .composition_capture = graph,
                .query_authority = query_authority,
                .claims = replay.claims,
                .manifest_value = cohort.manifest().*,
                .geometry_value = geometry,
                .node_public = live.input.parent_node_public,
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
            validation.counters.recordTimed(.graph_record, graph_ns);
            try result.validateForPaddingTarget(target);
            return result;
        }

        fn validateLiveTarget(
            target: *const target_mod.CampaignPaddingTargetV2,
            live: *const Live,
        ) !void {
            try target.validateSelf();
            try live.validate();
            if (live.padding_target != target)
                return error.CampaignPreFinalCommonProofMismatch;
        }
    };
}

fn startTimer() ?std.time.Timer {
    return std.time.Timer.start() catch null;
}

fn readTimer(timer: *?std.time.Timer) u64 {
    if (timer.*) |*active| return active.read();
    return 0;
}

fn stageFailure(comptime stage: []const u8, err: anyerror) anyerror {
    if (builtin.is_test) std.debug.print(
        "CAMPAIGN_PREFINAL_COMMON_Q193_STAGE={s} error={s}\n",
        .{ stage, @errorName(err) },
    );
    return err;
}

comptime {
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 1 or
        @intFromEnum(ROLE) != 2 or FRI_QUERY_COUNT != 193 or
        PRODUCTION_ACTIVATION or ROUTER_ACTIVATION or
        SERIALIZABLE_FRESH_CAPABILITY or DURABLE_PREFINAL_NODE_AVAILABLE)
    {
        @compileError("campaign pre-final common proof contract drifted");
    }
}
