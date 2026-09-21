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

const transcript_program = @import("recursive_common_ethereum_incremental_leaf_transcript_program_v4.zig");
const root_command = @import("ethereum_wrapper_root_command_v1.zig");
const recursion = frontend.recursion;
const CpuPreparationEngine = recursion.engine.ProverEngineForBackend(@import("stwo_cpu_backend").CpuBackend);
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

        /// Canonical bytes after native STARK verification. This owns no cold
        /// wrapper capability: consumers must admit the bytes through coldOpen.
        pub const EncodedProofV4 = struct {
            allocator: std.mem.Allocator,
            bytes: []u8,
            receipt: secure_engine.ReceiptV1,
            root_bundle: ?root_command.BundleLocationV1 = null,

            pub fn deinit(self: *EncodedProofV4) void {
                if (self.root_bundle) |*bundle| bundle.deinit();
                self.allocator.free(self.bytes);
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
            const OpaqueStorage = opaque {};
            backing: *OpaqueStorage,

            // Mutable proof-capture custody stays private. Metadata and the
            // prepared graph have no public mutable aliases. Legacy capture
            // ingress remains explicitly checked because its core slice type
            // is not deeply readonly.
            const Storage = struct {
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
                prepared_graph: Graph,
                artifact_ref: artifact_ref_mod.ArtifactRefV1,

                fn validateSourceIdentity(self: *const Storage) !void {
                    if (!std.mem.eql(u8, &self.materialized_identity_sha256, &self.materialized.identity_sha256))
                        return error.EthereumIncrementalUniversalColdProofMismatchV4;
                }
            };

            fn storage(self: *OwnedColdProofV4) *Storage {
                return @ptrCast(@alignCast(self.backing));
            }
            fn storageConst(self: *const OwnedColdProofV4) *const Storage {
                return @ptrCast(@alignCast(self.backing));
            }

            pub const ROLE = @import("recursive_circuit_registry_v1.zig")
                .CircuitRoleV4.ethereum_incremental_leaf_wrapper_v4;

            pub fn deinit(self: *OwnedColdProofV4) void {
                const value = storage(self);
                const allocator = value.allocator;
                value.composition_capture.deinit();
                value.cold.deinit();
                value.artifact_value.deinit();
                value.cohort.deinit();
                allocator.destroy(value.cohort);
                allocator.free(value.artifact_bytes);
                value.* = undefined;
                allocator.destroy(value);
                self.* = undefined;
            }

            pub fn validateBorrowed(self: *const OwnedColdProofV4) !void {
                const value = storageConst(self);
                // A changed and resealed external source cannot refresh this
                // owner's admission. Matching custody still needs the full
                // proof/input checks below.
                try value.validateSourceIdentity();
                try value.materialized.validate();
                try value.cohort.validate();
                try value.cohort.validateSession(&value.session);
                try value.artifact_value.validateCustody();
                try value.artifact_value.statement.validateAgainstSession(
                    &value.session,
                );
                try value.cold.validateBorrowed(value.cohort, &value.session);
                try value.query_authority.validateAgainstCold(&value.cold);
                // Construction validates the complete graph before privately
                // owning it. Only deeply const graph views escape. Recheck all
                // mutable source/capture inputs without rebuilding that graph.
                try value.composition_capture.validateInputSourcesAgainstCold(
                    value.cohort,
                    &value.session,
                    &value.cold,
                );
                const geometry = try cold_geometry.geometryFromCold(
                    value.cohort,
                    &value.session,
                    &value.cold,
                );
                if (value.materialized != value.cohort.materializedOwner() or
                    !std.mem.eql(
                        u8,
                        &value.materialized_identity_sha256,
                        &value.materialized.identity_sha256,
                    ) or !std.meta.eql(
                    value.cold.fresh.statement,
                    value.artifact_value.statement,
                ) or !std.meta.eql(
                    value.claims,
                    value.cold.replay.claims,
                ) or !std.meta.eql(value.geometry_value, geometry) or
                    !std.meta.eql(
                        value.node_public,
                        value.materialized.schedule.node_public,
                    ) or value.artifact_bytes.len == 0 or
                    !std.mem.eql(
                        u8,
                        &value.artifact_sha256,
                        &sha256(value.artifact_bytes),
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
                return &storageConst(self).geometry_value;
            }

            pub fn validateForPaddingTarget(
                self: *const OwnedColdProofV4,
                target: *const padding_target_mod.CampaignPaddingTargetV2,
            ) !void {
                const value = storageConst(self);
                try self.validateBorrowed();
                if (value.cohort.paddingTarget() != target)
                    return error.EthereumIncrementalUniversalColdProofMismatchV4;
                try target.validateRemintedGeometry(
                    OwnedColdProofV4.ROLE,
                    &value.geometry_value,
                );
            }

            pub const BorrowedViews = struct {
                ingress: FreshRecursiveIngressV4,
                graph: Graph,
            };

            /// Accept mutable sources once and project the current owned views.
            /// The returned data is not reusable acceptance: later public
            /// acquisitions still validate the current external capture bytes.
            pub fn borrowedViews(self: *const OwnedColdProofV4) !BorrowedViews {
                try self.validateBorrowed();
                return self.projectBorrowedViews();
            }

            fn projectBorrowedViews(self: *const OwnedColdProofV4) !BorrowedViews {
                const value = storageConst(self);
                const result = FreshRecursiveIngressV4{
                    .node_public = &value.node_public,
                    .claims = &value.claims,
                    .session = &value.session,
                    .statement = &value.cold.fresh.statement,
                    .geometry = &value.geometry_value,
                    .capture = &value.cold.fresh.capture,
                    .query_words = &value.query_authority.query_words,
                    .query_log_size = value.query_authority.query_log_size,
                    .final_transcript_digest = &value.query_authority.final_transcript_digest,
                    .final_transcript_draw_count = value.query_authority.final_transcript_draw_count,
                    .query_words_identity_sha256 = &value.query_authority.query_words_identity_sha256,
                    .manifest = value.cohort.manifest(),
                };
                try result.validate();
                return .{ .ingress = result, .graph = value.prepared_graph };
            }

            pub fn ingressView(
                self: *const OwnedColdProofV4,
            ) !FreshRecursiveIngressV4 {
                return (try self.borrowedViews()).ingress;
            }

            pub fn foldGraphView(self: *const OwnedColdProofV4) !Graph {
                return storageConst(self).prepared_graph;
            }

            pub fn proofArtifactRef(self: *const OwnedColdProofV4) !artifact_ref_mod.ArtifactRefV1 {
                return storageConst(self).artifact_ref;
            }

            pub fn backingAllocator(self: *const OwnedColdProofV4) std.mem.Allocator {
                return storageConst(self).allocator;
            }

            /// Alias custody only; the enclosing evidence boundary still calls
            /// validateBorrowed before accepting a legacy capture projection.
            pub fn validateCaptureAlias(self: *const OwnedColdProofV4, capture: *const common_authority.ProofCapture) !void {
                if (capture != &storageConst(self).cold.fresh.capture)
                    return error.EthereumIncrementalUniversalColdProofMismatchV4;
            }

            pub fn artifactBytes(self: *const OwnedColdProofV4) []const u8 {
                return storageConst(self).artifact_bytes;
            }
            pub fn materializedOwner(self: *const OwnedColdProofV4) *const Materialized {
                return storageConst(self).materialized;
            }
            pub fn paddingTarget(self: *const OwnedColdProofV4) ?*const padding_target_mod.CampaignPaddingTargetV2 {
                return storageConst(self).cohort.paddingTarget();
            }
            pub fn nodePublic(self: *const OwnedColdProofV4) *const @import("recursive_node_artifact_v2.zig").NodePublicV2 {
                return &storageConst(self).node_public;
            }
            pub fn claimsView(self: *const OwnedColdProofV4) *const manifest_mod.ClaimVector {
                return &storageConst(self).claims;
            }
            pub fn sessionView(self: *const OwnedColdProofV4) *const secure_artifact.SessionV1 {
                return &storageConst(self).session;
            }

            /// Compatibility boundary for consumers of the existing core
            /// capture type. Its nested slices are mutable, so this is never
            /// an unchecked immutable preparation getter.
            pub fn captureView(self: *const OwnedColdProofV4) !*const common_authority.ProofCapture {
                try self.validateBorrowed();
                return &storageConst(self).cold.fresh.capture;
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

        /// Produce durable bytes for a later independent wrapper admission.
        /// Native verification and candidate retention use the same path as
        /// proveAndColdVerify, without constructing a producer-side cold owner.
        pub fn proveCanonical(
            allocator: std.mem.Allocator,
            materialized: *const Materialized,
            execution: secure_engine.ExecutionOptions,
        ) !EncodedProofV4 {
            return proveCanonicalAtTarget(CpuPreparationEngine, allocator, materialized, null, execution);
        }

        /// Hybrid execution: only circuit Tree0 preparation uses the selected
        /// engine; the wrapper proof and verifier remain on their CPU route.
        /// The caller owns and admits any device runtime for the entire call.
        pub fn proveCanonicalWithPreparationEngine(
            comptime PreparationEngine: type,
            allocator: std.mem.Allocator,
            materialized: *const Materialized,
            execution: secure_engine.ExecutionOptions,
        ) !EncodedProofV4 {
            return proveCanonicalAtTarget(PreparationEngine, allocator, materialized, null, execution);
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

        fn initCohortWithWorkers(
            comptime PreparationEngine: type,
            allocator: std.mem.Allocator,
            materialized: *const Materialized,
            target: ?*const padding_target_mod.CampaignPaddingTargetV2,
            worker_count: usize,
        ) !Cohort {
            return initSelectedCohortWithWorkers(Cohort, PreparationEngine, allocator, materialized, target, worker_count);
        }

        fn initSelectedCohortWithWorkers(
            comptime SelectedCohort: type,
            comptime PreparationEngine: type,
            allocator: std.mem.Allocator,
            materialized: *const Materialized,
            target: ?*const padding_target_mod.CampaignPaddingTargetV2,
            worker_count: usize,
        ) !SelectedCohort {
            var scope: @import("ethereum_native_verification_scope_v1.zig").ScopeV1 = undefined;
            try scope.initInPlace(worker_count);
            defer scope.deinit();
            std.debug.print("ETHEREUM_WRAPPER_PREPARATION workers={d} phase=cohort-admission tree0_backend={s} proof_backend=cpu\n", .{ scope.workerCount(), if (PreparationEngine.Backend == CpuPreparationEngine.Backend) "cpu" else "authenticated-device-pcs" });
            return SelectedCohort.initWithPreparationEngine(PreparationEngine, allocator, .{ .materialized = materialized }, target);
        }

        fn proveCanonicalAtTarget(
            comptime PreparationEngine: type,
            allocator: std.mem.Allocator,
            materialized: *const Materialized,
            target: ?*const padding_target_mod.CampaignPaddingTargetV2,
            execution: secure_engine.ExecutionOptions,
        ) !EncodedProofV4 {
            try materialized.validate();
            try transcript_program.requireFieldBaseClaimAdmission(&materialized.base.input.stage101.profile);
            if (materialized.program_admission == null) return error.EthereumWholeProgramAdmissionRequired;
            if (materialized.initial_input_admission != null) {
                const InitialCohort = @import("recursive_common_ethereum_incremental_leaf_secure_cohort_v4.zig").InitialCohortV1(Engine);
                const InitialKernel = secure_engine.EngineKernelForManifest(InitialCohort, recursion.air.ethereum_initial_input_manifest_v1, .ethereum_incremental_field_v1);
                return produceCanonicalSelected(InitialCohort, InitialKernel, root_command.Initial38, PreparationEngine, allocator, materialized, target, execution);
            }
            return produceCanonicalSelected(Cohort, Kernel, root_command.Ordinary, PreparationEngine, allocator, materialized, target, execution);
        }

        fn produceCanonicalSelected(
            comptime SelectedCohort: type,
            comptime SelectedKernel: type,
            comptime RootCommand: type,
            comptime PreparationEngine: type,
            allocator: std.mem.Allocator,
            materialized: *const Materialized,
            target: ?*const padding_target_mod.CampaignPaddingTargetV2,
            execution: secure_engine.ExecutionOptions,
        ) !EncodedProofV4 {
            var production = blk: {
                var cohort = try initSelectedCohortWithWorkers(SelectedCohort, PreparationEngine, allocator, materialized, target, execution.worker_count);
                defer cohort.deinit();
                const session = try cohort.session();
                // This cohort already owns the authenticated preparation used to
                // derive the session. Reuse it through the kernel's checked entry
                // point; later coldOpen reconstructs fresh wrapper authority.
                var proved = SelectedKernel.proveAndColdVerifyWithReplay(
                    allocator,
                    &cohort,
                    session,
                    execution,
                ) catch |err| return if (target != null)
                    stageFailure("role0.padded-engine", err)
                else
                    stageFailure("role0.engine", err);
                defer proved.deinit();
                const encoded = proved.result.artifact.encodeCanonicalAlloc(allocator) catch |err|
                    return stageFailure("role0.encode", err);
                errdefer allocator.free(encoded);
                // Retain the actual verified proof even if later key export or
                // independent wrapper admission fails.
                try @import("ethereum_wrapper_candidate_v1.zig").retain(allocator, encoded);
                const root_bundle = if (proved.result.receipt.transcript_flavor == .ethereum_incremental_field_v1) root: {
                    const key_json = try cohort.encodeVerifierKey(allocator);
                    defer allocator.free(key_json);
                    break :root try RootCommand.retainCandidate(
                        allocator,
                        key_json,
                        materialized.schedule.node_public,
                        .{ .values = proved.replay.claims.values, .poseidon_partials = proved.replay.generated.native.poseidon2_partials },
                        proved.result.artifact.statement.interaction_pow_nonce,
                        proved.result.artifact.proof_bytes,
                    );
                } else null;
                break :blk .{ .bytes = encoded, .receipt = proved.result.receipt, .root_bundle = root_bundle };
            };
            const encoded = production.bytes;
            errdefer allocator.free(encoded);
            errdefer if (production.root_bundle) |*bundle| bundle.deinit();
            return .{ .allocator = allocator, .bytes = encoded, .receipt = production.receipt, .root_bundle = production.root_bundle };
        }

        fn proveAtTarget(
            allocator: std.mem.Allocator,
            materialized: *const Materialized,
            target: ?*const padding_target_mod.CampaignPaddingTargetV2,
            execution: secure_engine.ExecutionOptions,
        ) !ProveResultV4 {
            if (materialized.initial_input_admission != null) return error.EthereumInitialRootVerificationRequired;
            var production = try proveCanonicalAtTarget(CpuPreparationEngine, allocator, materialized, target, execution);
            defer production.deinit();
            const encoded = production.bytes;
            var proof = if (target) |padding_target|
                coldOpenAtTarget(
                    CpuPreparationEngine,
                    allocator,
                    materialized,
                    padding_target,
                    encoded,
                    execution.worker_count,
                ) catch |err| return stageFailure(
                    "role0.padded-cold-open",
                    err,
                )
            else
                coldOpenAtTarget(
                    CpuPreparationEngine,
                    allocator,
                    materialized,
                    null,
                    encoded,
                    execution.worker_count,
                ) catch |err| return stageFailure("role0.cold-open", err);
            errdefer proof.deinit();
            return .{ .proof = proof, .receipt = production.receipt };
        }

        /// Canonical decode followed by one independent q193 verifier and
        /// same-transaction replay retention.
        pub fn coldOpen(
            allocator: std.mem.Allocator,
            materialized: *const Materialized,
            retained_artifact_bytes: []const u8,
        ) !OwnedColdProofV4 {
            return coldOpenWithWorkers(allocator, materialized, retained_artifact_bytes, 1);
        }

        pub fn coldOpenWithWorkers(
            allocator: std.mem.Allocator,
            materialized: *const Materialized,
            retained_artifact_bytes: []const u8,
            worker_count: usize,
        ) !OwnedColdProofV4 {
            return coldOpenAtTarget(CpuPreparationEngine, allocator, materialized, null, retained_artifact_bytes, worker_count);
        }

        /// Keep the preparation choice explicit during independent admission.
        /// This does not trust a producer root or skip any cold proof checks.
        pub fn coldOpenWithPreparationEngine(
            comptime PreparationEngine: type,
            allocator: std.mem.Allocator,
            materialized: *const Materialized,
            retained_artifact_bytes: []const u8,
            worker_count: usize,
        ) !OwnedColdProofV4 {
            return coldOpenAtTarget(PreparationEngine, allocator, materialized, null, retained_artifact_bytes, worker_count);
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
                CpuPreparationEngine,
                allocator,
                materialized,
                target,
                retained_artifact_bytes,
                1,
            );
        }

        fn coldOpenAtTarget(
            comptime PreparationEngine: type,
            allocator: std.mem.Allocator,
            materialized: *const Materialized,
            target: ?*const padding_target_mod.CampaignPaddingTargetV2,
            retained_artifact_bytes: []const u8,
            worker_count: usize,
        ) !OwnedColdProofV4 {
            if (materialized.initial_input_admission != null) return error.EthereumInitialRootVerificationRequired;
            var phases = @import("ethereum_wrapper_resources_v1.zig").Measurements.init();
            errdefer phases.mark("cold.failed");
            try materialized.validate();
            try transcript_program.requireFieldBaseClaimAdmission(&materialized.base.input.stage101.profile);
            if (materialized.program_admission == null) return error.EthereumWholeProgramAdmissionRequired;
            var artifact_value = try secure_artifact.OwnedArtifactV1
                .decodeCanonical(allocator, retained_artifact_bytes);
            errdefer artifact_value.deinit();
            const cohort = try allocator.create(Cohort);
            var cohort_initialized = false;
            errdefer {
                if (cohort_initialized) cohort.deinit();
                allocator.destroy(cohort);
            }
            cohort.* = try initCohortWithWorkers(PreparationEngine, allocator, materialized, target, worker_count);
            cohort_initialized = true;
            phases.mark("cold.cohort");
            const session = try cohort.session();
            var cold = try Kernel.verifyColdWithReplay(
                allocator,
                cohort,
                &session,
                &artifact_value,
            );
            errdefer cold.deinit();
            phases.mark("cold.verify");
            const query_authority = try CaptureTypes.VerifierQueryAuthorityV4
                .init(&cold.replay);
            var graph = try CaptureTypes.CaptureV4.initFromColdReplay(
                allocator,
                cohort,
                &session,
                &cold,
            );
            errdefer graph.deinit();
            phases.mark("cold.graph");
            const geometry = try cold_geometry.geometryFromCold(
                cohort,
                &session,
                &cold,
            );
            phases.mark("cold.geometry");
            const artifact_bytes = try allocator.dupe(
                u8,
                retained_artifact_bytes,
            );
            errdefer allocator.free(artifact_bytes);
            const backing = try allocator.create(OwnedColdProofV4.Storage);
            errdefer allocator.destroy(backing);
            backing.* = .{
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
                .prepared_graph = undefined,
                .artifact_ref = .{
                    .kind = PROOF_ARTIFACT_KIND,
                    .format_version = artifact_ref_mod.ARTIFACT_REF_FORMAT_VERSION,
                    .schema_version = PROOF_ARTIFACT_SCHEMA_VERSION,
                    .byte_count = @intCast(artifact_bytes.len),
                    .sha256 = sha256(artifact_bytes),
                },
            };
            try backing.artifact_ref.validate();
            backing.prepared_graph = try backing.composition_capture.validatedView(&backing.query_authority);
            const result: OwnedColdProofV4 = .{ .backing = @ptrCast(backing) };
            try result.validateBorrowed();
            phases.mark("cold.final-validation");
            // The active field kernel validates the actual recorded transcript
            // against its admitted program. No legacy projection is needed here.
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

test "Ethereum cold proof immutable metadata reads require no source hierarchy" {
    const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
    const Proof = Types(recursion.engine.ProverEngineForBackend(CpuBackend));
    const Owner = Proof.OwnedColdProofV4;
    const Audit = struct {
        fn readOnly(comptime T: type) bool {
            return switch (@typeInfo(T)) {
                .pointer => |pointer| pointer.is_const and readOnly(pointer.child),
                .array => |array| readOnly(array.child),
                .optional => |optional| readOnly(optional.child),
                .@"struct" => |value| blk: {
                    for (value.fields) |field| if (!readOnly(field.type)) break :blk false;
                    break :blk true;
                },
                .@"union" => |value| blk: {
                    for (value.fields) |field| if (!readOnly(field.type)) break :blk false;
                    break :blk true;
                },
                else => true,
            };
        }
    };
    try std.testing.expectEqual(@as(usize, 1), @typeInfo(Owner).@"struct".fields.len);
    try std.testing.expect(comptime Audit.readOnly(Proof.Graph));
    try std.testing.expect(comptime Audit.readOnly(*const secure_artifact.SessionV1));
    try std.testing.expect(comptime Audit.readOnly(*const registry_mod.AuthenticatedGeometryV1));
    // Keep the known legacy capture leak explicit; it must not silently be
    // classified as an immutable preparation getter.
    try std.testing.expect(comptime !Audit.readOnly(*const common_authority.ProofCapture));
    var value: Owner.Storage = undefined;
    value.artifact_ref = .{
        .kind = PROOF_ARTIFACT_KIND,
        .format_version = artifact_ref_mod.ARTIFACT_REF_FORMAT_VERSION,
        .schema_version = PROOF_ARTIFACT_SCHEMA_VERSION,
        .byte_count = 3,
        .sha256 = sha256("abc"),
    };
    const bytes = try std.testing.allocator.dupe(u8, "abc");
    defer std.testing.allocator.free(bytes);
    value.artifact_bytes = bytes;
    value.session = std.mem.zeroInit(secure_artifact.SessionV1, .{
        .source_kind = .ethereum_incremental_leaf_wrapper_v4,
        .protocol = @import("recursive_temporal_secure_parent_protocol_v1.zig").AuthorityV1.secureParent(),
    });
    // Geometry is used only to compare its address here, never as admission.
    var owner: Owner = .{ .backing = @ptrCast(&value) };
    const moved = owner;
    owner = undefined;
    for (0..32) |_| {
        try std.testing.expectEqualDeep(value.artifact_ref, try moved.proofArtifactRef());
        try std.testing.expectEqualStrings("abc", moved.artifactBytes());
        try std.testing.expect(moved.sessionView() == &value.session);
        try std.testing.expect(moved.geometryForPaddingTarget() == &value.geometry_value);
    }
    // Admission metadata is returned by const reference or value; editing a
    // caller's copy cannot mutate the owner's stored session.
    var copied_session = moved.sessionView().*;
    copied_session.identity_sha256[0] ^= 1;
    try std.testing.expect(!std.meta.eql(copied_session, moved.sessionView().*));
}

test "Ethereum cold proof rejects resealed external source identity" {
    const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
    const Proof = Types(recursion.engine.ProverEngineForBackend(CpuBackend));
    var materialized: Proof.MaterializedV4 = undefined;
    materialized.identity_sha256 = sha256("admitted source");
    var value: Proof.OwnedColdProofV4.Storage = undefined;
    value.materialized = &materialized;
    value.materialized_identity_sha256 = materialized.identity_sha256;
    try value.validateSourceIdentity();
    materialized.identity_sha256 = sha256("changed and resealed source");
    try std.testing.expectError(error.EthereumIncrementalUniversalColdProofMismatchV4, value.validateSourceIdentity());
    // Matching custody is only the first check, never a validated flag or a
    // substitute for native verification / explicit validateBorrowed.
    materialized.identity_sha256 = value.materialized_identity_sha256;
    try value.validateSourceIdentity();
}
