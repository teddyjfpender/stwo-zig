//! Genuine q193 proof and cold graph remint for the field-native common fold.
//!
//! The durable values are the existing secure proof artifact and the
//! canonical kind-10/schema-2 recursive node.  All claims, PCS capture,
//! dynamic geometry checks, and composition graph values are rebuilt by a
//! fresh verifier and remain process-local.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const capture_mod =
    @import("recursive_common_fold_composition_capture_v2.zig");
const child_mod = @import("recursive_common_fold_child_v2.zig");
const cohort_mod = @import("recursive_common_fold_secure_cohort_v2.zig");
const live_mod = @import("recursive_common_fold_universal_cohort_v2.zig");
const manifest_mod =
    @import("recursive_common_fold_universal_manifest_v2.zig");
const common_authority = @import("recursive_common_wrapper_authority_v2.zig");
const artifact_mod = @import("recursive_node_artifact_v2.zig");
const artifact_v1 = @import("recursive_node_artifact_v1.zig");
const registry_mod = @import("recursive_circuit_registry_v1.zig");
const secure_artifact =
    @import("recursive_temporal_secure_parent_artifact_v1.zig");
const secure_engine =
    @import("recursive_temporal_secure_parent_native_engine_v1.zig");
const process_validation =
    @import("recursive_process_local_validation_token_v1.zig");
const cold_token = @import("recursive_common_fold_cold_token_v2.zig");

const recursion = frontend.recursion;
const M31 = stwo_core.fields.m31.M31;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const FRI_QUERY_COUNT: u32 = 193;
pub const QUERY_WORD_COUNT: usize = FRI_QUERY_COUNT;
pub const QueryWordV2 = M31;
pub const TranscriptDigestV2 = capture_mod.TranscriptDigestV2;
pub const OUTPUT_KIND: u32 = artifact_mod.RECURSIVE_NODE_ARTIFACT_KIND;
pub const OUTPUT_SCHEMA_VERSION: u16 = artifact_mod.SCHEMA_VERSION;
pub const PROOF_ARTIFACT_KIND: u32 = common_authority.PROOF_ARTIFACT_KIND;
pub const PROOF_ARTIFACT_SCHEMA_VERSION: u16 = 1;
pub const COMMON_FOLD_ROLE = registry_mod.CircuitRoleV1.common_fold_field_v2;
pub const PRODUCTION_ACTIVATION = false;
pub const COLD_VERIFICATION_BEFORE_REMINT = true;
pub const SERIALIZABLE_FRESH_CAPABILITY = false;

pub const Error = live_mod.Error || registry_mod.Error || artifact_mod.Error ||
    error{
        CommonFoldColdCaptureMismatch,
        CommonFoldColdGraphMismatch,
        CommonFoldDurableOutputMismatch,
        CommonFoldFreshIngressMismatch,
    };

pub fn BackendV2(comptime dimensions: recursion.fixed_wire.Dimensions) type {
    const CaptureTypes = capture_mod.Types(dimensions);
    const SecureCohort = cohort_mod.CohortV2(dimensions);
    const Kernel = CaptureTypes.KernelV2;

    return struct {
        pub const fri_query_count = FRI_QUERY_COUNT;
        pub const output_kind = OUTPUT_KIND;
        pub const output_schema_version = OUTPUT_SCHEMA_VERSION;
        pub const common_fold_role = COMMON_FOLD_ROLE;
        pub const cold_verification_before_remint =
            COLD_VERIFICATION_BEFORE_REMINT;
        pub const serializable_fresh_capability =
            SERIALIZABLE_FRESH_CAPABILITY;
        pub const production_activation = PRODUCTION_ACTIVATION;
        pub const ExecutionOptions = secure_engine.ExecutionOptions;

        pub const FreshRecursiveIngressV2 = child_mod.FreshRecursiveIngressV2;
        pub const FreshFoldChildV2 = child_mod.FreshFoldChildV2;

        pub const OwnedColdProof = struct {
            allocator: std.mem.Allocator,
            live: *const live_mod.CohortV2,
            live_identity_sha256: [32]u8,
            session: secure_artifact.SessionV1,
            artifact_value: secure_artifact.OwnedArtifactV1,
            artifact_bytes: []u8,
            fresh: secure_engine.FreshVerificationV1,
            composition_capture: CaptureTypes.CaptureV2,
            query_authority: CaptureTypes.VerifierQueryAuthorityV2,
            claims: manifest_mod.ClaimVector,
            node_artifact: artifact_mod.RecursiveNodeArtifactV2,
            validation: *process_validation.ValidatedOwnerV1,

            pub fn deinit(self: *OwnedColdProof) void {
                self.allocator.destroy(self.validation);
                self.composition_capture.deinit();
                self.fresh.deinit();
                self.artifact_value.deinit();
                self.allocator.free(self.artifact_bytes);
                self.* = undefined;
            }

            pub fn validateAgainst(
                self: *const OwnedColdProof,
                live: *const live_mod.CohortV2,
            ) !void {
                var timer = startTimer();
                defer self.validation.counters.recordTimed(
                    .token_check,
                    readTimer(&timer),
                );
                try live.validate();
                if (self.live != live or !std.mem.eql(
                    u8,
                    &self.live_identity_sha256,
                    &live.identity_sha256,
                )) return error.CommonFoldColdCaptureMismatch;
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
                try validateFreshGeometry(live, &self.fresh);
                try validateDurableOutput(&self.node_artifact, live);
                if (!std.meta.eql(
                    self.fresh.statement,
                    self.artifact_value.statement,
                )) return error.CommonFoldColdCaptureMismatch;
            }

            /// Full diagnostic audit. Normal capability extraction uses the
            /// token path above and does not replay transcript or graph work.
            pub fn fullAuditAgainst(
                self: *const OwnedColdProof,
                live: *const live_mod.CohortV2,
            ) !void {
                var full_timer = startTimer();
                defer self.validation.counters.recordTimed(
                    .full_audit,
                    readTimer(&full_timer),
                );
                try live.validate();
                if (self.live != live or !std.mem.eql(
                    u8,
                    &self.live_identity_sha256,
                    &live.identity_sha256,
                )) return error.CommonFoldColdCaptureMismatch;
                var cohort = try SecureCohort.init(
                    self.allocator,
                    .{ .live = live },
                );
                defer cohort.deinit();
                const expected_session = try cohort.session();
                try self.artifact_value.validateCustody();
                try self.artifact_value.statement.validateAgainstSession(
                    &self.session,
                );
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
                try validateFreshGeometry(live, &self.fresh);
                const canonical = try self.artifact_value.encodeCanonicalAlloc(
                    self.allocator,
                );
                defer self.allocator.free(canonical);
                const expected_node = try buildNodeArtifact(
                    live,
                    &self.artifact_bytes,
                );
                if (!std.meta.eql(self.session, expected_session) or
                    !std.meta.eql(
                        self.fresh.statement,
                        self.artifact_value.statement,
                    ) or !std.meta.eql(self.claims, replay.claims) or
                    !std.mem.eql(u8, canonical, self.artifact_bytes) or
                    !std.meta.eql(self.node_artifact, expected_node))
                {
                    return error.CommonFoldColdCaptureMismatch;
                }
                try validateDurableOutput(&self.node_artifact, live);
                try self.validateAgainst(live);
            }

            pub fn performanceSnapshot(
                self: *const OwnedColdProof,
            ) process_validation.CounterSnapshotV1 {
                return self.validation.counters.snapshot();
            }

            pub fn nodeArtifact(
                self: *const OwnedColdProof,
            ) *const artifact_mod.RecursiveNodeArtifactV2 {
                return &self.node_artifact;
            }

            pub fn proofBytes(self: *const OwnedColdProof) []const u8 {
                return self.artifact_bytes;
            }

            pub fn requireFoldChild(
                self: *const OwnedColdProof,
            ) !FreshFoldChildV2 {
                try self.validateAgainst(self.live);
                var timer = startTimer();
                const graph = try self.composition_capture
                    .borrowProcessLocalView(
                    &self.query_authority,
                    &self.validation.token,
                );
                self.validation.counters.recordTimed(
                    .graph_view_borrow,
                    readTimer(&timer),
                );
                const geometry = self.live.geometry.commonFoldGeometry();
                const result = FreshFoldChildV2{
                    .wrapper = .{
                        .artifact = &self.node_artifact,
                        .geometry = geometry,
                        .capture = &self.fresh.capture,
                    },
                    .ingress = .{
                        .node_public = &self.node_artifact.node_public,
                        .claims = &self.claims,
                        .session = &self.session,
                        .statement = &self.fresh.statement,
                        .geometry_authority = self.live.geometry,
                        .geometry = geometry,
                        .capture = &self.fresh.capture,
                        .query_words = &self.query_authority.query_words,
                        .query_log_size = self.query_authority.query_log_size,
                        .final_transcript_digest = &self.query_authority.final_transcript_digest,
                        .final_transcript_draw_count = self.query_authority.final_transcript_draw_count,
                        .query_words_identity_sha256 = &self.query_authority.query_words_identity_sha256,
                    },
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
            live: *const live_mod.CohortV2,
            execution: ExecutionOptions,
        ) !OwnedColdProof {
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
            live: *const live_mod.CohortV2,
            proof_bytes: []const u8,
            node_bytes: []const u8,
        ) !OwnedColdProof {
            try live.validate();
            const decoded_node = try artifact_mod.RecursiveNodeArtifactV2
                .decodeCanonical(node_bytes);
            var cohort = try SecureCohort.init(allocator, .{ .live = live });
            defer cohort.deinit();
            const session = try cohort.session();
            var artifact_value = try secure_artifact.OwnedArtifactV1
                .decodeCanonical(allocator, proof_bytes);
            errdefer artifact_value.deinit();
            var cold_timer = startTimer();
            var fresh = try Kernel.verifyCold(
                allocator,
                .{ .live = live },
                &session,
                &artifact_value,
            );
            const cold_verify_ns = readTimer(&cold_timer);
            errdefer fresh.deinit();
            return ownResult(
                allocator,
                live,
                session,
                artifact_value,
                fresh,
                &decoded_node,
                cold_verify_ns,
            );
        }

        fn ownResult(
            allocator: std.mem.Allocator,
            live: *const live_mod.CohortV2,
            session: secure_artifact.SessionV1,
            artifact_value: secure_artifact.OwnedArtifactV1,
            fresh: secure_engine.FreshVerificationV1,
            retained_node: ?*const artifact_mod.RecursiveNodeArtifactV2,
            cold_verify_ns: u64,
        ) !OwnedColdProof {
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
            const query_authority =
                try CaptureTypes.VerifierQueryAuthorityV2.init(&replay);
            var graph_timer = startTimer();
            var graph = try CaptureTypes.CaptureV2.init(
                allocator,
                &cohort,
                &session,
                &fresh.statement,
                &fresh.capture,
                &replay,
            );
            const graph_record_ns = readTimer(&graph_timer);
            errdefer graph.deinit();
            const artifact_bytes = try artifact_value.encodeCanonicalAlloc(
                allocator,
            );
            errdefer allocator.free(artifact_bytes);
            const node = try buildNodeArtifact(live, artifact_bytes);
            if (retained_node) |expected|
                if (!std.meta.eql(expected.*, node))
                    return error.CommonFoldDurableOutputMismatch;
            const validation = try allocator.create(
                process_validation.ValidatedOwnerV1,
            );
            errdefer allocator.destroy(validation);
            validation.* = undefined;
            var result = OwnedColdProof{
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
                .node_artifact = node,
                .validation = validation,
            };
            try cold_token.validateConstructed(&result, &cohort, &replay);
            validation.* = try process_validation.ValidatedOwnerV1.init(
                try cold_token.snapshot(&result),
            );
            validation.counters.recordTimed(
                .q193_cold_verification,
                cold_verify_ns,
            );
            validation.counters.recordTimed(.transcript_replay, replay_ns);
            validation.counters.recordTimed(.graph_record, graph_record_ns);
            try result.validateAgainst(live);
            return result;
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

fn validateFreshGeometry(
    live: *const live_mod.CohortV2,
    fresh: *const secure_engine.FreshVerificationV1,
) !void {
    try live.geometry.validate();
    const geometry = live.geometry.commonFoldGeometry();
    const capture = &fresh.capture;
    if (geometry.role != COMMON_FOLD_ROLE or
        capture.commitments.len != common_authority.COMMITMENT_TREE_COUNT or
        !std.meta.eql(geometry.preprocessed_root, capture.commitments[0]))
    {
        return error.CommonFoldColdCaptureMismatch;
    }
    const shape = try registry_mod.sealProofShapeFromCapture(
        capture,
        geometry.component_count,
        geometry.proof_shape.column_log_degree,
        geometry.proof_shape.table_layout_identity_sha256,
    );
    if (!std.meta.eql(shape, geometry.proof_shape))
        return error.CommonFoldColdCaptureMismatch;
}

fn buildNodeArtifact(
    live: *const live_mod.CohortV2,
    proof_bytes: []const u8,
) !artifact_mod.RecursiveNodeArtifactV2 {
    try live.validate();
    if (proof_bytes.len == 0)
        return error.CommonFoldDurableOutputMismatch;
    const geometry = live.geometry.commonFoldGeometry();
    const entry = try live.geometry.registry.entry(COMMON_FOLD_ROLE);
    const expected_entry = try registry_mod.RegistryEntryV1.fromGeometry(
        geometry,
    );
    if (!std.meta.eql(entry.*, expected_entry))
        return error.CommonFoldDurableOutputMismatch;
    const proof_ref = try proofArtifactRef(proof_bytes);
    const stage_kind: artifact_mod.StageKindV1 =
        if (live.input.parent_coordinate.height == artifact_v1.ROOT_HEIGHT)
            .root
        else
            .fold;
    const result = try artifact_mod.RecursiveNodeArtifactV2.seal(.{
        .stage_kind = stage_kind,
        .node_kind = live.public_schedule.parent.node_kind,
        .child_count = 2,
        .coordinate = live.input.parent_coordinate,
        .node_public = live.public_schedule.parent,
        .campaign_namespace_sha256 = live.input.campaign_namespace_sha256,
        .circuit_identity_sha256 = entry.circuit_identity_sha256,
        .program_identity_sha256 = entry.program_identity_sha256,
        .profile_identity_sha256 = entry.profile_identity_sha256,
        .pcs_identity_sha256 = entry.pcs_identity_sha256,
        .padding_layout_identity_sha256 = entry.padding_layout_identity_sha256,
        .registry_identity_sha256 = live.geometry.registry.identity_sha256,
        .node_public_abi_sha256 = geometry.output_abi.node_public_abi_sha256,
        .proof_shape_identity_sha256 = geometry.proof_shape.identity_sha256,
        .ordered_children = live.input.child_refs,
        .proof_ref = proof_ref,
        .preprocessed_root = geometry.preprocessed_root,
        .semantic_inputs_identity_sha256 = undefined,
        .field_public_transport_sha256 = undefined,
        .content_identity_sha256 = undefined,
    });
    try live.geometry.registry.admitV2(&result, geometry);
    return result;
}

fn validateDurableOutput(
    value: *const artifact_mod.RecursiveNodeArtifactV2,
    live: *const live_mod.CohortV2,
) !void {
    try value.validate();
    const geometry = live.geometry.commonFoldGeometry();
    if (value.proof_ref.kind != PROOF_ARTIFACT_KIND or
        value.proof_ref.schema_version != PROOF_ARTIFACT_SCHEMA_VERSION or
        value.proof_ref.byte_count == 0 or
        !std.meta.eql(value.coordinate, live.input.parent_coordinate) or
        !std.meta.eql(value.node_public, live.public_schedule.parent) or
        !std.meta.eql(value.ordered_children, live.input.child_refs) or
        !std.meta.eql(value.preprocessed_root, geometry.preprocessed_root))
    {
        return error.CommonFoldDurableOutputMismatch;
    }
    try live.geometry.registry.admitV2(value, geometry);
}

fn proofArtifactRef(
    bytes: []const u8,
) !artifact_mod.ArtifactRefV1 {
    if (bytes.len == 0) return error.CommonFoldDurableOutputMismatch;
    var sha: [32]u8 = undefined;
    Sha256.hash(bytes, &sha, .{});
    const result = artifact_mod.ArtifactRefV1{
        .kind = PROOF_ARTIFACT_KIND,
        .format_version = artifact_v1.ARTIFACT_REF_FORMAT_VERSION,
        .schema_version = PROOF_ARTIFACT_SCHEMA_VERSION,
        .byte_count = @intCast(bytes.len),
        .sha256 = sha,
    };
    try result.validate();
    return result;
}

comptime {
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 1 or
        FRI_QUERY_COUNT != 193 or OUTPUT_KIND != 10 or
        OUTPUT_SCHEMA_VERSION != 2 or PROOF_ARTIFACT_KIND != 8 or
        PRODUCTION_ACTIVATION or !COLD_VERIFICATION_BEFORE_REMINT or
        SERIALIZABLE_FRESH_CAPABILITY)
    {
        @compileError("common-fold secure proof contract drifted");
    }
}
