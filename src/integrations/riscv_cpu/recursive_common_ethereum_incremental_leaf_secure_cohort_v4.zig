//! Secure-engine adapter for the complete schema-3 role-0 universal cohort.
//!
//! Every engine transaction reconstructs fresh geometry and all 36 physical
//! row owners from one live campaign-bound stage-102 materialization. The
//! adapter retains no serialized freshness bit and never substitutes the
//! canonical-empty or common-fold cohort for the role-0 program.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const campaign_materializer =
    @import("recursive_common_ethereum_incremental_leaf_campaign_materializer_v4.zig");
const complete_mod =
    @import("recursive_common_ethereum_incremental_leaf_universal_cohort_v4_complete.zig");
const geometry_mod =
    @import("recursive_common_ethereum_incremental_leaf_universal_geometry_authority_v4.zig");
const manifest_mod =
    @import("recursive_common_ethereum_incremental_leaf_universal_manifest_v4.zig");
const preprocessed_authority =
    @import("recursive_process_local_preprocessed_authority_v1.zig");
const padding_target_mod =
    @import("recursive_pipeline_campaign_padding_target_v2.zig");
const campaign_public = @import("recursive_campaign_node_public_v2.zig");
const secure_artifact =
    @import("recursive_temporal_secure_parent_artifact_v1.zig");
const field_transcript = @import("ethereum_wrapper_field_transcript_v1.zig");
const secure_engine = @import("recursive_temporal_secure_parent_native_engine_v1.zig");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const recursion = frontend.recursion;
const universal = recursion.air.universal_challenges;
const provider = recursion.air.universal_shared_provider;

pub const FORMAT_VERSION: u16 = 4;
pub const SCHEMA_VERSION: u16 = 4;
pub const COMPONENT_COUNT: usize = manifest_mod.COMPONENT_COUNT;
pub const ROLE = manifest_mod.ROLE;
pub const PRODUCTION_ACTIVATION = false;
pub const SERIALIZABLE_FRESH_CAPABILITY = false;

const AUTHORITY_TRANSCRIPT_DOMAIN: u32 = 0x4549_4134; // "EIA4"
const BOUNDARY_TRANSCRIPT_DOMAIN: u32 = 0x4549_4234; // "EIB4"
const COHORT_IDENTITY_DOMAIN =
    "stwo-zig/common-ethereum-incremental-secure-cohort/v4-schema4\x00";
const AUDIT_IDENTITY_DOMAIN =
    "stwo-zig/common-ethereum-incremental-secure-audit/v4-schema4\x00";

pub const Error = error{
    EthereumIncrementalSecureAuditMismatchV4,
    EthereumIncrementalSecureCohortMismatchV4,
};

const ClosureReceiptV4 = @FieldType(complete_mod.GeneratedV4, "closure");
const PublicWireBoundaryV4 = @FieldType(ClosureReceiptV4, "public_wire");

pub const BoundaryEvidenceV4 = struct {
    domain: @FieldType(PublicWireBoundaryV4, "domain"),
    tuple_count: u64,
    claimed_sum: QM31,

    pub fn validate(self: BoundaryEvidenceV4, allow_empty: bool) !void {
        if ((!allow_empty and self.tuple_count == 0) or
            (allow_empty and self.tuple_count != 0) or
            !secureCanonical(self.claimed_sum) or
            (allow_empty and !self.claimed_sum.isZero()))
        {
            return error.EthereumIncrementalSecureAuditMismatchV4;
        }
    }
};

pub const ClosureEvidenceV4 = struct {
    closure_id: [32]u8,

    pub fn validate(self: ClosureEvidenceV4) !void {
        if (std.mem.allEqual(u8, &self.closure_id, 0))
            return error.EthereumIncrementalSecureAuditMismatchV4;
    }
};

pub const SecureAuditedInteractionsV4 = struct {
    receipt: @FieldType(complete_mod.GeneratedV4, "closure"),
    wire_boundary: BoundaryEvidenceV4,
    verifier_input_boundary: BoundaryEvidenceV4,
    public_statement: @FieldType(ClosureReceiptV4, "public_statement"),
    closure: ClosureEvidenceV4,
    identity_sha256: [32]u8,

    pub fn init(generated: *const complete_mod.GeneratedV4) !SecureAuditedInteractionsV4 {
        return initSelected(generated);
    }

    pub fn initForInitial(generated: *const complete_mod.Initial38.Generated) !SecureAuditedInteractionsV4 {
        return initSelected(generated);
    }

    fn initSelected(generated: anytype) !SecureAuditedInteractionsV4 {
        try generated.validateStructure();
        var result = SecureAuditedInteractionsV4{
            .receipt = generated.closure,
            .public_statement = generated.closure.public_statement,
            .wire_boundary = .{
                .domain = generated.closure.public_wire.domain,
                .tuple_count = generated.closure.public_wire.term_count,
                .claimed_sum = generated.closure.public_wire.claimed_sum,
            },
            .verifier_input_boundary = .{
                .domain = generated.closure.public_wire.domain,
                .tuple_count = 0,
                .claimed_sum = QM31.zero(),
            },
            .closure = .{
                .closure_id = generated.closure.identity_sha256,
            },
            .identity_sha256 = undefined,
        };
        result.identity_sha256 = auditedIdentity(&result);
        try result.validate();
        return result;
    }

    pub fn validate(self: *const SecureAuditedInteractionsV4) !void {
        try self.receipt.validate();
        try self.wire_boundary.validate(false);
        try self.verifier_input_boundary.validate(true);
        try self.public_statement.validate();
        if (!std.meta.eql(self.public_statement, self.receipt.public_statement))
            return error.EthereumIncrementalSecureAuditMismatchV4;
        try self.closure.validate();
        if (self.wire_boundary.domain != self.receipt.public_wire.domain or
            self.wire_boundary.tuple_count !=
                self.receipt.public_wire.term_count or
            !self.wire_boundary.claimed_sum.eql(
                self.receipt.public_wire.claimed_sum,
            ) or !std.mem.eql(
            u8,
            &self.closure.closure_id,
            &self.receipt.identity_sha256,
        ) or !std.mem.eql(
            u8,
            &self.identity_sha256,
            &auditedIdentity(self),
        )) return error.EthereumIncrementalSecureAuditMismatchV4;
    }
};

pub fn CohortV4(comptime Engine: type) type {
    return CohortForManifest(Engine, manifest_mod);
}

pub fn InitialCohortV1(comptime Engine: type) type {
    return CohortForManifest(Engine, recursion.air.ethereum_initial_input_manifest_v1);
}

pub fn CohortForManifest(comptime Engine: type, comptime Contract: type) type {
    const initial = Contract == recursion.air.ethereum_initial_input_manifest_v1;
    if (!initial and Contract != manifest_mod)
        @compileError("Ethereum secure cohort requires an explicitly selected manifest");
    const CompleteTypes = complete_mod.Types(Contract);
    const RootVerifier = @import("ethereum_wrapper_root_verifier_v1.zig").Types(Contract);
    const Materialized = campaign_materializer.PreparedOwnedCampaignCaptureV4(Engine);
    const Geometry = geometry_mod.OwnerV4(Engine);
    const Complete = CompleteTypes.Cohort(Engine);
    const field_public = @import("recursive_field_node_public_v2.zig");

    return struct {
        const Self = @This();
        const OpaqueStorage = opaque {};

        pub const AuthorityInputs = struct { materialized: *const Materialized };
        pub const GeneratedInteractionsV1 = CompleteTypes.Generated;
        pub const AuditedInteractionsV2 = SecureAuditedInteractionsV4;
        pub const Components = CompleteTypes.ComponentSet;
        pub const FIELD_TRANSCRIPT_VERSION = field_transcript.VERSION;

        // Keep the value-returning engine API, but expose no mutable owner or
        // protocol fields. Copies of this handle borrow the same lifetime.
        backing: *OpaqueStorage,

        const Storage = struct {
            allocator: std.mem.Allocator,
            inputs: AuthorityInputs,
            geometry: *Geometry,
            complete: *Complete,
            padding_target: ?*const padding_target_mod.CampaignPaddingTargetV2,
            // Constructed from admitted sources once. Interaction generation
            // changes only the complete cohort, never this value-only snapshot.
            admission: Admission,
            // Derived once from this owner's admitted circuit, never from the
            // candidate proof. Absence keeps legacy admission explicit.
            field_circuit: ?FieldCircuitAdmission = null,
        };

        const FieldCircuitAdmission = struct {
            preprocessed_root: recursion.engine.Hasher.Hash,
            wire_term_count: u32,
            session_fields: field_transcript.SessionFieldsV1,
        };

        const Admission = struct {
            manifest: Contract.Manifest,
            log_sizes: Contract.LogSizesV4,
            complete_provider: geometry_mod.CompleteProviderGeometryV4,
            geometry_identity: [32]u8,
            complete_identity: [32]u8,
            identity_sha256: [32]u8,
            statement_words: recursion.span_statement.StatementWords,
            publication_words: [field_public.AIR_WORD_COUNT]u32,
            session_authority: secure_artifact.EthereumIncrementalLeafWrapperSessionAuthorityV4,
            program_identity: [32]u8,
            padding_identity: [32]u8,
            table_identity: [32]u8,

            fn validateAgainst(self: *const Admission, fresh: *const Admission) !void {
                if (!std.meta.eql(self.*, fresh.*))
                    return error.EthereumIncrementalSecureCohortMismatchV4;
            }
        };

        fn storage(self: *Self) *Storage {
            return @ptrCast(@alignCast(self.backing));
        }
        fn storageConst(self: *const Self) *const Storage {
            return @ptrCast(@alignCast(self.backing));
        }

        pub fn init(allocator: std.mem.Allocator, inputs: AuthorityInputs) !Self {
            return initWithPreparationEngine(frontend.recursion.engine.ProverEngineForBackend(@import("stwo_cpu_backend").CpuBackend), allocator, inputs, null);
        }
        pub fn initForPaddingTarget(
            allocator: std.mem.Allocator,
            inputs: AuthorityInputs,
            target: *const padding_target_mod.CampaignPaddingTargetV2,
        ) !Self {
            return initWithPreparationEngine(frontend.recursion.engine.ProverEngineForBackend(@import("stwo_cpu_backend").CpuBackend), allocator, inputs, target);
        }
        /// Preparation backend is an explicit execution choice. It does not
        /// enter the circuit key or change the admitted field transcript.
        pub fn initWithPreparationEngine(
            comptime PreparationEngine: type,
            allocator: std.mem.Allocator,
            inputs: AuthorityInputs,
            target: ?*const padding_target_mod.CampaignPaddingTargetV2,
        ) !Self {
            try secure_engine.requirePreparationEngine(PreparationEngine);
            try inputs.materialized.validate();
            if (initial != (inputs.materialized.initial_input_admission != null)) return error.InvalidEthereumInitialInputAdmission;
            if (initial and target != null) return error.UnsupportedEthereumInitialPaddingTarget;
            if (target) |value| try validateTargetCustody(value, inputs.materialized);
            const geometry = if (target) |value|
                try Geometry.initForLogSizes(allocator, inputs.materialized, try targetLogSizes(value))
            else
                try Geometry.init(allocator, inputs.materialized);
            errdefer geometry.deinit();
            const complete = try Complete.init(allocator, geometry);
            errdefer complete.deinit();
            const admitted = try deriveAdmission(inputs, target, try geometry.geometryView(), try complete.identity(), try complete.manifest());
            const value = try allocator.create(Storage);
            errdefer allocator.destroy(value);
            value.* = .{
                .allocator = allocator,
                .inputs = inputs,
                .geometry = geometry,
                .complete = complete,
                .padding_target = target,
                .admission = admitted,
            };
            var result = Self{ .backing = @ptrCast(value) };
            if (inputs.materialized.base.input.stage101.profile.usesFieldTranscript()) {
                try inputs.materialized.base.input.requireGlobalAdmission();
                const native = try (try geometry.geometryView()).suffix.nativeCore();
                const wire_term_count = try native.publicWireBoundaryTermCount();
                const selected_session = try result.session();
                const root = try secure_engine.derivePreprocessedRootWithEngine(PreparationEngine, Self, Contract, allocator, &result, &selected_session, PreparationEngine.Backend == @import("stwo_cpu_backend").CpuBackend);
                const terms = try native.copyPublicWireTerms(allocator);
                defer allocator.free(terms);
                if (terms.len != wire_term_count) return error.EthereumIncrementalSecureCohortMismatchV4;
                var key = RootVerifier.KeyV1{
                    .manifest = result.manifest().*,
                    .session_fields = try field_transcript.SessionFieldsV1.fromSession(&selected_session),
                    .preprocessed_root = root,
                    .parameters = try verifierParameters(native),
                    .wire_terms = terms,
                };
                const fields = try @import("ethereum_wrapper_fixed_circuit_v1.zig").sessionFields(&key);
                key.session_fields = fields;
                try key.validate();
                value.field_circuit = .{ .preprocessed_root = root, .wire_term_count = wire_term_count, .session_fields = fields };
                const field_session = try result.session();
                const field_admission = field_transcript.AdmissionV1{
                    .session = &field_session,
                    .preprocessed_root = root,
                    .wire_term_count = wire_term_count,
                };
                try field_admission.validate();
            }
            return result;
        }
        pub fn deinit(self: *Self) void {
            const value = storage(self);
            const allocator = value.allocator;
            value.complete.deinit();
            value.geometry.deinit();
            value.* = undefined;
            allocator.destroy(value);
            self.* = undefined;
        }

        /// Explicit input/proof boundary. Fresh derivation is independent of
        /// the retained metadata; changing and resealing a borrowed input does
        /// not silently update the admitted circuit, publication or session.
        pub fn validate(self: *Self) !void {
            try storage(self).complete.validate();
            try self.validateAdmissionSnapshot();
        }

        // Called only after a complete-cohort admission in the same operation.
        // This compares private value metadata with the admitted source; it is
        // neither a cached validity flag nor a caller-supplied trust receipt.
        fn validateAdmissionSnapshot(self: *Self) !void {
            const value = storage(self);
            if (value.padding_target) |target|
                try validateTargetCustody(target, value.inputs.materialized);
            const geometry = try value.geometry.geometryView();
            const complete_identity = try value.complete.identity();
            const fresh = try deriveAdmission(value.inputs, value.padding_target, geometry, complete_identity, try value.complete.manifest());
            try value.admission.validateAgainst(&fresh);
        }

        fn deriveAdmission(
            inputs: AuthorityInputs,
            target: ?*const padding_target_mod.CampaignPaddingTargetV2,
            geometry: Geometry.GeometryViewV4,
            complete_identity: [32]u8,
            selected_manifest: *const Contract.Manifest,
        ) !Admission {
            const materialized = inputs.materialized;
            const campaign = materialized.campaign_authority;
            const logs = geometry.log_sizes;
            const provider_geometry = geometry.complete_provider;
            const native = try geometry.suffix.nativeCore();
            try selected_manifest.validate();
            var selected_logs: Contract.LogSizesV4 = undefined;
            for (selected_manifest.placements, &selected_logs) |placement, *log|
                log.* = (placement orelse return error.EthereumIncrementalSecureCohortMismatchV4).geometry.log_size;
            const identities = if (initial) try initialIdentities(
                selected_manifest,
                native.publicSumsProgramIdentity(),
            ) else try manifest_mod.identitiesWithPublicSumsProgram(
                logs,
                campaign,
                provider_geometry,
                native.publicSumsProgramIdentity(),
            );
            if (target) |value| {
                if (!std.meta.eql(logs, try targetLogSizes(value)))
                    return error.EthereumIncrementalSecureCohortMismatchV4;
            }
            var words: recursion.span_statement.StatementWords = undefined;
            for (&words, materialized.base.input.publicationStatementWords()) |*destination, word|
                destination.* = M31.fromCanonical(word);
            return .{
                .manifest = selected_manifest.*,
                .log_sizes = selected_logs,
                .complete_provider = provider_geometry,
                .geometry_identity = geometry.identity_sha256,
                .complete_identity = complete_identity,
                .identity_sha256 = cohortIdentity(.{
                    .inputs = inputs,
                    .manifest_value = selected_manifest,
                    .padding_target = target,
                    .statement_words = words,
                }, geometry.identity_sha256, complete_identity),
                .statement_words = words,
                .publication_words = try materialized.schedule.node_public.canonicalAirWords(),
                .session_authority = .{
                    .ingress_identity_sha256 = materialized.identity_sha256,
                    .parent_statement_words = words,
                    .profile_identity_sha256 = bindPaddingTarget(target, "stwo-zig/role0-padded-profile/v4\x00", identities.profile),
                    .child_composition_manifest_sha256 = materialized.base.composition.program().graph_sha256,
                    .parent_outer_manifest_sha256 = bindPaddingTarget(target, "stwo-zig/role0-padded-contract/v4\x00", identities.contract),
                    .verification_key_id = bindPaddingTargetDigest(target, 0x4550_564b, identities.verification_key),
                    .next_parent_vk_id = bindPaddingTargetDigest(target, 0x4550_4e4b, identities.next_parent_key),
                    .air_program_id = bindPaddingTargetDigest(target, 0x4550_4150, identities.air_program),
                },
                .program_identity = bindPaddingTarget(target, "stwo-zig/role0-padded-program/v4\x00", identities.program),
                .padding_identity = if (target) |value| value.target.padding_table_layout_identity_sha256 else identities.padding,
                .table_identity = if (target) |value| value.target.padding_table_layout_identity_sha256 else identities.table,
            };
        }

        pub fn manifest(self: *const Self) *const Contract.Manifest {
            return &storageConst(self).admission.manifest;
        }
        pub fn logSizes(self: *const Self) Contract.LogSizesV4 {
            return storageConst(self).admission.log_sizes;
        }
        /// Custody coordinates only, not a mutable preparation view.
        pub fn materializedOwner(self: *const Self) *const Materialized {
            return storageConst(self).inputs.materialized;
        }
        pub fn paddingTarget(self: *const Self) ?*const padding_target_mod.CampaignPaddingTargetV2 {
            return storageConst(self).padding_target;
        }
        pub fn tupleClosure(self: *const Self) !recursion.air.relation_interaction.TupleClosureReport {
            return storageConst(self).complete.tupleClosure();
        }
        pub fn recursiveStatementWords(self: *const Self) !*const recursion.span_statement.StatementWords {
            return &storageConst(self).admission.statement_words;
        }
        pub fn parentManifestIdentity(self: *const Self) ![32]u8 {
            return storageConst(self).admission.session_authority.parent_outer_manifest_sha256;
        }
        pub fn programIdentity(self: *const Self) ![32]u8 {
            return storageConst(self).admission.program_identity;
        }
        pub fn profileIdentity(self: *const Self) ![32]u8 {
            return storageConst(self).admission.session_authority.profile_identity_sha256;
        }
        pub fn paddingLayoutIdentity(self: *const Self) ![32]u8 {
            return storageConst(self).admission.padding_identity;
        }
        pub fn tableLayoutIdentity(self: *const Self) ![32]u8 {
            return storageConst(self).admission.table_identity;
        }
        pub fn verificationKeyId(self: *const Self) !recursion.poseidon2_channel.Digest {
            return (try self.sessionAuthority()).verification_key_id;
        }
        pub fn nextParentVkId(self: *const Self) !recursion.poseidon2_channel.Digest {
            return (try self.sessionAuthority()).next_parent_vk_id;
        }
        pub fn airProgramId(self: *const Self) !recursion.poseidon2_channel.Digest {
            return (try self.sessionAuthority()).air_program_id;
        }
        pub fn sessionAuthority(self: *const Self) !secure_artifact.EthereumIncrementalLeafWrapperSessionAuthorityV4 {
            const value = storageConst(self);
            var authority = value.admission.session_authority;
            if (value.field_circuit) |fixed| {
                authority.verification_key_id = fixed.session_fields.verification_key_id;
                authority.next_parent_vk_id = fixed.session_fields.next_parent_vk_id;
                authority.air_program_id = fixed.session_fields.air_program_id;
            }
            return authority;
        }

        pub fn processLocalPreprocessedCacheKey(
            self: *Self,
            pcs_identity_sha256: [32]u8,
            root: recursion.engine.Hasher.Hash,
        ) !preprocessed_authority.KeyV1 {
            return preprocessed_authority.KeyV1.init(.{
                .circuit_identity_sha256 = try self.parentManifestIdentity(),
                .program_identity_sha256 = try self.programIdentity(),
                .profile_identity_sha256 = try self.profileIdentity(),
                .pcs_identity_sha256 = pcs_identity_sha256,
                .padding_identity_sha256 = try self.paddingLayoutIdentity(),
                .preprocessed_identity_sha256 = try preprocessed_authority
                    .preprocessedIdentity(
                    recursion.engine.Hasher.Hash,
                    try self.tableLayoutIdentity(),
                    self.manifest().seal,
                    root,
                ),
                .identity_sha256 = undefined,
            });
        }

        pub fn session(self: *Self) !secure_artifact.SessionV1 {
            return secure_artifact.SessionV1
                .initEthereumIncrementalLeafWrapperV4(
                try self.sessionAuthority(),
            );
        }

        /// Shared field transcript inputs from the private, immutable circuit
        /// admission. The session is independently checked against this owner;
        /// neither a proof root nor a caller-supplied term count is accepted.
        pub fn fieldTranscriptAdmission(self: *const Self, candidate: *const secure_artifact.SessionV1) !field_transcript.AdmissionV1 {
            const expected = try secure_artifact.SessionV1.initEthereumIncrementalLeafWrapperV4(try self.sessionAuthority());
            if (!std.meta.eql(candidate.*, expected)) return error.EthereumIncrementalSecureCohortMismatchV4;
            const circuit = storageConst(self).field_circuit orelse return error.EthereumFieldCircuitAdmissionRequired;
            const admission = field_transcript.AdmissionV1{
                .session = candidate,
                .preprocessed_root = circuit.preprocessed_root,
                .wire_term_count = circuit.wire_term_count,
            };
            try admission.validate();
            return admission;
        }

        /// Serialize only admitted fixed circuit structure. Dynamic statement
        /// and native custody fields remain outside the reusable verifier key.
        pub fn encodeVerifierKey(self: *Self, allocator: std.mem.Allocator) ![]u8 {
            try self.validate();
            const selected_session = try self.session();
            const field_admission = try self.fieldTranscriptAdmission(&selected_session);
            const native = try (try storageConst(self).geometry.geometryView()).suffix.nativeCore();
            const terms = try native.copyPublicWireTerms(allocator);
            defer allocator.free(terms);
            if (terms.len != field_admission.wire_term_count) return error.EthereumIncrementalSecureCohortMismatchV4;
            const key = RootVerifier.KeyV1{
                .manifest = self.manifest().*,
                .session_fields = try field_transcript.SessionFieldsV1.fromSession(&selected_session),
                .preprocessed_root = field_admission.preprocessed_root,
                .parameters = try verifierParameters(native),
                .wire_terms = terms,
            };
            try key.validate();
            return std.json.Stringify.valueAlloc(allocator, key, .{});
        }

        pub fn validateSession(
            self: *Self,
            candidate: *const secure_artifact.SessionV1,
        ) !void {
            if (!std.meta.eql(candidate.*, try self.session()))
                return error.EthereumIncrementalSecureCohortMismatchV4;
        }

        /// Record the admitted arithmetic anchors with symbolic challenges.
        pub fn recordPublicWireBoundary(
            self: *const Self,
            challenges: *const recursion.air.composition_graph_recorder.ChallengeSet,
        ) !recursion.air.composition_graph_recorder.Scalar {
            const suffix = try storageConst(self).geometry.rows10Through34();
            const native = try suffix.nativeCore();
            return native.recordPublicWireBoundary(challenges);
        }

        /// Copy of the immutable admission mixed into the proof transcript.
        /// Input acceptance/revalidation owns authentication; this read does not
        /// traverse producer state or expose mutable admission storage.
        pub fn publicationWords(self: *const Self) [field_public.AIR_WORD_COUNT]u32 {
            return storageConst(self).admission.publication_words;
        }

        pub fn mixAuthority(self: *Self, transcript: anytype) !void {
            const words = &storageConst(self).admission.publication_words;
            transcript.mixU32s(&.{
                AUTHORITY_TRANSCRIPT_DOMAIN,
                FORMAT_VERSION,
                SCHEMA_VERSION,
                @as(u32, @intCast(words.len)),
            });
            transcript.mixU32s(words);
        }

        pub fn mixBoundaryReceipt(
            transcript: anytype,
            audited: *const AuditedInteractionsV2,
        ) !void {
            try audited.validate();
            transcript.mixU32s(&.{
                BOUNDARY_TRANSCRIPT_DOMAIN,
                FORMAT_VERSION,
                SCHEMA_VERSION,
                @as(u32, @intCast(audited.wire_boundary.tuple_count)),
                0,
                @intFromEnum(audited.wire_boundary.domain),
                @intFromEnum(audited.public_statement.domain),
                audited.public_statement.term_count,
            });
            transcript.mixFelts(&.{
                audited.wire_boundary.claimed_sum,
                audited.verifier_input_boundary.claimed_sum,
                audited.public_statement.claimed_sum,
            });
        }

        pub fn fillPreprocessedInto(
            self: *Self,
            manifest_value: *const Contract.Manifest,
            destination: [][]M31,
        ) !void {
            try self.requireManifest(manifest_value);
            return storage(self).complete.fillPreprocessedInto(destination);
        }

        pub fn fillMainInto(
            self: *Self,
            manifest_value: *const Contract.Manifest,
            destination: [][]M31,
        ) !void {
            try self.requireManifest(manifest_value);
            return storage(self).complete.fillMainInto(destination);
        }

        pub fn fillInteractionInto(
            self: *Self,
            manifest_value: *const Contract.Manifest,
            relations: *const universal.UniversalRelations,
            provider_relations: *const provider.SharedProviderRelations,
            destination: [][]M31,
        ) !GeneratedInteractionsV1 {
            try self.requireManifest(manifest_value);
            return storage(self).complete.fillInteractionInto(
                relations,
                provider_relations,
                destination,
            );
        }

        pub fn rebuildGeneratedInteractions(
            self: *Self,
            relations: *const universal.UniversalRelations,
            provider_relations: *const provider.SharedProviderRelations,
        ) !GeneratedInteractionsV1 {
            return storage(self).complete.rebuildGeneratedInteractions(
                relations,
                provider_relations,
            );
        }

        pub fn validateGenerated(
            self: *Self,
            generated: *const GeneratedInteractionsV1,
            relations: *const universal.UniversalRelations,
            provider_relations: *const provider.SharedProviderRelations,
        ) !void {
            try storage(self).complete.validateGenerated(
                generated,
                relations,
                provider_relations,
            );
            try self.validateAdmissionSnapshot();
        }

        pub fn claimVector(
            self: *Self,
            generated: *const GeneratedInteractionsV1,
        ) !Contract.ClaimVector {
            try generated.validateStructure();
            if (!std.mem.eql(
                u8,
                &generated.cohort_identity_sha256,
                &storageConst(self).admission.complete_identity,
            ) or !std.mem.eql(
                u8,
                &generated.manifest_seal,
                &self.manifest().seal,
            )) return error.EthereumIncrementalSecureCohortMismatchV4;
            try generated.claims.validate(self.manifest());
            return generated.claims;
        }

        pub fn auditGlobalClosureV2(
            self: *Self,
            generated: *const GeneratedInteractionsV1,
            claims: *const Contract.ClaimVector,
            relations: *const universal.UniversalRelations,
            provider_relations: *const provider.SharedProviderRelations,
        ) !AuditedInteractionsV2 {
            try self.validateGenerated(
                generated,
                relations,
                provider_relations,
            );
            if (!std.meta.eql(claims.*, try self.claimVector(generated)))
                return error.EthereumIncrementalSecureAuditMismatchV4;
            return if (initial) AuditedInteractionsV2.initForInitial(generated) else AuditedInteractionsV2.init(generated);
        }

        pub fn auditGlobalClosure(
            self: *Self,
            generated: *const GeneratedInteractionsV1,
            claims: *const Contract.ClaimVector,
            relations: *const universal.UniversalRelations,
            provider_relations: *const provider.SharedProviderRelations,
        ) !void {
            _ = try self.auditGlobalClosureV2(
                generated,
                claims,
                relations,
                provider_relations,
            );
        }

        pub fn validateAuditedInteractions(
            self: *Self,
            audited: *const AuditedInteractionsV2,
            claims: *const Contract.ClaimVector,
            relations: *const universal.UniversalRelations,
            provider_relations: *const provider.SharedProviderRelations,
        ) !void {
            try audited.validate();
            const generated = try self.rebuildGeneratedInteractions(
                relations,
                provider_relations,
            );
            const expected = try self.auditGlobalClosureV2(
                &generated,
                claims,
                relations,
                provider_relations,
            );
            if (!std.meta.eql(audited.*, expected))
                return error.EthereumIncrementalSecureAuditMismatchV4;
        }

        pub fn initComponents(
            self: *Self,
            generated: *const GeneratedInteractionsV1,
            relations: *const universal.UniversalRelations,
            provider_relations: *const provider.SharedProviderRelations,
        ) !Components {
            return storage(self).complete.initComponents(
                generated,
                relations,
                provider_relations,
            );
        }

        fn verifierParameters(native: anytype) !@FieldType(RootVerifier.KeyV1, "parameters") {
            const value = try native.verifierParameters();
            return .{ .query_reference = value.query_reference, .poseidon_active_rows = value.poseidon_active_rows };
        }

        fn requireManifest(self: *const Self, candidate: *const Contract.Manifest) !void {
            try candidate.validate();
            if (!std.meta.eql(candidate.*, self.manifest().*))
                return error.EthereumIncrementalSecureCohortMismatchV4;
        }
    };
}

/// Versioned fixed-circuit extension. Custody, job hashes and input values do
/// not enter this identity: the typed manifest and admitted arithmetic do.
fn initialIdentities(
    manifest: *const recursion.air.ethereum_initial_input_manifest_v1.Manifest,
    public_sums_program_identity: [32]u8,
) !manifest_mod.ProgramBoundIdentitiesV1 {
    try manifest.validate();
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/ethereum-initial-secure-circuit/v1\x00");
    hash.update(&manifest.seal);
    return manifest_mod.bindPublicSumsProgram(hash.finalResult(), manifest.seal, public_sums_program_identity);
}

fn bindPaddingTarget(
    padding_target: ?*const padding_target_mod.CampaignPaddingTargetV2,
    comptime domain: []const u8,
    base: [32]u8,
) [32]u8 {
    const target = padding_target orelse return base;
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(domain);
    hash.update(&base);
    hash.update(&target.identity_sha256);
    hash.update(&target.shape.identity_sha256);
    return hash.finalResult();
}

fn bindPaddingTargetDigest(
    padding_target: ?*const padding_target_mod.CampaignPaddingTargetV2,
    capacity_tag: u32,
    base: recursion.poseidon2_channel.Digest,
) recursion.poseidon2_channel.Digest {
    const target = padding_target orelse return base;
    var bytes: [@sizeOf(recursion.poseidon2_channel.Digest) + 64]u8 =
        undefined;
    var cursor: usize = 0;
    for (base) |word| {
        std.mem.writeInt(
            u32,
            bytes[cursor..][0..@sizeOf(u32)],
            word,
            .little,
        );
        cursor += @sizeOf(u32);
    }
    @memcpy(bytes[cursor..][0..32], &target.identity_sha256);
    cursor += 32;
    @memcpy(bytes[cursor..][0..32], &target.shape.identity_sha256);
    cursor += 32;
    std.debug.assert(cursor == bytes.len);
    return recursion.poseidon2_channel.hashBytes(
        &bytes,
        capacity_tag,
    );
}

fn cohortIdentity(value: anytype, geometry_identity: [32]u8, complete_identity: [32]u8) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(COHORT_IDENTITY_DOMAIN);
    hashInt(&hash, u16, FORMAT_VERSION);
    hashInt(&hash, u16, SCHEMA_VERSION);
    hash.update(&value.inputs.materialized.identity_sha256);
    hash.update(&value.inputs.materialized.campaign_authority.view()
        .authority_identity_sha256);
    hash.update(&geometry_identity);
    hash.update(&complete_identity);
    hash.update(&value.manifest_value.seal);
    if (value.padding_target) |target| {
        hash.update(&target.identity_sha256);
        hash.update(&target.shape.identity_sha256);
    }
    for (value.statement_words) |word|
        hashInt(&hash, u32, word.toU32());
    return hash.finalResult();
}

fn targetLogSizes(
    target: *const padding_target_mod.CampaignPaddingTargetV2,
) !manifest_mod.LogSizesV4 {
    try target.validateSelf();
    const padded = try target.paddedLogs();
    var result: manifest_mod.LogSizesV4 = undefined;
    for (&result, padded[0..manifest_mod.COMPONENT_COUNT]) |
        *destination,
        source,
    | destination.* = source;
    return result;
}

fn validateTargetCustody(
    target: *const padding_target_mod.CampaignPaddingTargetV2,
    materialized: anytype,
) !void {
    try target.validateSelf();
    try campaign_public.validate(
        &target.shape,
        &materialized.schedule.node_public,
    );
    if (materialized.campaign_authority.view().leaf_count !=
        target.shape.real_leaf_count or
        !std.mem.eql(
            u8,
            &materialized.campaign_authority.view().campaign_inventory
                .table_identity_sha256,
            &target.shape.inventory_identity_sha256,
        )) return error.EthereumIncrementalSecureCohortMismatchV4;
}

fn auditedIdentity(value: *const SecureAuditedInteractionsV4) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(AUDIT_IDENTITY_DOMAIN);
    hash.update(&value.receipt.identity_sha256);
    hashInt(&hash, u64, value.wire_boundary.tuple_count);
    hashQm31(&hash, value.wire_boundary.claimed_sum);
    hashInt(&hash, u64, value.verifier_input_boundary.tuple_count);
    hashQm31(&hash, value.verifier_input_boundary.claimed_sum);
    hash.update(&value.public_statement.identity_sha256);
    hash.update(&value.closure.closure_id);
    return hash.finalResult();
}

fn secureCanonical(value: QM31) bool {
    for (value.toM31Array()) |word| if (word.toU32() >=
        stwo_core.fields.m31.Modulus)
    {
        return false;
    };
    return true;
}

fn hashQm31(hash: anytype, value: QM31) void {
    for (value.toM31Array()) |word|
        hashInt(hash, u32, word.toU32());
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

comptime {
    if (FORMAT_VERSION != 4 or SCHEMA_VERSION != 4 or
        COMPONENT_COUNT != 36 or @intFromEnum(ROLE) != 0 or
        PRODUCTION_ACTIVATION or SERIALIZABLE_FRESH_CAPABILITY)
    {
        @compileError("Ethereum incremental secure cohort V4 drifted");
    }
}

test "Ethereum secure cohort metadata reads only its immutable admission" {
    const Engine = recursion.engine.ProverEngineForBackend(@import("stwo_cpu_backend").CpuBackend);
    const Cohort = CohortV4(Engine);
    // This isolated ownership test deliberately supplies no source hierarchy.
    // Metadata reads must use only the privately retained, pointer-free value.
    var value: Cohort.Storage = .{
        .allocator = std.testing.allocator,
        .inputs = undefined,
        .geometry = undefined,
        .complete = undefined,
        .padding_target = null,
        .admission = std.mem.zeroes(Cohort.Admission),
    };
    value.admission.program_identity = [_]u8{7} ** 32;
    value.admission.padding_identity = [_]u8{8} ** 32;
    value.admission.table_identity = [_]u8{9} ** 32;
    value.admission.statement_words[0] = M31.fromCanonical(17);
    value.admission.session_authority.parent_outer_manifest_sha256 = [_]u8{10} ** 32;
    value.admission.session_authority.profile_identity_sha256 = [_]u8{11} ** 32;
    value.admission.session_authority.verification_key_id = [_]u32{12} ** 8;
    value.admission.session_authority.next_parent_vk_id = [_]u32{13} ** 8;
    value.admission.session_authority.air_program_id = [_]u32{14} ** 8;
    value.admission.publication_words[0] = 19;
    var cohort = Cohort{ .backing = @ptrCast(&value) };
    const Channel = struct {
        count: usize = 0,
        words: [454]u32 = undefined,
        pub fn mixU32s(self: *@This(), words: []const u32) void {
            @memcpy(self.words[self.count..][0..words.len], words);
            self.count += words.len;
        }
    };
    for (0..32) |_| {
        try std.testing.expectEqual(value.admission.program_identity, try cohort.programIdentity());
        try std.testing.expectEqual(value.admission.padding_identity, try cohort.paddingLayoutIdentity());
        try std.testing.expectEqual(value.admission.table_identity, try cohort.tableLayoutIdentity());
        try std.testing.expectEqual(value.admission.session_authority.parent_outer_manifest_sha256, try cohort.parentManifestIdentity());
        try std.testing.expectEqual(value.admission.session_authority.profile_identity_sha256, try cohort.profileIdentity());
        try std.testing.expectEqual(value.admission.session_authority.verification_key_id, try cohort.verificationKeyId());
        try std.testing.expectEqual(value.admission.session_authority.next_parent_vk_id, try cohort.nextParentVkId());
        try std.testing.expectEqual(value.admission.session_authority.air_program_id, try cohort.airProgramId());
        try std.testing.expectEqualDeep(value.admission.manifest, cohort.manifest().*);
        try std.testing.expectEqual(value.admission.log_sizes, cohort.logSizes());
        const statement = try cohort.recursiveStatementWords();
        try std.testing.expect(@typeInfo(@TypeOf(statement)).pointer.is_const);
        try std.testing.expectEqual(@as(u32, 17), statement[0].toU32());
        var copied = try cohort.sessionAuthority();
        copied.profile_identity_sha256[0] ^= 1;
        try std.testing.expectEqual(value.admission.session_authority, try cohort.sessionAuthority());
        var publication_copy = cohort.publicationWords();
        publication_copy[0] ^= 1;
        try std.testing.expectEqual(value.admission.publication_words, cohort.publicationWords());
        var channel = Channel{};
        try cohort.mixAuthority(&channel);
        try std.testing.expectEqual(@as(usize, 454), channel.count);
        try std.testing.expectEqualSlices(u32, &.{ AUTHORITY_TRANSCRIPT_DOMAIN, FORMAT_VERSION, SCHEMA_VERSION, 450 }, channel.words[0..4]);
        try std.testing.expectEqualSlices(u32, &value.admission.publication_words, channel.words[4..]);
    }
    try std.testing.expectEqual(@as(usize, 1), @typeInfo(Cohort).@"struct".fields.len);
    try std.testing.expect(@typeInfo(@FieldType(Cohort, "backing")).pointer.child == Cohort.OpaqueStorage);
    // Exercise only the private metadata projection, without minting a key or
    // claiming that this isolated fixture owns preprocessing.
    const fields = field_transcript.SessionFieldsV1{
        .protocol = @import("recursive_temporal_secure_parent_protocol_v1.zig").AuthorityV1.secureParent(),
        .verification_key_id = [_]u32{21} ** 8,
        .next_parent_vk_id = [_]u32{22} ** 8,
        .air_program_id = [_]u32{23} ** 8,
    };
    value.field_circuit = .{ .preprocessed_root = [_]u32{24} ** 8, .wire_term_count = 1, .session_fields = fields };
    value.admission.session_authority.verification_key_id[0] += 1;
    value.admission.session_authority.next_parent_vk_id[0] += 1;
    value.admission.session_authority.air_program_id[0] += 1;
    try std.testing.expectEqual(fields.verification_key_id, try cohort.verificationKeyId());
    try std.testing.expectEqual(fields.next_parent_vk_id, try cohort.nextParentVkId());
    try std.testing.expectEqual(fields.air_program_id, try cohort.airProgramId());
    try std.testing.expectEqual(value.admission.session_authority.profile_identity_sha256, try cohort.profileIdentity());
}

test "Ethereum secure cohort admission rejects changed metadata even with replacement seals" {
    const Engine = recursion.engine.ProverEngineForBackend(@import("stwo_cpu_backend").CpuBackend);
    const Cohort = CohortV4(Engine);
    const original = std.mem.zeroes(Cohort.Admission);
    var changed = original;
    try original.validateAgainst(&changed);
    changed.publication_words[49] = 1;
    changed.identity_sha256 = [_]u8{7} ** 32;
    changed.geometry_identity = [_]u8{8} ** 32;
    changed.complete_identity = [_]u8{9} ** 32;
    try std.testing.expectError(error.EthereumIncrementalSecureCohortMismatchV4, original.validateAgainst(&changed));
    changed = original;
    changed.session_authority.profile_identity_sha256[0] ^= 1;
    try std.testing.expectError(error.EthereumIncrementalSecureCohortMismatchV4, original.validateAgainst(&changed));
    changed = original;
    changed.statement_words[0] = M31.fromCanonical(1);
    try std.testing.expectError(error.EthereumIncrementalSecureCohortMismatchV4, original.validateAgainst(&changed));
    changed = original;
    changed.log_sizes[0] += 1;
    try std.testing.expectError(error.EthereumIncrementalSecureCohortMismatchV4, original.validateAgainst(&changed));
}

test "Ethereum public sums program mutation changes same geometry session and cache admission" {
    const Engine = recursion.engine.ProverEngineForBackend(@import("stwo_cpu_backend").CpuBackend);
    const Cohort = CohortV4(Engine);
    const allocator = std.testing.allocator;
    var logs = [_]u32{4} ** manifest_mod.COMPONENT_COUNT;
    logs[34] = manifest_mod.MINIMUM_PROVIDER_LOG_SIZE;
    logs[35] = manifest_mod.RANGE_LOG_SIZE;
    const manifest = try manifest_mod.buildForDerivedLogSizes(logs);

    // An identity-binding mutation fixture, not a synthetic proof or source
    // admission. Geometry and the prospective root are identical in both arms.
    const geometry_contract = [_]u8{41} ** 32;
    const first_program = [_]u8{71} ** 32;
    var second_program = first_program;
    second_program[0] ^= 1;
    const first = try manifest_mod.bindPublicSumsProgram(geometry_contract, manifest.seal, first_program);
    const second = try manifest_mod.bindPublicSumsProgram(geometry_contract, manifest.seal, second_program);
    inline for (.{ "contract", "program", "profile", "padding", "table", "verification_key", "next_parent_key", "air_program" }) |name|
        try std.testing.expect(!std.meta.eql(@field(first, name), @field(second, name)));
    try std.testing.expectError(error.EthereumIncrementalUniversalManifestMismatchV4, manifest_mod.bindPublicSumsProgram(geometry_contract, manifest.seal, [_]u8{0} ** 32));

    const span = recursion.span_statement;
    const digest = [_]u32{1} ** 8;
    const entry = try span.MachineState.init(0, [_]u32{0} ** 32, digest, digest);
    const exit = try span.MachineState.init(4, [_]u32{0} ** 32, digest, digest);
    const complete = try span.CompleteExecution.init(recursion.protocol.PROTOCOL_ID_WORDS, digest, entry, exit, digest, digest, 8);
    const job = try span.JobContext.init(complete, 1);
    const executed = try span.ExecutedSpan.init(0, 1, 0, 8, entry, exit, try span.EdgeClaim.present(digest), try span.EdgeClaim.present(digest));
    const leaf = try span.SpanStatement.segmentLeaf(job, 0, executed);

    // Only metadata-reading methods are exercised. The storage deliberately
    // owns no fabricated materializer or geometry hierarchy.
    const value = try allocator.create(Cohort.Storage);
    defer allocator.destroy(value);
    value.* = undefined;
    value.admission = std.mem.zeroes(Cohort.Admission);
    value.field_circuit = null;
    value.admission.manifest = manifest;
    value.admission.session_authority = .{
        .ingress_identity_sha256 = [_]u8{1} ** 32,
        .parent_statement_words = try leaf.canonicalWords(),
        .profile_identity_sha256 = first.profile,
        .child_composition_manifest_sha256 = [_]u8{3} ** 32,
        .parent_outer_manifest_sha256 = first.contract,
        .verification_key_id = first.verification_key,
        .next_parent_vk_id = first.next_parent_key,
        .air_program_id = first.air_program,
    };
    value.admission.program_identity = first.program;
    value.admission.padding_identity = first.padding;
    value.admission.table_identity = first.table;
    var cohort = Cohort{ .backing = @ptrCast(value) };
    const first_session = try cohort.session();
    try cohort.validateSession(&first_session);
    const root = [_]u32{7} ** 8;
    const first_key = try cohort.processLocalPreprocessedCacheKey([_]u8{8} ** 32, root);
    const first_authority = try preprocessed_authority.AuthorityV1(Engine.Hasher.Hash).init(first_key, root);
    const first_admission = value.admission;

    value.admission.session_authority.profile_identity_sha256 = second.profile;
    value.admission.session_authority.parent_outer_manifest_sha256 = second.contract;
    value.admission.session_authority.verification_key_id = second.verification_key;
    value.admission.session_authority.next_parent_vk_id = second.next_parent_key;
    value.admission.session_authority.air_program_id = second.air_program;
    value.admission.program_identity = second.program;
    value.admission.padding_identity = second.padding;
    value.admission.table_identity = second.table;
    const second_session = try cohort.session();
    try cohort.validateSession(&second_session);
    try std.testing.expectError(error.EthereumIncrementalSecureCohortMismatchV4, cohort.validateSession(&first_session));
    try std.testing.expectError(error.EthereumIncrementalSecureCohortMismatchV4, first_admission.validateAgainst(&value.admission));
    const second_key = try cohort.processLocalPreprocessedCacheKey([_]u8{8} ** 32, root);
    try std.testing.expect(!std.meta.eql(first_key, second_key));
    try std.testing.expectError(error.InvalidProcessLocalPreprocessedAuthority, first_authority.validateAgainst(&second_key, root));
}

test "Ethereum initial secure circuit identities bind exact shape and arithmetic" {
    const initial_manifest = recursion.air.ethereum_initial_input_manifest_v1;
    var logs = [_]u32{4} ** manifest_mod.COMPONENT_COUNT;
    logs[34] = manifest_mod.MINIMUM_PROVIDER_LOG_SIZE;
    logs[35] = manifest_mod.RANGE_LOG_SIZE;
    const ordinary = try manifest_mod.buildForDerivedLogSizes(logs);
    const first_manifest = try initial_manifest.build(&ordinary, 40);
    const second_manifest = try initial_manifest.build(&ordinary, 41);
    // Identical padded geometry must not erase the exact admitted capacity.
    for (first_manifest.placements, second_manifest.placements) |first, second|
        try std.testing.expectEqual(first.?.geometry.log_size, second.?.geometry.log_size);
    const first_program = [_]u8{71} ** 32;
    var second_program = first_program;
    second_program[0] ^= 1;
    const first = try initialIdentities(&first_manifest, first_program);
    const changed_capacity = try initialIdentities(&second_manifest, first_program);
    const changed_arithmetic = try initialIdentities(&first_manifest, second_program);
    inline for (.{ "contract", "program", "profile", "padding", "table", "verification_key", "next_parent_key", "air_program" }) |name| {
        try std.testing.expect(!std.meta.eql(@field(first, name), @field(changed_capacity, name)));
        try std.testing.expect(!std.meta.eql(@field(first, name), @field(changed_arithmetic, name)));
    }
}

test "Ethereum initial secure circuit admission rejects drift and has no custody input" {
    const initial_manifest = recursion.air.ethereum_initial_input_manifest_v1;
    var logs = [_]u32{4} ** manifest_mod.COMPONENT_COUNT;
    logs[34] = manifest_mod.MINIMUM_PROVIDER_LOG_SIZE;
    logs[35] = manifest_mod.RANGE_LOG_SIZE;
    const ordinary = try manifest_mod.buildForDerivedLogSizes(logs);
    const manifest = try initial_manifest.build(&ordinary, 40);
    const program = [_]u8{71} ** 32;
    var changed = manifest;
    changed.input_capacity += 1;
    try std.testing.expectError(error.ManifestSealMismatch, initialIdentities(&changed, program));
    changed = manifest;
    changed.placements[initial_manifest.keyIndex(.ethereum_initial_input_lane)].?.geometry.log_size += 1;
    try std.testing.expectError(error.ManifestSealMismatch, initialIdentities(&changed, program));
    try std.testing.expectError(error.EthereumIncrementalUniversalManifestMismatchV4, initialIdentities(&manifest, [_]u8{0} ** 32));

    // Keep the fixed identity boundary limited to validated circuit structure
    // and admitted arithmetic; no capture owner or job values enter this API.
    const parameters = @typeInfo(@TypeOf(initialIdentities)).@"fn".params;
    try std.testing.expectEqual(@as(usize, 2), parameters.len);
    try std.testing.expect(parameters[0].type.? == *const initial_manifest.Manifest);
    try std.testing.expect(parameters[1].type.? == [32]u8);
}
