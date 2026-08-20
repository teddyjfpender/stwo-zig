//! Cohesive internal authority extracted from recursive_fri_outer.zig.

pub fn Namespace(comptime context: type) type {
    return struct {
        const std = context.d_std;
        const stwo_core = context.d_stwo_core;
        const QM31 = context.d_QM31;
        const recursion = context.d_recursion;
        const outer_admission = context.d_outer_admission;
        const global_closure = context.d_global_closure;
        const air = context.d_air;
        const vm_input_air = context.d_vm_input_air;
        const composition_control_air = context.d_composition_control_air;
        const query_bits_air = context.d_query_bits_air;
        const query_mapping_air = context.d_query_mapping_air;
        const merkle_root_air = context.d_merkle_root_air;
        const trace_merkle_air = context.d_trace_merkle_air;
        const pcs_air = context.d_pcs_air;
        const fri_leaf_air = context.d_fri_leaf_air;
        const fri_node_air = context.d_fri_node_air;
        const fri_anchor_air = context.d_fri_anchor_air;
        const control_air = context.d_control_air;
        const input_air = context.d_input_air;
        const multiply_air = context.d_multiply_air;
        const inverse_air = context.d_inverse_air;
        const linear_air = context.d_linear_air;
        const merkle_path_air = context.d_merkle_path_air;
        const manifest_v2 = context.d_manifest_v2;
        const shared_provider = context.d_shared_provider;
        const universal = context.d_universal;
        const universal_binding = context.d_universal_binding;
        const adapter = context.d_adapter;
        const framework = context.d_framework;
        const poseidon2_air = context.d_poseidon2_air;
        const LogIndex = context.d_LogIndex;
        const OuterProofCapture = context.d_OuterProofCapture;
        const POSEIDON2_ROSTER_ROW = context.d_POSEIDON2_ROSTER_ROW;
        const POSEIDON2_PARTIAL_COUNT = context.d_POSEIDON2_PARTIAL_COUNT;
        const POSEIDON2_COMPOSITION_CLAIM_INDICES = context.d_POSEIDON2_COMPOSITION_CLAIM_INDICES;
        const SEGMENT_GLOBAL_CLOSURE_FORMAT_VERSION = context.d_SEGMENT_GLOBAL_CLOSURE_FORMAT_VERSION;
        const V2_CORE_ROWS_18_34_PREFLIGHT_FORMAT_VERSION = context.d_V2_CORE_ROWS_18_34_PREFLIGHT_FORMAT_VERSION;
        const V2_CORE_FIRST_ROW = context.d_V2_CORE_FIRST_ROW;
        const V2_CORE_LAST_ROW = context.d_V2_CORE_LAST_ROW;
        const V2_CORE_ROW_COUNT = context.d_V2_CORE_ROW_COUNT;
        const VerifiedOuterProofV1 = context.d_VerifiedOuterProofV1;
        const SegmentProviderClaimV2 = context.d_SegmentProviderClaimV2;
        const VerifierPlans = context.d_VerifierPlans;
        const RelationDomain = context.d_RelationDomain;
        const relationDomainBit = context.d_relationDomainBit;
        const ScheduleFacts = context.d_ScheduleFacts;
        const Authority = context.d_Authority;
        const qm31FromWire = context.d_qm31FromWire;
        const validateAuxiliaryQm31 = context.d_validateAuxiliaryQm31;
        const validateAuxiliaryDigest = context.d_validateAuxiliaryDigest;
        const segmentClosureReceiptIdentity = context.d_segmentClosureReceiptIdentity;
        const v2CoreRows18Through34PreflightIdentity = context.d_v2CoreRows18Through34PreflightIdentity;
        const requireSha256Id = context.d_requireSha256Id;
        const requireCanonicalClosureVector = context.d_requireCanonicalClosureVector;
        const requireZeroDomainClosure = context.d_requireZeroDomainClosure;
        const allRelationDomainMask = context.d_allRelationDomainMask;

        pub const SegmentGlobalClosureReceiptV2 = struct {
            format_version: u16 = SEGMENT_GLOBAL_CLOSURE_FORMAT_VERSION,
            roster_count: u8 = global_closure.TOTAL_ROW_COUNT,
            domain_count: u8 = global_closure.DOMAIN_COUNT,
            checked_domain_mask: u64,
            active_domain_mask: u64,
            native_manifest_id: recursion.poseidon2_channel.Digest,
            native_verifier_receipt_id: recursion.poseidon2_channel.Digest,
            native_relation_replay_id: recursion.poseidon2_channel.Digest,
            row_claims_id: [32]u8,
            prefix_totals: [global_closure.DOMAIN_COUNT]QM31,
            provider_claim: SegmentProviderClaimV2,
            public_boundaries: global_closure.PublicBoundariesV2,
            closed_totals: [global_closure.DOMAIN_COUNT]QM31,
            framework_total: QM31,
            closure_id: [32]u8,

            pub fn validate(self: *const SegmentGlobalClosureReceiptV2) !void {
                if (self.format_version != SEGMENT_GLOBAL_CLOSURE_FORMAT_VERSION or
                    self.roster_count != global_closure.TOTAL_ROW_COUNT or
                    self.domain_count != global_closure.DOMAIN_COUNT or
                    self.checked_domain_mask != allRelationDomainMask())
                {
                    return error.SegmentClosureIdentityMismatch;
                }
                if (self.active_domain_mask & ~self.checked_domain_mask != 0)
                    return error.SegmentClosureIdentityMismatch;
                try validateAuxiliaryDigest(self.native_manifest_id);
                try validateAuxiliaryDigest(self.native_verifier_receipt_id);
                try validateAuxiliaryDigest(self.native_relation_replay_id);
                try requireSha256Id(self.row_claims_id);
                try self.provider_claim.validate();
                try self.public_boundaries.validate();
                try requireCanonicalClosureVector(&self.prefix_totals);
                try requireCanonicalClosureVector(&self.closed_totals);
                try validateAuxiliaryQm31(self.framework_total);

                const required_domains = relationDomainBit(.range_check_8_8) |
                    relationDomainBit(.recursion_wire) |
                    relationDomainBit(.recursion_verifier_input_word);
                if (self.active_domain_mask & required_domains != required_domains)
                    return error.SegmentClosureIdentityMismatch;

                var expected_closed = self.prefix_totals;
                expected_closed[@intFromEnum(RelationDomain.range_check_8_8)] =
                    expected_closed[@intFromEnum(RelationDomain.range_check_8_8)].add(
                        self.provider_claim.claimed_sum,
                    );
                expected_closed[@intFromEnum(RelationDomain.recursion_wire)] =
                    expected_closed[@intFromEnum(RelationDomain.recursion_wire)].add(
                        self.public_boundaries.wire.claimed_sum,
                    );
                expected_closed[
                    @intFromEnum(RelationDomain.recursion_verifier_input_word)
                ] = expected_closed[
                    @intFromEnum(RelationDomain.recursion_verifier_input_word)
                ].add(self.public_boundaries.verifier_input.claimed_sum);
                for (expected_closed, self.closed_totals) |expected, actual| {
                    if (!expected.eql(actual))
                        return error.SegmentClosureIdentityMismatch;
                }
                try requireZeroDomainClosure(&self.closed_totals);

                var expected_framework = QM31.zero();
                for (self.prefix_totals) |value|
                    expected_framework = expected_framework.add(value);
                expected_framework = expected_framework
                    .add(self.provider_claim.claimed_sum)
                    .add(self.public_boundaries.claimedSum());
                if (!expected_framework.eql(self.framework_total))
                    return error.SegmentClosureIdentityMismatch;
                if (!self.framework_total.isZero())
                    return error.RelationDomainClosureMismatch;
                try requireSha256Id(self.closure_id);
                if (!std.mem.eql(
                    u8,
                    &self.closure_id,
                    &segmentClosureReceiptIdentity(self),
                )) return error.SegmentClosureIdentityMismatch;
            }

            pub fn validateAgainst(
                self: *const SegmentGlobalClosureReceiptV2,
                verified: *const VerifiedOuterProofV1,
            ) !void {
                try self.validate();
                try verified.validate();
                if (!std.meta.eql(
                    self.native_manifest_id,
                    verified.receipt.manifest_id,
                ) or !std.meta.eql(
                    self.native_verifier_receipt_id,
                    verified.seal.receipt_id,
                ) or !std.meta.eql(
                    self.native_relation_replay_id,
                    verified.relation_replay.identity,
                )) return error.SegmentClosureIdentityMismatch;
                if (!self.provider_claim.claimed_sum.eql(qm31FromWire(
                    verified.receipt.claimed_sums[
                        @intFromEnum(air.universal_roster.Component.range_check_8_8)
                    ],
                )) or !self.public_boundaries.wire.claimed_sum.eql(qm31FromWire(
                    verified.receipt.wire_closure[1],
                )) or !self.public_boundaries.verifier_input.claimed_sum.eql(qm31FromWire(
                    verified.receipt.verifier_input_boundary,
                ))) return error.SegmentClosureIdentityMismatch;
            }
        };

        /// Explicit V2 publication. V1 custody remains byte- and type-identical;
        /// callers opt into the additional exact-domain receipt through a separate
        /// entry point.
        pub const VerifiedOuterProofV2 = struct {
            verified_v1: VerifiedOuterProofV1,
            global_closure: SegmentGlobalClosureReceiptV2,

            pub fn deinit(self: *VerifiedOuterProofV2, allocator: std.mem.Allocator) void {
                self.verified_v1.deinit(allocator);
                self.* = undefined;
            }

            pub fn validate(self: *const VerifiedOuterProofV2) !void {
                try self.global_closure.validateAgainst(&self.verified_v1);
            }

            pub fn productionReady(_: *const VerifiedOuterProofV2) bool {
                // Exact segment closure does not install or prove a temporal parent.
                return false;
            }
        };

        pub const CapturePublication = union(enum) {
            capture: *OuterProofCapture,
            verified: *VerifiedOuterProofV1,
            verified_v2: *VerifiedOuterProofV2,
        };
        pub const VerifierScheme = stwo_core.pcs.verifier.CommitmentSchemeVerifier(
            recursion.engine.Hasher,
            recursion.engine.MerkleChannel,
        );
        pub const InputRelation = universal_binding.Binding(input_air);
        pub const VmInputRelation = universal_binding.Binding(vm_input_air);
        pub const CompositionControlRelation = universal_binding.Binding(composition_control_air);
        pub const QueryBitsRelation = universal_binding.Binding(query_bits_air);
        pub const QueryMappingRelation = universal_binding.Binding(query_mapping_air);
        pub const MerkleRootRelation = universal_binding.Binding(merkle_root_air);
        pub const TraceMerkleRelation = universal_binding.Binding(trace_merkle_air);
        pub const PcsRelation = universal_binding.Binding(pcs_air);
        pub const FriLeafRelation = universal_binding.Binding(fri_leaf_air);
        pub const FriNodeRelation = universal_binding.Binding(fri_node_air);
        pub const FriAnchorRelation = universal_binding.Binding(fri_anchor_air);
        pub const ControlRelation = universal_binding.Binding(control_air);
        pub const MultiplyRelation = universal_binding.Binding(multiply_air);
        pub const InverseRelation = universal_binding.Binding(inverse_air);
        pub const LinearRelation = universal_binding.Binding(linear_air);
        pub const MerklePathRelation = universal_binding.Binding(merkle_path_air);
        pub const InputFramework = framework.Runtime(InputRelation.Runtime);
        pub const VmInputFramework = framework.Runtime(VmInputRelation.Runtime);
        pub const CompositionControlFramework = framework.Runtime(CompositionControlRelation.Runtime);
        pub const QueryBitsFramework = framework.Runtime(QueryBitsRelation.Runtime);
        pub const QueryMappingFramework = framework.Runtime(QueryMappingRelation.Runtime);
        pub const MerkleRootFramework = framework.Runtime(MerkleRootRelation.Runtime);
        pub const TraceMerkleFramework = framework.Runtime(TraceMerkleRelation.Runtime);
        pub const PcsFramework = framework.Runtime(PcsRelation.Runtime);
        pub const FriLeafFramework = framework.Runtime(FriLeafRelation.Runtime);
        pub const FriNodeFramework = framework.Runtime(FriNodeRelation.Runtime);
        pub const FriAnchorFramework = framework.Runtime(FriAnchorRelation.Runtime);
        pub const ControlFramework = framework.Runtime(ControlRelation.Runtime);
        pub const MultiplyFramework = framework.Runtime(MultiplyRelation.Runtime);
        pub const InverseFramework = framework.Runtime(InverseRelation.Runtime);
        pub const LinearFramework = framework.Runtime(LinearRelation.Runtime);
        pub const MerklePathFramework = framework.Runtime(MerklePathRelation.Runtime);
        pub const InputAdapter = adapter.Component(input_air, InputRelation);
        pub const VmInputAdapter = adapter.Component(vm_input_air, VmInputRelation);
        pub const CompositionControlAdapter = adapter.Component(
            composition_control_air,
            CompositionControlRelation,
        );
        pub const QueryBitsAdapter = adapter.Component(query_bits_air, QueryBitsRelation);
        pub const QueryMappingAdapter = adapter.Component(query_mapping_air, QueryMappingRelation);
        pub const MerkleRootAdapter = adapter.Component(merkle_root_air, MerkleRootRelation);
        pub const TraceMerkleAdapter = adapter.Component(trace_merkle_air, TraceMerkleRelation);
        pub const PcsAdapter = adapter.Component(pcs_air, PcsRelation);
        pub const FriLeafAdapter = adapter.Component(fri_leaf_air, FriLeafRelation);
        pub const FriNodeAdapter = adapter.Component(fri_node_air, FriNodeRelation);
        pub const FriAnchorAdapter = adapter.Component(fri_anchor_air, FriAnchorRelation);
        pub const ControlAdapter = adapter.Component(control_air, ControlRelation);
        pub const MultiplyAdapter = adapter.Component(multiply_air, MultiplyRelation);
        pub const InverseAdapter = adapter.Component(inverse_air, InverseRelation);
        pub const LinearAdapter = adapter.Component(linear_air, LinearRelation);
        pub const MerklePathAdapter = adapter.Component(merkle_path_air, MerklePathRelation);
        pub const V2VmInputAdapter = adapter.ComponentForManifest(
            vm_input_air,
            VmInputRelation,
            manifest_v2,
        );
        pub const V2CompositionControlAdapter = adapter.ComponentForManifest(
            composition_control_air,
            CompositionControlRelation,
            manifest_v2,
        );
        pub const V2QueryBitsAdapter = adapter.ComponentForManifest(
            query_bits_air,
            QueryBitsRelation,
            manifest_v2,
        );
        pub const V2QueryMappingAdapter = adapter.ComponentForManifest(
            query_mapping_air,
            QueryMappingRelation,
            manifest_v2,
        );
        pub const V2MerkleRootAdapter = adapter.ComponentForManifest(
            merkle_root_air,
            MerkleRootRelation,
            manifest_v2,
        );
        pub const V2TraceMerkleAdapter = adapter.ComponentForManifest(
            trace_merkle_air,
            TraceMerkleRelation,
            manifest_v2,
        );
        pub const V2PcsAdapter = adapter.ComponentForManifest(
            pcs_air,
            PcsRelation,
            manifest_v2,
        );
        pub const V2FriLeafAdapter = adapter.ComponentForManifest(
            fri_leaf_air,
            FriLeafRelation,
            manifest_v2,
        );
        pub const V2FriNodeAdapter = adapter.ComponentForManifest(
            fri_node_air,
            FriNodeRelation,
            manifest_v2,
        );
        pub const V2FriAnchorAdapter = adapter.ComponentForManifest(
            fri_anchor_air,
            FriAnchorRelation,
            manifest_v2,
        );
        pub const V2ControlAdapter = adapter.ComponentForManifest(
            control_air,
            ControlRelation,
            manifest_v2,
        );
        pub const V2InputAdapter = adapter.ComponentForManifest(
            input_air,
            InputRelation,
            manifest_v2,
        );
        pub const V2MultiplyAdapter = adapter.ComponentForManifest(
            multiply_air,
            MultiplyRelation,
            manifest_v2,
        );
        pub const V2InverseAdapter = adapter.ComponentForManifest(
            inverse_air,
            InverseRelation,
            manifest_v2,
        );
        pub const V2LinearAdapter = adapter.ComponentForManifest(
            linear_air,
            LinearRelation,
            manifest_v2,
        );
        pub const V2MerklePathAdapter = adapter.ComponentForManifest(
            merkle_path_air,
            MerklePathRelation,
            manifest_v2,
        );
        pub const V2Poseidon2Adapter = shared_provider.Poseidon2AdapterForManifest(
            manifest_v2,
        );

        pub const FORMAT_VERSION: u32 = 1;
        pub const TRANSCRIPT_DOMAIN: u32 = 0x5246_4131; // "RFA1"
        pub const SEGMENT_CIRCUIT_ID: u32 = 301;
        pub const LEFT_CIRCUIT_ID: u32 = 302;
        pub const RIGHT_CIRCUIT_ID: u32 = 303;
        pub const PCS_SEGMENT_CIRCUIT_ID: u32 = 201;
        pub const PCS_LEFT_CIRCUIT_ID: u32 = 202;
        pub const PCS_RIGHT_CIRCUIT_ID: u32 = 203;
        pub const VM_BINARY_CAPACITY_CIRCUIT_ID: u32 = 2;
        pub const INACTIVE_MIDDLE_FIRST: usize = 10;
        pub const INACTIVE_MIDDLE_COUNT: usize = 2;
        pub const INACTIVE_LOG_SIZE: u32 = 4;
        pub const COMPOSITION_DIAGNOSTIC_ENV = "STWO_RECURSION_DIAGNOSE_COMPOSITION";
        pub const STAGE_TELEMETRY_ENV = "STWO_RECURSION_OUTER_STAGE_TELEMETRY";
        pub const CLOSURE_DIAGNOSTIC_ENV = "STWO_RECURSION_OUTER_CLOSURE_DIAGNOSTIC";

        pub const OUTER_CONFIG: stwo_core.pcs.PcsConfig = .{
            .pow_bits = 0,
            .fri_config = .{
                .log_blowup_factor = 1,
                .log_last_layer_degree_bound = 0,
                .n_queries = 3,
                .fold_step = 1,
            },
        };

        pub const AIR_PROGRAM_ID_DOMAIN: u32 = 0x4f41_4952; // "OAIR"
        pub const MANIFEST_ID_DOMAIN: u32 = 0x4f4d_414e; // "OMAN"
        pub const VERIFICATION_KEY_ID_DOMAIN: u32 = 0x4f56_4b49; // "OVKI"

        comptime {
            if (OUTER_CONFIG.pow_bits != outer_admission.PCS_POW_BITS or
                OUTER_CONFIG.fri_config.log_blowup_factor !=
                    outer_admission.LOG_BLOWUP_FACTOR or
                OUTER_CONFIG.fri_config.log_last_layer_degree_bound !=
                    outer_admission.LOG_LAST_LAYER_DEGREE_BOUND or
                OUTER_CONFIG.fri_config.n_queries != outer_admission.QUERY_COUNT or
                OUTER_CONFIG.fri_config.fold_step != outer_admission.FOLD_STEP or
                air.universal_roster.COMPONENT_COUNT !=
                    outer_admission.CLAIMED_SUM_COUNT or
                poseidon2_air.N_SUMS != POSEIDON2_PARTIAL_COUNT or
                @intFromEnum(air.universal_roster.Component.poseidon2) !=
                    POSEIDON2_ROSTER_ROW or
                outer_admission.CLAIMED_SUM_COUNT !=
                    POSEIDON2_COMPOSITION_CLAIM_INDICES[0] or
                POSEIDON2_COMPOSITION_CLAIM_INDICES[1] !=
                    POSEIDON2_COMPOSITION_CLAIM_INDICES[0] + 1)
            {
                @compileError("outer child admission profile drifted from native verifier");
            }
        }

        /// Shape authority for feeding a successfully verified outer proof into the
        /// next recursion level. The outer transcript has no interaction PoW, mixes
        /// one claim for every universal-roster row, and uses the local PCS profile.
        pub fn captureProfileConfig() recursion.captured_fri.ProfileConfig {
            return .{
                .log_blowup_factor = OUTER_CONFIG.fri_config.log_blowup_factor,
                .log_last_layer_degree_bound = OUTER_CONFIG.fri_config.log_last_layer_degree_bound,
                .interaction_pow_bits = 0,
                .pcs_pow_bits = OUTER_CONFIG.pow_bits,
                .claimed_sum_count = air.universal_roster.COMPONENT_COUNT,
            };
        }

        pub const Error = error{
            ArithmeticOverflow,
            AuxiliaryClaimNonCanonical,
            AuxiliaryClaimSealMismatch,
            AuxiliaryClaimTotalMismatch,
            AuthorityMismatch,
            DiagnosticColumnCountMismatch,
            DiagnosticColumnLogOutOfRange,
            DiagnosticCompositionLogMismatch,
            DiagnosticComponentLogOutOfRange,
            DiagnosticComponentLogMismatch,
            DiagnosticCoefficientsUnavailable,
            DiagnosticPendingCommit,
            DiagnosticRetentionPolicyMismatch,
            DiagnosticRosterMismatch,
            DiagnosticTreeCountMismatch,
            InvalidProofShape,
            MutationConsumedProof,
            PreprocessedRootMismatch,
            ProofAlreadyConsumed,
            MutationAccepted,
            MutationPublishedOutput,
            MutationWrongError,
            PoseidonClosureMismatch,
            RelationReplayCheckpointMismatch,
            RelationReplayIdentityMismatch,
            RelationReplayManifestMismatch,
            RelationDomainClosureMismatch,
            SegmentClosureIdentityMismatch,
            SegmentClosureProviderMismatch,
            SegmentClosurePublicationUnavailable,
            V2Rows18Through35PreflightMismatch,
            V2CoreRows18Through34PreflightMismatch,
            V2CoreCohortMismatch,
            V2TranscriptEvidenceUnavailable,
            WireClosureMismatch,
            WorkerPoolMismatch,
        };

        /// Sealed cold receipt proving that the existing native-verifier machinery
        /// can be constructed as a boundary-independent rows-18--34 cohort.  This is
        /// the reuse seam for V2: no V1 transcript/public source is synthesized, and
        /// row 35 remains owned by the versioned statement/range authority.
        pub const V2CoreRows18Through34PreflightReceipt = struct {
            format_version: u16 = V2_CORE_ROWS_18_34_PREFLIGHT_FORMAT_VERSION,
            first_row: u8 = V2_CORE_FIRST_ROW,
            last_row: u8 = V2_CORE_LAST_ROW,
            row_count: u8 = V2_CORE_ROW_COUNT,
            preprocessed_columns: u32,
            main_columns: u32,
            interaction_columns: u32,
            constraint_count: u32,
            log_sizes: [LogIndex.count]u32,
            core_poseidon_call_count: u32,
            manifest_seal: [32]u8,
            lowering_authority_id: [32]u8,
            identity: [32]u8,

            pub fn validate(
                self: *const V2CoreRows18Through34PreflightReceipt,
            ) !void {
                if (self.format_version !=
                    V2_CORE_ROWS_18_34_PREFLIGHT_FORMAT_VERSION or
                    self.first_row != V2_CORE_FIRST_ROW or
                    self.last_row != V2_CORE_LAST_ROW or
                    self.row_count != V2_CORE_ROW_COUNT or
                    self.preprocessed_columns == 0 or self.main_columns == 0 or
                    self.interaction_columns == 0 or self.constraint_count == 0 or
                    self.core_poseidon_call_count == 0 or
                    std.mem.allEqual(u8, &self.manifest_seal, 0) or
                    std.mem.allEqual(u8, &self.lowering_authority_id, 0) or
                    !std.mem.eql(
                        u8,
                        &self.identity,
                        &v2CoreRows18Through34PreflightIdentity(self),
                    ))
                {
                    return error.V2CoreRows18Through34PreflightMismatch;
                }
                for (self.log_sizes) |log_size| {
                    if (log_size == 0 or log_size >= 31)
                        return error.V2CoreRows18Through34PreflightMismatch;
                }
            }

            pub fn productionReady(
                _: *const V2CoreRows18Through34PreflightReceipt,
            ) bool {
                return false;
            }
        };

        /// Constructs and seals the boundary-independent verifier core that V2 reuses
        /// at universal roster rows 18--34.  The partial manifest is deliberately
        /// inspected here: accepting an accidentally admitted boundary/range row
        /// would turn a useful reuse seam into an implicit V1 compatibility claim.
        pub fn preflightV2CoreRows18Through34(
            allocator: std.mem.Allocator,
            captured: *const recursion.captured_fri.Owned,
            vm_air: *const recursion.vm_air_composition_circuit.Prepared,
            verifier_plans: VerifierPlans,
        ) !V2CoreRows18Through34PreflightReceipt {
            try captured.evaluation.validateAgainst(&captured.circuit);
            try captured.pcs_evaluation.validateAgainst(&captured.pcs_circuit);
            try vm_air.validate();
            try verifier_plans.vm.validate();
            try verifier_plans.recursion.validate();
            if (verifier_plans.vm.schema != .vm or
                verifier_plans.recursion.schema != .recursion)
            {
                return error.V2CoreRows18Through34PreflightMismatch;
            }

            var authority = try Authority.init(
                allocator,
                &captured.circuit,
                &captured.pcs_circuit,
                captured.trace_tree_heights,
                captured.column_log_sizes,
                ScheduleFacts.fromCaptured(captured),
                vm_air,
                verifier_plans,
                null,
                null,
                0,
            );
            defer authority.deinit();
            try authority.manifest.validate();
            if (authority.full_roster or authority.segment_transcript_inputs != null or
                authority.segment_transcript != null or
                authority.segment_leaf_admission != null or authority.vm_air == null or
                authority.manifest.roster_count != V2_CORE_ROW_COUNT or
                authority.manifest.placements[V2_CORE_LAST_ROW + 1] != null)
            {
                return error.V2CoreRows18Through34PreflightMismatch;
            }
            for (
                authority.manifest.roster_rows[0..authority.manifest.roster_count],
                V2_CORE_FIRST_ROW..V2_CORE_LAST_ROW + 1,
            ) |actual, expected| {
                if (actual != expected)
                    return error.V2CoreRows18Through34PreflightMismatch;
            }

            var result = V2CoreRows18Through34PreflightReceipt{
                .preprocessed_columns = authority.manifest.total_preprocessed_columns,
                .main_columns = authority.manifest.total_main_columns,
                .interaction_columns = authority.manifest.total_interaction_columns,
                .constraint_count = authority.manifest.total_constraints,
                .log_sizes = authority.log_sizes,
                .core_poseidon_call_count = authority.poseidon2_row_count,
                .manifest_seal = authority.manifest.seal,
                .lowering_authority_id = authority.lowering_plan.authority_digest,
                .identity = undefined,
            };
            result.identity = v2CoreRows18Through34PreflightIdentity(&result);
            try result.validate();
            return result;
        }

        pub const NATIVE_V2_CORE_FORMAT_VERSION: u16 = 1;
        pub const NATIVE_V2_CORE_FIRST_ROW: u8 = V2_CORE_FIRST_ROW;
        pub const NATIVE_V2_CORE_LAST_ROW: u8 = V2_CORE_LAST_ROW;
        pub const NATIVE_V2_CORE_ROW_COUNT: usize = V2_CORE_ROW_COUNT;
        /// Publication copies from the three retained trees and allocates nothing.
        /// Interaction generation is a separate, explicitly cold phase because the
        /// typed framework currently allocates bounded generation/audit scratch.
        pub const NATIVE_V2_CORE_HOT_TREE_HEAP_ALLOCATIONS = [_]usize{ 0, 0, 0 };
        pub const NATIVE_V2_CORE_COLD_DOMAIN_AUDIT_ALLOCATION_CALLS: usize = 2 * 16;
        pub const NATIVE_V2_CORE_INTERACTION_GENERATION_IS_COLD = true;
        pub const NATIVE_V2_CORE_PROVIDER_INSTANCE_COUNT: usize = 1;
        /// Audited ownership invariant: every retained slice points either into an
        /// allocator-owned buffer or caller-owned authenticated input, and the two
        /// retained verifier schedules are allocator-created objects. Executors and
        /// relation plans retain value bindings, never an address of this owner or of
        /// one of its sibling fields. The owner is consequently safe to move, while
        /// `initInPlace` lets aggregate cohorts give it a stable address regardless.
        pub const NATIVE_V2_CORE_RETAINS_SELF_POINTERS = false;
        pub const NATIVE_V2_CORE_AUTHORITY_ID_DOMAIN =
            "stwo-zig/typed-air/native-segment-core-v2/authority/v1\x00";
    };
}
