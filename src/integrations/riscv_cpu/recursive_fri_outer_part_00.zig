//! Cohesive internal authority extracted from recursive_fri_outer.zig.

pub fn Namespace(comptime context: type) type {
    return struct {
        const verifiedStatementId = context.d_verifiedStatementId;
        const replayRelationTranscript = context.d_replayRelationTranscript;
        const deriveRelationReplayIdentity = context.d_deriveRelationReplayIdentity;
        const validateAuxiliaryQm31 = context.d_validateAuxiliaryQm31;
        const validateAuxiliaryDigest = context.d_validateAuxiliaryDigest;
        const validatePoseidon2AuxiliaryClaimCustody = context.d_validatePoseidon2AuxiliaryClaimCustody;
        const validatePoseidon2AuxiliaryClaimInputs = context.d_validatePoseidon2AuxiliaryClaimInputs;
        const derivePoseidon2AuxiliaryClaimSeal = context.d_derivePoseidon2AuxiliaryClaimSeal;
        const segmentProviderClaimIdentity = context.d_segmentProviderClaimIdentity;
        const requireSha256Id = context.d_requireSha256Id;

        pub const std = @import("std");
        pub const stwo_core = @import("stwo_core");
        pub const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
        pub const frontend = @import("stwo_riscv_frontend");
        pub const prover_air_accumulation = @import("stwo_prover_engine").air.accumulation;
        pub const prover_air = @import("stwo_prover_engine").air.component_prover;
        pub const prover_circle = @import("stwo_prover_engine").poly.circle;
        pub const prover_pcs = @import("stwo_prover_engine").pcs;
        pub const prover_work_pool = @import("stwo_prover_engine").work_pool;

        pub const M31 = stwo_core.fields.m31.M31;
        pub const QM31 = stwo_core.fields.qm31.QM31;
        pub const recursion = frontend.recursion;
        pub const outer_admission = recursion.outer_parent_child_admission;
        pub const global_closure = recursion.binary_global_closure_outer_source;
        pub const segment_range_authority = recursion.segment_range_authority;
        pub const air = recursion.air;
        pub const vm_input_air = air.vm_air_composition_input;
        pub const vm_input_witness = air.vm_air_composition_input_witness;
        pub const composition_control_air = air.vm_air_composition_control.Air;
        pub const composition_control_witness = air.control_slice_witness;
        pub const circuit_mod = air.fri_verifier_circuit;
        pub const query_bits_air = air.query_bits;
        pub const query_bits_witness = air.query_bits_witness;
        pub const query_mapping_air = air.query_mapping;
        pub const query_mapping_witness = air.query_mapping_witness;
        pub const merkle_root_air = air.merkle_root;
        pub const merkle_root_witness = air.merkle_root_witness;
        pub const trace_merkle_air = air.trace_merkle;
        pub const trace_merkle_witness = air.trace_merkle_witness;
        pub const pcs_circuit_mod = air.pcs_deep_circuit;
        pub const pcs_air = air.pcs_deep_input;
        pub const pcs_witness = air.pcs_deep_input_witness;
        pub const fri_leaf_air = air.fri_merkle_leaf;
        pub const fri_leaf_witness = air.fri_merkle_leaf_witness;
        pub const fri_node_air = air.fri_merkle_node;
        pub const fri_node_witness = air.fri_merkle_node_witness;
        pub const fri_anchor_air = air.fri_merkle_anchor;
        pub const fri_anchor_witness = air.fri_merkle_anchor_witness;
        pub const control_air = air.fri_verifier_control;
        pub const control_witness = air.fri_verifier_control_witness;
        pub const schedule = air.verifier_schedule;
        pub const input_air = air.fri_verifier_input;
        pub const input_witness = air.fri_verifier_input_witness;
        pub const composition_graph = air.composition_circuit;
        pub const lowering = air.verifier_arithmetic_lowering;
        pub const multiply_air = air.qm31_mul_full;
        pub const multiply_witness = air.qm31_mul_full_witness;
        pub const inverse_air = air.qm31_inv;
        pub const inverse_witness = air.qm31_inv_witness;
        pub const linear_air = air.linear_ops;
        pub const linear_witness = air.linear_ops_witness;
        pub const merkle_path_air = air.merkle_path;
        pub const merkle_path_witness = air.merkle_path_witness;
        pub const merkle_path_poseidon = air.merkle_path_poseidon_bridge;
        pub const transcript_payload_relation = air.transcript_payload_relation;
        pub const transcript_payload_witness = air.transcript_payload_witness;
        pub const verifier_randomness_relation = air.verifier_randomness_relation;
        pub const verifier_randomness_witness = air.verifier_randomness_witness;
        pub const statement_input_relation = air.statement_input_relation;
        pub const statement_input_witness = air.statement_input_witness;
        pub const statement_semantics_relation = air.statement_semantics_input_relation;
        pub const statement_semantics_witness = air.statement_semantics_input_witness;
        pub const manifest_mod = air.universal_adapter_manifest;
        pub const manifest_v2 = air.segment_outer_adapter_manifest_v2;
        pub const universal_manifest = air.universal_manifest;
        pub const catalog = air.universal_catalog;
        pub const shared_provider = air.universal_shared_provider;
        pub const range_bridge = air.range_check_8_8_bridge;
        pub const universal = air.universal_challenges;
        pub const universal_binding = air.universal_relation_binding;
        pub const adapter = air.universal_typed_component;
        pub const framework = air.framework_interaction;
        pub const poseidon2_air = frontend.air.memory_commitment.poseidon2_air;
        pub const poseidon2_authority = frontend.air.typed_poseidon2_authority;
        pub const shared_schedule_v2 = recursion.segment_shared_poseidon_schedule_v2;
        pub const segment_transcript_source_v2 =
            recursion.segment_transcript_outer_source_v2;
        pub const public_native_sum =
            recursion.segment_public_native_sum_authority_v2;

        pub const SegmentTranscriptSource = recursion.segment_transcript_outer_source.Source(
            recursion.segment_profile.DIMENSIONS,
        );
        pub const SegmentPublicSource = recursion.segment_public_outer_source.Source;
        pub const SegmentLeafOuterBundle = recursion.segment_leaf_outer_bundle.Bundle(
            recursion.segment_profile.DIMENSIONS,
        );

        pub const LogIndex = struct {
            pub const vm_input: usize = 0;
            pub const composition_control: usize = 1;
            pub const query_bits: usize = 2;
            pub const query_mapping: usize = 3;
            pub const merkle_root: usize = 4;
            pub const trace_merkle: usize = 5;
            pub const pcs_deep: usize = 6;
            pub const fri_leaf: usize = 7;
            pub const fri_node: usize = 8;
            pub const fri_anchor: usize = 9;
            pub const fri_control: usize = 10;
            pub const fri_input: usize = 11;
            pub const multiply: usize = 12;
            pub const inverse: usize = 13;
            pub const linear: usize = 14;
            pub const merkle_path: usize = 15;
            pub const poseidon2: usize = 16;
            pub const count: usize = 17;
        };

        /// VM AIR + SegmentV2 public sums + three transcript/public lanes + PCS + FRI
        /// + the binary-capacity anchor. The fixed stack buffer keeps evaluation
        /// assembly allocation-free while the authenticated reference remains the
        /// exact runtime lane-count authority.
        pub const MAX_ARITHMETIC_EVALUATION_LANES: usize = 8;

        pub const Engine = recursion.engine.ProverEngineForBackend(CpuBackend);
        pub const OuterProofCapture = stwo_core.pcs.verifier.VerifiedProofCapture(
            recursion.engine.Hasher,
        );

        pub const POSEIDON2_ROSTER_ROW: usize = 34;
        pub const POSEIDON2_PARTIAL_COUNT: usize = 2;
        pub const POSEIDON2_COMPOSITION_CLAIM_INDICES =
            [POSEIDON2_PARTIAL_COUNT]u32{ 36, 37 };
        pub const RELATION_REPLAY_FORMAT_VERSION: u32 = 1;
        pub const RELATION_REPLAY_DOMAIN: u32 = 0x4f52_5231; // "ORR1"
        pub const RELATION_REPLAY_HEAP_ALLOCATIONS: usize = 0;
        pub const POSEIDON2_AUXILIARY_CLAIM_FORMAT_VERSION: u32 = 2;
        pub const POSEIDON2_AUXILIARY_CLAIM_SEAL_DOMAIN: u32 =
            0x4f50_3241; // "OP2A"
        pub const SEGMENT_GLOBAL_CLOSURE_FORMAT_VERSION: u16 = 2;
        pub const SEGMENT_GLOBAL_CLOSURE_CHECKED_DOMAINS: usize =
            global_closure.DOMAIN_COUNT;
        pub const SEGMENT_GLOBAL_CLOSURE_VERIFIER_TUPLE_LEDGER_ALLOCATIONS: usize = 0;
        pub const V2_ROWS_18_35_PREFLIGHT_FORMAT_VERSION: u16 = 3;
        pub const V2_ROWS_18_35_HEAP_ALLOCATIONS: usize = 0;
        pub const V2_CORE_ROWS_18_34_PREFLIGHT_FORMAT_VERSION: u16 = 1;
        pub const V2_CORE_COHORT_FORMAT_VERSION: u16 = 1;
        /// Once prepared, tree publication and component-gate assembly perform no
        /// heap allocation.  The cold constructor intentionally owns every buffer
        /// whose address is retained by a type-erased AIR component.
        pub const V2_CORE_COHORT_HOT_HEAP_ALLOCATIONS: usize = 0;
        pub const V2_CORE_FIRST_ROW: u8 = 18;
        pub const V2_CORE_LAST_ROW: u8 = 34;
        pub const V2_CORE_ROW_COUNT: u8 =
            V2_CORE_LAST_ROW - V2_CORE_FIRST_ROW + 1;
        /// The universal row ordinals remain the frozen 36-row V1 roster.  V2 adds
        /// two committed boundary sources in front of that roster; they are not
        /// aliases for rows 10 or 16 and must not be hidden inside the universal
        /// count.
        pub const V2_UNIVERSAL_ROSTER_COMPONENT_COUNT: u8 =
            global_closure.TOTAL_ROW_COUNT;
        pub const V2_AUTHORITY_SOURCE_COMPONENT_COUNT: u8 =
            recursion.segment_leaf_outer_authority_v2.COMPONENT_COUNT;
        pub const V2_TARGET_COMPONENT_COUNT: u8 =
            V2_UNIVERSAL_ROSTER_COMPONENT_COUNT +
            V2_AUTHORITY_SOURCE_COMPONENT_COUNT;
        comptime {
            if (V2_UNIVERSAL_ROSTER_COMPONENT_COUNT != 36 or
                V2_AUTHORITY_SOURCE_COMPONENT_COUNT != 2 or
                V2_TARGET_COMPONENT_COUNT != 38)
            {
                @compileError("V2 outer roster contract changed; version and audit the boundary mapping");
            }
        }
        pub const V2_ROWS_18_35_PREFLIGHT_ID_DOMAIN =
            "stwo-zig/typed-air/v2-rows-18-35-preflight/v2\x00";
        pub const V2_CORE_ROWS_18_34_PREFLIGHT_ID_DOMAIN =
            "stwo-zig/typed-air/v2-core-rows-18-34-preflight/v1\x00";
        pub const V2_CORE_COHORT_ID_DOMAIN =
            "stwo-zig/typed-air/v2-core-rows-18-34-cohort/v1\x00";
        pub const V2_CORE_TREE_ID_DOMAIN =
            "stwo-zig/typed-air/v2-core-rows-18-34-tree/v1\x00";
        pub const V2_CORE_POSEIDON_CALLS_ID_DOMAIN =
            "stwo-zig/typed-air/v2-core-rows-18-34-poseidon-calls/v1\x00";
        pub const V2_CORE_RELATION_BINDING_ID_DOMAIN =
            "stwo-zig/typed-air/v2-core-rows-18-34-relations/v1\x00";
        pub const SEGMENT_PROVIDER_CLAIM_ID_DOMAIN =
            "stwo-zig/typed-air/segment-global-closure-provider/v2\x00";
        pub const SEGMENT_CLOSURE_INPUT_ID_DOMAIN =
            "stwo-zig/typed-air/segment-global-closure-input/v2\x00";
        pub const SEGMENT_CLOSURE_RECEIPT_ID_DOMAIN =
            "stwo-zig/typed-air/segment-global-closure-result/v2\x00";
        pub const SEGMENT_WIRE_BOUNDARY_SNAPSHOT_DOMAIN =
            "stwo-zig/typed-air/segment-wire-boundary-snapshot/v2\x00";
        pub const SEGMENT_WIRE_BOUNDARY_TUPLES_DOMAIN =
            "stwo-zig/typed-air/segment-wire-boundary-tuples/v2\x00";
        pub const SEGMENT_VERIFIER_INPUT_SNAPSHOT_DOMAIN =
            "stwo-zig/typed-air/segment-verifier-input-snapshot/v2\x00";
        pub const SEGMENT_VERIFIER_INPUT_TUPLES_DOMAIN =
            "stwo-zig/typed-air/segment-verifier-input-tuples/v2\x00";

        /// Verifier-owned channel state immediately before the fixed 47-pair
        /// universal-relation draw. Its identity is accepted only when replaying the
        /// draw, canonical 36-claim mix, public boundaries, and interaction root lands
        /// exactly on the receipt's already authenticated pre-core checkpoint.
        pub const RelationReplayReceiptV1 = struct {
            format_version: u32 = RELATION_REPLAY_FORMAT_VERSION,
            domain: u32 = RELATION_REPLAY_DOMAIN,
            pre_relation_channel: outer_admission.ChannelCheckpointV1,
            identity: recursion.poseidon2_channel.Digest,

            /// Producer/test constructor that issues no detached checkpoint token: the
            /// complete transition must reach `receipt.pre_core_channel` first.
            pub fn initVerified(
                pre_relation_channel: outer_admission.ChannelCheckpointV1,
                receipt: *const outer_admission.VerifierReceiptV1,
                verifier_seal: outer_admission.VerifierSealV1,
                interaction_root: recursion.poseidon2_channel.Digest,
            ) !RelationReplayReceiptV1 {
                pre_relation_channel.validate() catch
                    return error.RelationReplayCheckpointMismatch;
                try verifier_seal.validate();
                const replay = try replayRelationTranscript(
                    pre_relation_channel,
                    receipt,
                    interaction_root,
                );
                if (!std.meta.eql(replay.final_channel, receipt.pre_core_channel))
                    return error.RelationReplayCheckpointMismatch;
                const identity = deriveRelationReplayIdentity(
                    pre_relation_channel,
                    receipt,
                    verifier_seal,
                    interaction_root,
                );
                validateAuxiliaryDigest(identity) catch
                    return error.RelationReplayIdentityMismatch;
                return .{
                    .pre_relation_channel = pre_relation_channel,
                    .identity = identity,
                };
            }

            /// Deterministic producer/test utility for assembling the target receipt
            /// before `initVerified`. This returns no custody token; validation still
            /// requires the issued receipt identity and the verifier publication.
            pub fn expectedPreCoreChannel(
                pre_relation_channel: outer_admission.ChannelCheckpointV1,
                receipt: *const outer_admission.VerifierReceiptV1,
                interaction_root: recursion.poseidon2_channel.Digest,
            ) !outer_admission.ChannelCheckpointV1 {
                pre_relation_channel.validate() catch
                    return error.RelationReplayCheckpointMismatch;
                return (try replayRelationTranscript(
                    pre_relation_channel,
                    receipt,
                    interaction_root,
                )).final_channel;
            }

            pub fn validateAndReplay(
                self: RelationReplayReceiptV1,
                receipt: *const outer_admission.VerifierReceiptV1,
                verifier_seal: outer_admission.VerifierSealV1,
                interaction_root: recursion.poseidon2_channel.Digest,
            ) !universal.UniversalRelations {
                if (self.format_version != RELATION_REPLAY_FORMAT_VERSION or
                    self.domain != RELATION_REPLAY_DOMAIN)
                {
                    return error.RelationReplayIdentityMismatch;
                }
                self.pre_relation_channel.validate() catch
                    return error.RelationReplayCheckpointMismatch;
                try verifier_seal.validate();
                validateAuxiliaryDigest(self.identity) catch
                    return error.RelationReplayIdentityMismatch;
                const replay = try replayRelationTranscript(
                    self.pre_relation_channel,
                    receipt,
                    interaction_root,
                );
                if (!std.meta.eql(replay.final_channel, receipt.pre_core_channel))
                    return error.RelationReplayCheckpointMismatch;
                const expected = deriveRelationReplayIdentity(
                    self.pre_relation_channel,
                    receipt,
                    verifier_seal,
                    interaction_root,
                );
                if (!std.meta.eql(expected, self.identity))
                    return error.RelationReplayIdentityMismatch;
                return replay.relations;
            }
        };

        /// Versioned, domain-separated authentication of the two native Poseidon2
        /// recurrence coordinates retained outside proof-transcript V1. The digest
        /// binds their order as composition claimed-sum inputs 36 and 37 as well as
        /// the already authenticated roster-row-34 total.
        pub const Poseidon2AuxiliaryClaimSealV1 = struct {
            format_version: u32 = POSEIDON2_AUXILIARY_CLAIM_FORMAT_VERSION,
            domain: u32 = POSEIDON2_AUXILIARY_CLAIM_SEAL_DOMAIN,
            digest: recursion.poseidon2_channel.Digest,

            /// Producer/test constructor. It validates canonicality and the fixed-wire
            /// row-34 total before issuing the V2 seal bound to relation replay.
            pub fn initVerified(
                receipt: *const outer_admission.VerifierReceiptV1,
                verifier_seal: outer_admission.VerifierSealV1,
                relation_replay_identity: recursion.poseidon2_channel.Digest,
                partials: [POSEIDON2_PARTIAL_COUNT]QM31,
            ) !Poseidon2AuxiliaryClaimSealV1 {
                try validatePoseidon2AuxiliaryClaimInputs(
                    receipt,
                    verifier_seal,
                    relation_replay_identity,
                    partials,
                );
                const result = derivePoseidon2AuxiliaryClaimSeal(
                    receipt,
                    verifier_seal,
                    relation_replay_identity,
                    partials,
                );
                try result.validate();
                return result;
            }

            pub fn validate(self: Poseidon2AuxiliaryClaimSealV1) !void {
                if (self.format_version != POSEIDON2_AUXILIARY_CLAIM_FORMAT_VERSION or
                    self.domain != POSEIDON2_AUXILIARY_CLAIM_SEAL_DOMAIN)
                {
                    return error.AuxiliaryClaimSealMismatch;
                }
                try validateAuxiliaryDigest(self.digest);
            }
        };

        /// Trusted publication produced by one successful independent outer verifier
        /// call. The receipt, seal, and canonical statement words are derived from
        /// verifier-owned state while the capture is still local, then the complete
        /// value is committed to the caller together. No field is decoded or
        /// reconstructed by the consumer.
        pub const VerifiedOuterProofV1 = struct {
            capture: OuterProofCapture,
            receipt: outer_admission.VerifierReceiptV1,
            seal: outer_admission.VerifierSealV1,
            statement_words: recursion.span_statement.StatementWords,
            relation_replay: RelationReplayReceiptV1,
            /// Verifier-authenticated provider recurrence coordinates in canonical
            /// alpha order: `[poseidon2, poseidon2_io]`. Their sum is receipt roster
            /// row 34; binary composition consumes them separately at indices 36/37.
            poseidon2_partials: [POSEIDON2_PARTIAL_COUNT]QM31,
            auxiliary_claim_seal: Poseidon2AuxiliaryClaimSealV1,

            pub fn deinit(self: *VerifiedOuterProofV1, allocator: std.mem.Allocator) void {
                self.capture.deinit(allocator);
                self.* = undefined;
            }

            pub fn validate(self: *const VerifiedOuterProofV1) !void {
                _ = try self.validateAndReplayRelations();
            }

            /// Full role-neutral custody validation plus allocation-free reconstruction
            /// of the 47 universal relation pairs consumed by binary composition.
            pub fn validateAndReplayRelations(
                self: *const VerifiedOuterProofV1,
            ) !universal.UniversalRelations {
                try self.receipt.validate();
                try self.seal.validate();
                const statement_id = try verifiedStatementId(&self.statement_words);
                if (!std.meta.eql(statement_id, self.receipt.statement_id))
                    return error.StatementMismatch;
                const expected = try outer_admission.deriveVerifierSeal(
                    &self.receipt,
                    &self.capture,
                );
                if (!std.meta.eql(expected, self.seal))
                    return error.ProfileSealMismatch;
                if (self.capture.commitments.len <= manifest_mod.INTERACTION_TREE_INDEX)
                    return error.InvalidProofShape;
                const relations = try self.relation_replay.validateAndReplay(
                    &self.receipt,
                    self.seal,
                    self.capture.commitments[manifest_mod.INTERACTION_TREE_INDEX],
                );
                try validatePoseidon2AuxiliaryClaimCustody(
                    &self.receipt,
                    self.seal,
                    self.relation_replay.identity,
                    self.poseidon2_partials,
                    self.auxiliary_claim_seal,
                );
                return relations;
            }

            pub fn productionReady(self: *const VerifiedOuterProofV1) bool {
                return outer_admission.RECURSIVE_PARENT_PRODUCTION and
                    self.receipt.scope == .complete_parent;
            }
        };

        /// Segment-leaf row-35 custody. This is deliberately distinct from the
        /// binary parent's one-source provider claim: segment row 35 is derived from
        /// both statement-semantics and VM-public requests.
        pub const SegmentProviderClaimV2 = struct {
            format_version: u16 = SEGMENT_GLOBAL_CLOSURE_FORMAT_VERSION,
            present: u8 = global_closure.PRESENT,
            padding: u8 = 0,
            source_authority_id: [32]u8,
            snapshot_id: [32]u8,
            claimed_sum: QM31,
            identity: [32]u8,

            fn init(
                source_authority_id: [32]u8,
                snapshot_id: [32]u8,
                claimed_sum: QM31,
            ) !SegmentProviderClaimV2 {
                var result = SegmentProviderClaimV2{
                    .source_authority_id = source_authority_id,
                    .snapshot_id = snapshot_id,
                    .claimed_sum = claimed_sum,
                    .identity = undefined,
                };
                result.identity = segmentProviderClaimIdentity(&result);
                try result.validate();
                return result;
            }

            pub fn validate(self: *const SegmentProviderClaimV2) !void {
                if (self.format_version != SEGMENT_GLOBAL_CLOSURE_FORMAT_VERSION or
                    self.present != global_closure.PRESENT or self.padding != 0)
                {
                    return error.SegmentClosureProviderMismatch;
                }
                const expected_source =
                    segment_range_authority.SourceAuthority.pinned().identityDigest();
                if (!std.mem.eql(
                    u8,
                    &self.source_authority_id,
                    &expected_source,
                )) return error.SegmentClosureProviderMismatch;
                try requireSha256Id(self.snapshot_id);
                try validateAuxiliaryQm31(self.claimed_sum);
                try requireSha256Id(self.identity);
                if (!std.mem.eql(
                    u8,
                    &self.identity,
                    &segmentProviderClaimIdentity(self),
                )) return error.SegmentClosureProviderMismatch;
            }
        };

        // Pointer-free verifier publication for exact segment-leaf global closure.
        // The input identity seals every verifier-rebuilt consumer row/domain value
        // plus the STARK-verified Poseidon provider split; retained totals make all
        // 47 zero checks independently replayable.
        // Native Poseidon identities remain typed `[8]u32` fields and are never
        // reduced into, or substituted for, the SHA-256 closure identifiers.
    };
}
