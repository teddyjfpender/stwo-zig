//! Cohesive internal authority extracted from recursive_temporal_nonfri_source_v2.zig.

pub fn Namespace(comptime context: type) type {
    return struct {
        const Error = context.d_Error;
        const domainBit = context.d_domainBit;
        const rangeMask = context.d_rangeMask;

        pub const std = @import("std");
        pub const stwo_core = @import("stwo_core");
        pub const frontend = @import("stwo_riscv_frontend");

        pub const M31 = stwo_core.fields.m31.M31;
        pub const QM31 = stwo_core.fields.qm31.QM31;
        pub const m31 = stwo_core.fields.m31;

        pub const recursion = frontend.recursion;
        pub const binary_transcript_source = recursion.binary_transcript_outer_source;
        pub const channel = recursion.poseidon2_channel;
        pub const cohort_protocol = recursion.segment_outer_cohort_v2;
        pub const inactive = recursion.binary_inactive_outer_source;
        pub const leaf_authority = recursion.segment_leaf_authority;
        pub const manifest_mod = recursion.air.segment_outer_adapter_manifest_v2;
        pub const outer_admission = recursion.outer_parent_child_admission;
        pub const range_owner = recursion.outer_parent_range_authority;
        pub const schedule = recursion.air.verifier_schedule;
        pub const transcript_shape = recursion.transcript_shape;
        pub const transcript_program = recursion.transcript_program;
        pub const fri_verifier_circuit = recursion.air.fri_verifier_circuit;
        pub const segment_public = recursion.segment_public_outer_source;
        pub const statement_air = recursion.outer_parent_statement_air_source;
        pub const statement_source = recursion.segment_statement_outer_source;
        pub const statement_circuit = recursion.statement_semantics_circuit;
        pub const span_statement = recursion.span_statement;
        pub const temporal = recursion.temporal_pair_node;
        pub const segment_transcript_v2 = recursion.segment_transcript_outer_source_v2;
        pub const transcript_air = recursion.air.transcript_air_witness;
        pub const transcript_component = recursion.air.transcript_air;
        pub const transcript_control = recursion.air.control_witness;
        pub const transcript_binding = recursion.air.transcript_binding_witness;
        pub const transcript_state = recursion.air.transcript_state_witness;
        pub const transcript_word = recursion.air.transcript_word_witness;
        pub const transcript_payload = recursion.air.transcript_payload;
        pub const pow_check_air = recursion.air.pow_check;
        pub const relation_challenge = recursion.air.relation_challenge_witness;
        pub const verifier_randomness = recursion.air.verifier_randomness_witness;
        pub const relation_interaction = recursion.air.relation_interaction;
        pub const framework_interaction = recursion.air.framework_interaction;
        pub const universal_binding = recursion.air.universal_relation_binding;
        pub const universal_catalog = recursion.air.universal_catalog;
        pub const universal_manifest = recursion.air.universal_adapter_manifest;
        pub const universal_roster = recursion.air.universal_roster;
        pub const universal_typed_component = recursion.air.universal_typed_component;
        pub const global_closure = recursion.binary_global_closure_outer_source;
        pub const poseidon2 = frontend.air.memory_commitment.poseidon2;
        pub const pair_authority = @import("recursive_temporal_pair_authority_v2.zig");
        pub const segment_artifact =
            @import("recursive_segment_v2_verified_artifact.zig");
        pub const segment_publication =
            @import("recursive_segment_v2_verified_publication.zig");
        pub const packed_relation_challenge_v2 =
            recursion.air.temporal_packed_relation_challenge_v2;

        pub const control_air = recursion.air.control;
        pub const transcript_binding_air = recursion.air.transcript_binding;
        pub const transcript_state_air = recursion.air.transcript_state;
        pub const transcript_word_air = recursion.air.transcript_word;
        pub const pow_frame_air = recursion.air.pow_frame;
        pub const verifier_randomness_air = recursion.air.verifier_randomness;
        pub const statement_input_air = recursion.air.statement_input;
        pub const statement_input_witness = recursion.air.statement_input_witness;
        pub const statement_semantics_air = recursion.air.statement_semantics_input;
        pub const statement_semantics_witness =
            recursion.air.statement_semantics_input_witness;
        pub const vm_claim_input_air = recursion.air.vm_public_claim_input;
        pub const vm_claim_hash_air = recursion.air.vm_public_claim_hash;
        pub const vm_io_hash_air = recursion.air.vm_public_io_hash;
        pub const vm_claim_semantics_air = recursion.air.vm_public_claim_semantics_input;
        pub const vm_public_logup_air = recursion.air.vm_public_logup_input;
        pub const vm_public_logup_control_air = recursion.air.vm_public_logup_control.Air;

        /// Manifest-parametric native adapters for exact temporal rows 0--17. The
        /// generic evaluator remains the sole equation implementation; the only
        /// protocol substitution is row 8's disjoint packed V2 AIR.
        pub fn TemporalPrefixAdaptersForManifest(comptime manifest_contract: type) type {
            return struct {
                pub const Control = universal_typed_component.ComponentForManifest(
                    control_air,
                    ControlRelation,
                    manifest_contract,
                );
                pub const TranscriptAir = universal_typed_component.ComponentForManifest(
                    transcript_component,
                    TranscriptAirRelation,
                    manifest_contract,
                );
                pub const TranscriptBinding = universal_typed_component.ComponentForManifest(
                    transcript_binding_air,
                    TranscriptBindingRelation,
                    manifest_contract,
                );
                pub const TranscriptState = universal_typed_component.ComponentForManifest(
                    transcript_state_air,
                    TranscriptStateRelation,
                    manifest_contract,
                );
                pub const TranscriptWord = universal_typed_component.ComponentForManifest(
                    transcript_word_air,
                    TranscriptWordRelation,
                    manifest_contract,
                );
                pub const TranscriptPayload = universal_typed_component.ComponentForManifest(
                    transcript_payload,
                    TranscriptPayloadRelation,
                    manifest_contract,
                );
                pub const PowCheck = universal_typed_component.ComponentForManifest(
                    pow_check_air,
                    PowCheckRelation,
                    manifest_contract,
                );
                pub const PowFrame = universal_typed_component.ComponentForManifest(
                    pow_frame_air,
                    PowFrameRelation,
                    manifest_contract,
                );
                pub const PackedRelationChallenge = universal_typed_component.ComponentForManifest(
                    packed_relation_challenge_v2,
                    PackedRelationChallengeRelation,
                    manifest_contract,
                );
                pub const VerifierRandomness = universal_typed_component.ComponentForManifest(
                    verifier_randomness_air,
                    VerifierRandomnessRelation,
                    manifest_contract,
                );
                pub const StatementInput = universal_typed_component.ComponentForManifest(
                    statement_input_air,
                    universal_binding.Binding(statement_input_air),
                    manifest_contract,
                );
                pub const StatementSemantics = universal_typed_component.ComponentForManifest(
                    statement_semantics_air,
                    universal_binding.Binding(statement_semantics_air),
                    manifest_contract,
                );
                pub const VmClaimInput = universal_typed_component.ComponentForManifest(
                    vm_claim_input_air,
                    universal_binding.Binding(vm_claim_input_air),
                    manifest_contract,
                );
                pub const VmClaimHash = universal_typed_component.ComponentForManifest(
                    vm_claim_hash_air,
                    universal_binding.Binding(vm_claim_hash_air),
                    manifest_contract,
                );
                pub const VmIoHash = universal_typed_component.ComponentForManifest(
                    vm_io_hash_air,
                    universal_binding.Binding(vm_io_hash_air),
                    manifest_contract,
                );
                pub const VmClaimSemantics = universal_typed_component.ComponentForManifest(
                    vm_claim_semantics_air,
                    universal_binding.Binding(vm_claim_semantics_air),
                    manifest_contract,
                );
                pub const VmPublicLogup = universal_typed_component.ComponentForManifest(
                    vm_public_logup_air,
                    universal_binding.Binding(vm_public_logup_air),
                    manifest_contract,
                );
                pub const VmPublicLogupControl = universal_typed_component.ComponentForManifest(
                    vm_public_logup_control_air,
                    universal_binding.Binding(vm_public_logup_control_air),
                    manifest_contract,
                );
            };
        }

        /// Stable-address component cohort for the temporal prefix. It is deliberately
        /// incapable of sealing a complete gate: rows 18--35 must be appended by their
        /// separately authenticated suffix owner before `ProofGate.sealGate` succeeds.
        pub fn TemporalPrefixComponentsForManifest(comptime manifest_contract: type) type {
            const Adapters = TemporalPrefixAdaptersForManifest(manifest_contract);
            return struct {
                control: Adapters.Control,
                transcript_air: Adapters.TranscriptAir,
                transcript_binding: Adapters.TranscriptBinding,
                transcript_state: Adapters.TranscriptState,
                transcript_word: Adapters.TranscriptWord,
                transcript_payload: Adapters.TranscriptPayload,
                pow_check: Adapters.PowCheck,
                pow_frame: Adapters.PowFrame,
                packed_relation_challenge: Adapters.PackedRelationChallenge,
                verifier_randomness: Adapters.VerifierRandomness,
                statement_input: Adapters.StatementInput,
                statement_semantics: Adapters.StatementSemantics,
                vm_claim_input: Adapters.VmClaimInput,
                vm_claim_hash: Adapters.VmClaimHash,
                vm_io_hash: Adapters.VmIoHash,
                vm_claim_semantics: Adapters.VmClaimSemantics,
                vm_public_logup: Adapters.VmPublicLogup,
                vm_public_logup_control: Adapters.VmPublicLogupControl,

                pub fn appendToGate(
                    self: *const @This(),
                    manifest: *const manifest_contract.Manifest,
                    gate: *manifest_contract.ProofGate,
                ) !void {
                    inline for (.{
                        "control",
                        "transcript_air",
                        "transcript_binding",
                        "transcript_state",
                        "transcript_word",
                        "transcript_payload",
                        "pow_check",
                        "pow_frame",
                        "packed_relation_challenge",
                        "verifier_randomness",
                        "statement_input",
                        "statement_semantics",
                        "vm_claim_input",
                        "vm_claim_hash",
                        "vm_io_hash",
                        "vm_claim_semantics",
                        "vm_public_logup",
                        "vm_public_logup_control",
                    }) |field| try gate.append(
                        manifest,
                        try @field(self, field).binding(manifest),
                    );
                }
            };
        }

        pub const Digest = channel.Digest;
        pub const PairAuthority =
            pair_authority.PreparedTemporalPairAuthorityV1;

        /// Single production seam for the immutable prepared pair capability consumed
        /// by temporal rows 0--17. Keeping every source constructor on this function
        /// makes the zero-hash hot path executable evidence rather than a detached
        /// helper that production might accidentally bypass.
        pub fn authenticatePreparedPairForSource(
            pair: *const PairAuthority,
        ) pair_authority.Error!temporal.RootAuthenticatedTemporalPairV2 {
            return pair.authenticatePrepared();
        }

        pub const FORMAT_VERSION: u16 = 2;
        pub const SCHEMA_VERSION: u16 = 1;
        pub const PUBLIC_ID_DOMAIN: u32 = 0x544e_5055; // "TNPU"
        pub const STATEMENT_SOURCE_ID_DOMAIN: u32 = 0x544e_5354; // "TNST"
        pub const ROW_AUTHORITY_ID_DOMAIN: u32 = 0x544e_5241; // "TNRA"

        pub const FIRST_TRANSCRIPT_ROW: usize = 0;
        pub const LAST_TRANSCRIPT_ROW: usize = 9;
        pub const FIRST_IMPLEMENTED_ROW: usize = 10;
        pub const LAST_IMPLEMENTED_ROW: usize = 17;
        pub const IMPLEMENTED_ROW_COUNT: usize =
            LAST_IMPLEMENTED_ROW - FIRST_IMPLEMENTED_ROW + 1;
        pub const TRANSCRIPT_ROW_COUNT: usize =
            LAST_TRANSCRIPT_ROW - FIRST_TRANSCRIPT_ROW + 1;
        pub const IMPLEMENTED_ROW_MASK: u64 =
            rangeMask(FIRST_IMPLEMENTED_ROW, IMPLEMENTED_ROW_COUNT);
        pub const TRANSCRIPT_ROW_MASK: u64 =
            rangeMask(FIRST_TRANSCRIPT_ROW, TRANSCRIPT_ROW_COUNT);

        /// Active binary-mode relation domains, indexed by rows 10--17.  Rows 12--16
        /// retain their typed AIR but every event weight is canonically zero.
        pub const IMPLEMENTED_ACTIVE_DOMAIN_MASKS = [IMPLEMENTED_ROW_COUNT]u64{
            domainBit(25) | domainBit(29), // verifier input, statement word
            domainBit(10) | domainBit(13) | domainBit(29), // range, wire, statement
            0,
            0,
            0,
            0,
            0,
            domainBit(14), // recursion step
        };

        pub const HEAP_ALLOCATIONS_PER_ROW_AUTHORITY: usize = 0;
        pub const CALLER_AUTHORED_CLAIMS_ACCEPTED = false;
        pub const FROZEN_SPLIT_ROLE_ADAPTER_USED = false;
        pub const ROWS_10_THROUGH_17_AVAILABLE = true;
        pub const ROWS_0_THROUGH_9_AVAILABLE = true;
        pub const ROWS_0_THROUGH_9_EXACT_REPLAY_AVAILABLE = true;
        pub const ROWS_0_THROUGH_9_TYPED_AIR_AVAILABLE = true;
        pub const ROWS_0_THROUGH_9_EXTENDED_MANIFEST_AVAILABLE = true;
        pub const ROWS_0_THROUGH_17_COMMITMENT_LAYOUT_AVAILABLE = true;
        pub const ROWS_0_THROUGH_17_RELATION_DOMAIN_CUSTODY_AVAILABLE = true;
        pub const ROWS_0_THROUGH_17_TREE_WRITER_AVAILABLE = false;
        pub const TRANSCRIPT_ROW_1_TYPED_AIR_AVAILABLE = true;
        pub const TRANSCRIPT_POSEIDON_PROVIDER_AVAILABLE = true;
        pub const TRANSCRIPT_ROWS_0_THROUGH_3_TYPED_AIR_AVAILABLE = true;
        pub const TRANSCRIPT_ROWS_0_THROUGH_4_TYPED_AIR_AVAILABLE = true;
        pub const TRANSCRIPT_ROWS_0_THROUGH_7_TYPED_AIR_AVAILABLE = true;
        pub const TRANSCRIPT_ROWS_6_7_9_TYPED_AIR_AVAILABLE = true;
        pub const TRANSCRIPT_ROW_8_PACKED_V2_TYPED_AIR_AVAILABLE = true;
        pub const TYPED_TRANSCRIPT_ROW_MASK: u64 = TRANSCRIPT_ROW_MASK;

        pub const CHILD_QUERY_COUNT: usize = outer_admission.QUERY_COUNT;
        pub const MAX_CHILD_FRI_ROUNDS: usize = outer_admission.MAX_FRI_ROUNDS;
        pub const CHILD_COMMITMENT_COUNT: usize = outer_admission.TREE_COUNT;
        pub const CHILD_RELATION_DRAW_COUNT: usize =
            segment_artifact.RELATION_DRAW_COUNT;
        pub const CHILD_PACKED_RELATION_DRAW_COUNT: usize =
            CHILD_RELATION_DRAW_COUNT /
            packed_relation_challenge_v2.CHALLENGES_PER_DRAW;

        pub const COHORT_AUTHORITY_TRANSCRIPT_DOMAIN: u32 = 0x5343_5632; // "SCV2"
        pub const COHORT_FORMAT_VERSION: u32 = 1;
        pub const CORE_FIRST_ROW: u32 = 18;
        pub const CORE_LAST_ROW: u32 = 34;
        pub const NONCORE_AUTHORITY_TRANSCRIPT_DOMAIN: u32 = 0x4e43_5632; // "NCV2"
        pub const NONCORE_FORMAT_VERSION: u32 = 1;
        pub const NONCORE_ROW_COUNT: u32 = 22;
        pub const CORE_AUTHORITY_TRANSCRIPT_DOMAIN: u32 = 0x4e43_5632; // "NCV2"
        pub const CORE_FORMAT_VERSION: u32 = 1;
        pub const CORE_PROVIDER_INSTANCE_COUNT: u32 = 1;
        pub const PUBLIC_WIRE_BOUNDARY_TRANSCRIPT_DOMAIN: u32 = 0x5742_5632; // "WBV2"
        pub const TRANSCRIPT_REPLAY_ID_DOMAIN: u32 = 0x5452_5632; // "TRV2"
        pub const TRANSCRIPT_ROWS_FORMAT_VERSION: u16 = 2;
        /// Schema 2 authenticates the per-lane interaction-claim count so the
        /// same typed transcript rows admit both 39-claim SegmentV2 children
        /// and 36-claim universal temporal parents without misclassifying the
        /// following public wire, samples, or last-layer coefficients.
        pub const TRANSCRIPT_ROWS_SCHEMA_VERSION: u16 = 2;
        /// Append-only custody for two canonical proofless height-zero empty
        /// children.  The rows remain the same typed binary-parent transcript
        /// AIR; only the admitted replay has no PCS/FRI/query continuation.
        pub const PROOFLESS_EMPTY_CHILD_REPLAY_SCHEMA_VERSION: u16 = 2;
        pub const PROOFLESS_EMPTY_TRANSCRIPT_ROWS_SCHEMA_VERSION: u16 = 3;

        pub fn validTranscriptRowsSchema(schema: u16) bool {
            return schema == TRANSCRIPT_ROWS_SCHEMA_VERSION or
                schema == PROOFLESS_EMPTY_TRANSCRIPT_ROWS_SCHEMA_VERSION;
        }
        pub const TRANSCRIPT_ROWS_AUTHORITY_DOMAIN =
            "stwo-zig/typed-air/recursive-temporal-transcript-rows/v2\x00";
        pub const TRANSCRIPT_MANIFEST_FORMAT_VERSION: u16 = 2;
        pub const TRANSCRIPT_MANIFEST_SCHEMA_VERSION: u16 = 1;
        pub const TRANSCRIPT_MANIFEST_AUTHORITY_DOMAIN =
            "stwo-zig/typed-air/recursive-temporal-transcript-manifest/v2\x00";
        pub const PREFIX_CUSTODY_FORMAT_VERSION: u16 = 3;
        pub const PREFIX_CUSTODY_SCHEMA_VERSION: u16 = 1;
        pub const PREFIX_ROW_COUNT: usize = LAST_IMPLEMENTED_ROW + 1;
        pub const PREFIX_ROW_MASK: u64 = rangeMask(0, PREFIX_ROW_COUNT);
        pub const PREFIX_TYPED_ROW_MASK: u64 = PREFIX_ROW_MASK;
        pub const PREFIX_CUSTODY_ID_DOMAIN: u32 = 0x5450_4333; // "TPC3"
        pub const PREFIX_LAYOUT_AUTHORITY_DOMAIN =
            "stwo-zig/typed-air/recursive-temporal-prefix-layout/v3\x00";
        pub const RELATION_DOMAIN_CUSTODY_DOMAIN =
            "stwo-zig/typed-air/recursive-temporal-relation-domains/v3\x00";
        pub const RELATION_DOMAIN_COUNT: usize =
            recursion.air.universal_challenges.RELATION_COUNT;
        pub const EXACT_PREFIX_RELATION_DOMAIN_MASK: u64 =
            relation_interaction.allDomainMask();
        pub const TEMPORAL_PAYLOAD_FORMAT_VERSION: u16 = 2;
        pub const TEMPORAL_PAYLOAD_SCHEMA_VERSION: u16 = 1;
        pub const TEMPORAL_PAYLOAD_SOURCE_KIND_COUNT: u8 = 13;
        pub const TEMPORAL_PAYLOAD_PUBLIC_GEOMETRY_KIND: u8 = 13;
        pub const TEMPORAL_PAYLOAD_RELATION_DOMAIN_MASK: u64 =
            (@as(u64, 1) << 24) | (@as(u64, 1) << 25);
        pub const TEMPORAL_PAYLOAD_AUTHORITY_DOMAIN =
            "stwo-zig/typed-air/recursive-temporal-payload-authority/v2\x00";
        pub const PREFIX_TREE_WRITER_FORMAT_VERSION: u16 = 3;
        pub const PREFIX_TREE_WRITER_SCHEMA_VERSION: u16 = 1;
        pub const PREFIX_INTERACTIONS_SCHEMA_VERSION: u16 = 2;
        pub const PREFIX_DOMAIN_AUDITS_SCHEMA_VERSION: u16 = 1;
        pub const PREFIX_TREE_WRITER_AUTHORITY_DOMAIN =
            "stwo-zig/typed-air/recursive-temporal-prefix-tree-writer/v3\x00";
        pub const PREFIX_DOMAIN_AUDITS_AUTHORITY_DOMAIN =
            "stwo-zig/typed-air/recursive-temporal-prefix-domain-audits/v3\x00";
        pub const PREFIX_TREE_COUNT: usize = 3;
        pub const PREFIX_TREE0_INDEX: usize = 0;
        pub const PREFIX_TREE1_INDEX: usize = 1;
        pub const PREFIX_TREE2_INDEX: usize = 2;
        pub const PREFIX_TREE_WRITER_HOT_HEAP_ALLOCATIONS: usize = 0;

        pub const TranscriptAirRow = transcript_air.Row;
        pub const TranscriptProviderCall = transcript_air.ProviderCall;
        pub const TranscriptControlRow = transcript_control.Row;
        pub const TranscriptBindingRowV2 = struct {
            preprocessing: transcript_binding.PreprocessedRow,
            main: transcript_binding.MainRow,
        };
        pub const TranscriptStateRowV2 = struct {
            preprocessing: transcript_state.PreprocessedRow,
            main: transcript_state.MainRow,
        };
        pub const TranscriptWordRowV2 = struct {
            preprocessing: transcript_word.Row,
            value: M31,
        };
        pub const TemporalTranscriptPayloadRowV2 =
            segment_transcript_v2.TranscriptPayloadRowV2;
        pub const TemporalPayloadSourceKindV2 =
            segment_transcript_v2.PayloadSourceKindV2;
        /// The V3 composition ABI reserves claimed-sum items 39 and 40 for the two
        /// Poseidon partials. The transcript-authenticated public-wire boundary is a
        /// distinct secure input at item 41.
        pub const PUBLIC_WIRE_BOUNDARY_CLAIMED_SUM_ITEM_INDEX: u32 =
            manifest_mod.COMPONENT_COUNT + 2;
        pub const TemporalPowCheckRowV2 = struct {
            enabler: u32 = 1,
            verifier_id: u32,
            pow_kind: pow_check_air.PowKind = .pcs,
            call_id: u32,
            bits: u32,
            word: M31,
            word_bits: [31]u32,
            active_bits: [31]u32,
        };
        pub const TemporalPowFrameRowV2 = struct {
            enabler: u32 = 1,
            verifier_id: u32,
            sequence: u32,
            pow_kind: pow_check_air.PowKind = .pcs,
            hash_id: u32,
            call_id: u32,
            bits: u32,
            words: [channel.RATE]M31,
        };
        pub const TemporalVerifierRandomnessRowV2 = struct {
            preprocessing: verifier_randomness.PreprocessedRow,
            main: verifier_randomness.MainRow,
        };
        pub const TemporalPackedRelationChallengeRowV2 =
            packed_relation_challenge_v2.Row;

        pub const ControlRelation = universal_binding.Binding(control_air);
        pub const TranscriptAirRelation = universal_binding.Binding(transcript_component);
        pub const TranscriptBindingRelation = universal_binding.Binding(
            transcript_binding_air,
        );
        pub const TranscriptStateRelation = universal_binding.Binding(transcript_state_air);
        pub const TranscriptWordRelation = universal_binding.Binding(transcript_word_air);
        pub const TranscriptPayloadRelation = universal_binding.Binding(transcript_payload);
        pub const PowCheckRelation = universal_binding.Binding(pow_check_air);
        pub const PowFrameRelation = universal_binding.Binding(pow_frame_air);
        pub const PackedRelationChallengeRelation = universal_binding.Binding(
            packed_relation_challenge_v2,
        );
        pub const VerifierRandomnessRelation = universal_binding.Binding(
            verifier_randomness_air,
        );

        pub fn InteractionFramework(comptime Air: type) type {
            return framework_interaction.Runtime(universal_binding.Binding(Air).Runtime);
        }

        pub fn TemporalAirOwner(comptime Air: type) type {
            const Binding = universal_binding.Binding(Air);
            return struct {
                definition: Air.Definition,
                relation: Binding.Plan,

                pub fn init(allocator: std.mem.Allocator) !@This() {
                    var definition = try Air.build(allocator);
                    errdefer definition.deinit();
                    return .{
                        .relation = try Binding.authenticate(&definition),
                        .definition = definition,
                    };
                }

                pub fn validate(self: *const @This()) !void {
                    try self.definition.validate();
                    try self.relation.validateAgainst(
                        &self.definition.arena,
                        Air.SEMANTIC_DIGEST,
                        Binding.events(&self.definition),
                    );
                }

                pub fn deinit(self: *@This()) void {
                    self.definition.deinit();
                    self.* = undefined;
                }
            };
        }
    };
}
