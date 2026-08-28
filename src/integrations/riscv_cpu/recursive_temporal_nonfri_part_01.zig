//! Cohesive internal authority extracted from recursive_temporal_nonfri_source_v2.zig.

pub fn Namespace(comptime context: type) type {
    return struct {
        const std = context.d_std;
        const QM31 = context.d_QM31;
        const recursion = context.d_recursion;
        const cohort_protocol = context.d_cohort_protocol;
        const manifest_mod = context.d_manifest_mod;
        const outer_admission = context.d_outer_admission;
        const range_owner = context.d_range_owner;
        const schedule = context.d_schedule;
        const transcript_shape = context.d_transcript_shape;
        const fri_verifier_circuit = context.d_fri_verifier_circuit;
        const statement_air = context.d_statement_air;
        const statement_source = context.d_statement_source;
        const temporal = context.d_temporal;
        const transcript_air = context.d_transcript_air;
        const transcript_binding = context.d_transcript_binding;
        const transcript_state = context.d_transcript_state;
        const transcript_word = context.d_transcript_word;
        const transcript_payload = context.d_transcript_payload;
        const verifier_randomness = context.d_verifier_randomness;
        const relation_interaction = context.d_relation_interaction;
        const framework_interaction = context.d_framework_interaction;
        const universal_manifest = context.d_universal_manifest;
        const pair_authority = context.d_pair_authority;
        const segment_artifact = context.d_segment_artifact;
        const segment_publication = context.d_segment_publication;
        const packed_relation_challenge_v2 = context.d_packed_relation_challenge_v2;
        const statement_input_witness = context.d_statement_input_witness;
        const statement_semantics_witness = context.d_statement_semantics_witness;
        const Digest = context.d_Digest;
        const FORMAT_VERSION = context.d_FORMAT_VERSION;
        const TRANSCRIPT_ROW_COUNT = context.d_TRANSCRIPT_ROW_COUNT;
        const TRANSCRIPT_ROW_MASK = context.d_TRANSCRIPT_ROW_MASK;
        const ROWS_0_THROUGH_9_EXACT_REPLAY_AVAILABLE = context.d_ROWS_0_THROUGH_9_EXACT_REPLAY_AVAILABLE;
        const ROWS_0_THROUGH_9_TYPED_AIR_AVAILABLE = context.d_ROWS_0_THROUGH_9_TYPED_AIR_AVAILABLE;
        const ROWS_0_THROUGH_9_EXTENDED_MANIFEST_AVAILABLE = context.d_ROWS_0_THROUGH_9_EXTENDED_MANIFEST_AVAILABLE;
        const ROWS_0_THROUGH_17_RELATION_DOMAIN_CUSTODY_AVAILABLE = context.d_ROWS_0_THROUGH_17_RELATION_DOMAIN_CUSTODY_AVAILABLE;
        const ROWS_0_THROUGH_17_TREE_WRITER_AVAILABLE = context.d_ROWS_0_THROUGH_17_TREE_WRITER_AVAILABLE;
        const TYPED_TRANSCRIPT_ROW_MASK = context.d_TYPED_TRANSCRIPT_ROW_MASK;
        const CHILD_PACKED_RELATION_DRAW_COUNT = context.d_CHILD_PACKED_RELATION_DRAW_COUNT;
        const TRANSCRIPT_MANIFEST_FORMAT_VERSION = context.d_TRANSCRIPT_MANIFEST_FORMAT_VERSION;
        const TRANSCRIPT_MANIFEST_SCHEMA_VERSION = context.d_TRANSCRIPT_MANIFEST_SCHEMA_VERSION;
        const PREFIX_CUSTODY_FORMAT_VERSION = context.d_PREFIX_CUSTODY_FORMAT_VERSION;
        const PREFIX_CUSTODY_SCHEMA_VERSION = context.d_PREFIX_CUSTODY_SCHEMA_VERSION;
        const PREFIX_ROW_COUNT = context.d_PREFIX_ROW_COUNT;
        const PREFIX_ROW_MASK = context.d_PREFIX_ROW_MASK;
        const PREFIX_TYPED_ROW_MASK = context.d_PREFIX_TYPED_ROW_MASK;
        const RELATION_DOMAIN_COUNT = context.d_RELATION_DOMAIN_COUNT;
        const EXACT_PREFIX_RELATION_DOMAIN_MASK = context.d_EXACT_PREFIX_RELATION_DOMAIN_MASK;
        const TEMPORAL_PAYLOAD_FORMAT_VERSION = context.d_TEMPORAL_PAYLOAD_FORMAT_VERSION;
        const TEMPORAL_PAYLOAD_SCHEMA_VERSION = context.d_TEMPORAL_PAYLOAD_SCHEMA_VERSION;
        const TEMPORAL_PAYLOAD_SOURCE_KIND_COUNT = context.d_TEMPORAL_PAYLOAD_SOURCE_KIND_COUNT;
        const TEMPORAL_PAYLOAD_PUBLIC_GEOMETRY_KIND = context.d_TEMPORAL_PAYLOAD_PUBLIC_GEOMETRY_KIND;
        const TEMPORAL_PAYLOAD_RELATION_DOMAIN_MASK = context.d_TEMPORAL_PAYLOAD_RELATION_DOMAIN_MASK;
        const validateCaptureTranscriptShape = context.d_validateCaptureTranscriptShape;
        const temporalPrefixGeometry = context.d_temporalPrefixGeometry;
        const relationRegistryShaId = context.d_relationRegistryShaId;
        const temporalPayloadAuthoritySha = context.d_temporalPayloadAuthoritySha;
        const prefixLayoutSha = context.d_prefixLayoutSha;
        const transcriptManifestSha = context.d_transcriptManifestSha;
        const rowIndex = context.d_rowIndex;
        const requireDigest = context.d_requireDigest;
        const requireSha = context.d_requireSha;
        const allZero = context.d_allZero;

        pub const TemporalTranscriptRowV2 = enum(u8) {
            control = 0,
            transcript_air = 1,
            transcript_binding = 2,
            transcript_state = 3,
            transcript_word = 4,
            transcript_payload = 5,
            pow_check = 6,
            pow_frame = 7,
            packed_relation_challenge = 8,
            verifier_randomness = 9,
        };

        /// Exact dynamic geometry for the versioned temporal 0--9 source.  Its
        /// identity binds ordered logical counts, minimal log sizes, the packed-row
        /// semantic identity, and the full one-pass recorder custody seal.
        pub const TemporalTranscriptManifestV2 = struct {
            format_version: u16 = TRANSCRIPT_MANIFEST_FORMAT_VERSION,
            schema_version: u16 = TRANSCRIPT_MANIFEST_SCHEMA_VERSION,
            frozen_v1_compatible: bool = false,
            row_count: u8 = TRANSCRIPT_ROW_COUNT,
            row_mask: u64 = TRANSCRIPT_ROW_MASK,
            typed_row_mask: u64 = TYPED_TRANSCRIPT_ROW_MASK,
            packed_row_format_version: u32 =
                packed_relation_challenge_v2.PACKING_FORMAT_VERSION,
            challenges_per_draw: u8 =
                packed_relation_challenge_v2.CHALLENGES_PER_DRAW,
            limbs_per_challenge: u8 =
                packed_relation_challenge_v2.LIMBS_PER_CHALLENGE,
            logical_rows: [TRANSCRIPT_ROW_COUNT]u32,
            log_sizes: [TRANSCRIPT_ROW_COUNT]u8,
            pair_authority_id: Digest,
            transcript_rows_authority_sha_id: [32]u8,
            packed_row_semantic_digest: [32]u8 =
                packed_relation_challenge_v2.SEMANTIC_DIGEST,
            identity: [32]u8,

            pub fn validate(self: *const TemporalTranscriptManifestV2) Error!void {
                if (self.format_version != TRANSCRIPT_MANIFEST_FORMAT_VERSION or
                    self.schema_version != TRANSCRIPT_MANIFEST_SCHEMA_VERSION or
                    self.frozen_v1_compatible or self.row_count != TRANSCRIPT_ROW_COUNT or
                    self.row_mask != TRANSCRIPT_ROW_MASK or
                    self.typed_row_mask != TYPED_TRANSCRIPT_ROW_MASK or
                    self.packed_row_format_version !=
                        packed_relation_challenge_v2.PACKING_FORMAT_VERSION or
                    self.challenges_per_draw !=
                        packed_relation_challenge_v2.CHALLENGES_PER_DRAW or
                    self.limbs_per_challenge !=
                        packed_relation_challenge_v2.LIMBS_PER_CHALLENGE or
                    !std.mem.eql(
                        u8,
                        &self.packed_row_semantic_digest,
                        &packed_relation_challenge_v2.SEMANTIC_DIGEST,
                    ))
                {
                    return error.InvalidTranscriptManifest;
                }
                for (self.logical_rows, self.log_sizes) |count, log_size| {
                    if (count == 0 or log_size < transcript_air.MIN_LOG_SIZE or
                        log_size > transcript_air.MAX_LOG_SIZE or
                        (@as(u64, 1) << @intCast(log_size)) < count or
                        (log_size > transcript_air.MIN_LOG_SIZE and
                            (@as(u64, 1) << @intCast(log_size - 1)) >= count))
                    {
                        return error.InvalidTranscriptManifest;
                    }
                }
                if (self.logical_rows[rowIndex(.transcript_air)] !=
                    self.logical_rows[rowIndex(.transcript_binding)] or
                    self.logical_rows[rowIndex(.pow_check)] !=
                        self.logical_rows[rowIndex(.pow_frame)] or
                    self.logical_rows[rowIndex(.packed_relation_challenge)] !=
                        temporal.CHILD_COUNT * CHILD_PACKED_RELATION_DRAW_COUNT)
                {
                    return error.InvalidTranscriptManifest;
                }
                try requireDigest(self.pair_authority_id);
                try requireSha(self.transcript_rows_authority_sha_id);
                if (!std.mem.eql(u8, &self.identity, &transcriptManifestSha(self)))
                    return error.InvalidTranscriptManifest;
            }
        };

        /// Host-ABI authority for temporal row 5.
        ///
        /// The shared typed AIR deliberately models `source_kind` as a field element;
        /// its frozen witness facade narrows that field to the original twelve-value
        /// enum. Temporal proof replay additionally absorbs verifier-owned public
        /// geometry under kind 13. This authority versions that host ABI without
        /// changing or relabelling the authenticated polynomial program. A frozen
        /// witness row therefore cannot be cast into the temporal source, and the V3
        /// commitment layout binds the exact semantic program, relation registry and
        /// two relation domains beside the extended source-kind grammar.
        pub const TemporalPayloadAuthorityV2 = struct {
            format_version: u16 = TEMPORAL_PAYLOAD_FORMAT_VERSION,
            schema_version: u16 = TEMPORAL_PAYLOAD_SCHEMA_VERSION,
            frozen_witness_compatible: bool = false,
            source_kind_count: u8 = TEMPORAL_PAYLOAD_SOURCE_KIND_COUNT,
            public_geometry_source_kind: u8 = TEMPORAL_PAYLOAD_PUBLIC_GEOMETRY_KIND,
            relation_event_count: u8 = transcript_payload.RELATION_EVENT_COUNT,
            padding: [2]u8 = .{ 0, 0 },
            relation_domain_mask: u64 = TEMPORAL_PAYLOAD_RELATION_DOMAIN_MASK,
            typed_air_semantic_digest: [32]u8 = transcript_payload.SEMANTIC_DIGEST,
            relation_registry_sha_id: [32]u8,
            identity: [32]u8,

            pub fn pinned() TemporalPayloadAuthorityV2 {
                var result = TemporalPayloadAuthorityV2{
                    .relation_registry_sha_id = relationRegistryShaId(),
                    .identity = undefined,
                };
                result.identity = temporalPayloadAuthoritySha(&result);
                return result;
            }

            pub fn validate(self: *const TemporalPayloadAuthorityV2) Error!void {
                const expected_registry = relationRegistryShaId();
                if (self.format_version != TEMPORAL_PAYLOAD_FORMAT_VERSION or
                    self.schema_version != TEMPORAL_PAYLOAD_SCHEMA_VERSION or
                    self.frozen_witness_compatible or
                    self.source_kind_count != TEMPORAL_PAYLOAD_SOURCE_KIND_COUNT or
                    self.public_geometry_source_kind !=
                        TEMPORAL_PAYLOAD_PUBLIC_GEOMETRY_KIND or
                    self.relation_event_count != transcript_payload.RELATION_EVENT_COUNT or
                    !allZero(&self.padding) or
                    self.relation_domain_mask != TEMPORAL_PAYLOAD_RELATION_DOMAIN_MASK or
                    !std.mem.eql(
                        u8,
                        &self.typed_air_semantic_digest,
                        &transcript_payload.SEMANTIC_DIGEST,
                    ) or !std.mem.eql(
                    u8,
                    &self.relation_registry_sha_id,
                    &expected_registry,
                ) or !std.mem.eql(
                    u8,
                    &self.identity,
                    &temporalPayloadAuthoritySha(self),
                )) {
                    return error.InvalidTemporalPayloadAuthority;
                }
            }
        };

        /// Ordered commitment geometry for temporal-parent rows 0--17.
        ///
        /// This is deliberately a new protocol version.  Rows 0--7 and 9 retain
        /// their universal typed AIRs, while row 8 is derived from the disjoint
        /// packed-QM31 V2 AIR.  The layout therefore cannot be admitted by relabelling
        /// the frozen universal manifest.  Rows 10--17 retain their typed AIR
        /// identities and exact binary-node geometry.
        pub const TemporalPrefixCommitmentLayoutV3 = struct {
            format_version: u16 = PREFIX_CUSTODY_FORMAT_VERSION,
            schema_version: u16 = PREFIX_CUSTODY_SCHEMA_VERSION,
            row_count: u8 = PREFIX_ROW_COUNT,
            relation_domain_count: u8 = RELATION_DOMAIN_COUNT,
            row_mask: u64 = PREFIX_ROW_MASK,
            typed_row_mask: u64 = PREFIX_TYPED_ROW_MASK,
            relation_domain_mask: u64 = EXACT_PREFIX_RELATION_DOMAIN_MASK,
            relation_registry_sha_id: [32]u8,
            temporal_payload_authority_sha_id: [32]u8,
            pair_authority_id: Digest,
            parent_public_id: Digest,
            transcript_manifest_sha_id: [32]u8,
            rows_10_through_17_authority_id: Digest,
            child_publication_ids: [temporal.CHILD_COUNT]Digest,
            child_replay_ids: [temporal.CHILD_COUNT]Digest,
            child_relation_domain_sha_ids: [temporal.CHILD_COUNT][32]u8,
            placements: [PREFIX_ROW_COUNT]universal_manifest.Placement,
            total_preprocessed_columns: u32,
            total_main_columns: u32,
            total_interaction_columns: u32,
            total_constraints: u32,
            layout_sha_id: [32]u8,

            pub fn validate(
                self: *const TemporalPrefixCommitmentLayoutV3,
            ) Error!void {
                const expected_registry_sha_id = relationRegistryShaId();
                const expected_payload_authority = TemporalPayloadAuthorityV2.pinned();
                if (self.format_version != PREFIX_CUSTODY_FORMAT_VERSION or
                    self.schema_version != PREFIX_CUSTODY_SCHEMA_VERSION or
                    self.row_count != PREFIX_ROW_COUNT or
                    self.relation_domain_count != RELATION_DOMAIN_COUNT or
                    self.row_mask != PREFIX_ROW_MASK or
                    self.typed_row_mask != PREFIX_TYPED_ROW_MASK or
                    self.relation_domain_mask != EXACT_PREFIX_RELATION_DOMAIN_MASK or
                    !std.mem.eql(
                        u8,
                        &self.relation_registry_sha_id,
                        &expected_registry_sha_id,
                    ) or !std.mem.eql(
                    u8,
                    &self.temporal_payload_authority_sha_id,
                    &expected_payload_authority.identity,
                )) {
                    return error.InvalidPrefixCommitmentLayout;
                }
                try requireDigest(self.pair_authority_id);
                try requireDigest(self.parent_public_id);
                try requireSha(self.transcript_manifest_sha_id);
                try requireDigest(self.rows_10_through_17_authority_id);
                for (self.child_publication_ids) |value| try requireDigest(value);
                for (self.child_replay_ids) |value| try requireDigest(value);
                for (self.child_relation_domain_sha_ids) |value|
                    try requireSha(value);
                if (std.meta.eql(
                    self.child_publication_ids[0],
                    self.child_publication_ids[1],
                ) or std.meta.eql(
                    self.child_replay_ids[0],
                    self.child_replay_ids[1],
                ) or std.mem.eql(
                    u8,
                    &self.child_relation_domain_sha_ids[0],
                    &self.child_relation_domain_sha_ids[1],
                )) return error.DuplicateChild;

                var preprocessed: u32 = 0;
                var main: u32 = 0;
                var interaction: u32 = 0;
                var constraints: u32 = 0;
                for (self.placements, 0..) |placement, row| {
                    const geometry = placement.geometry;
                    try geometry.validateForComponentCount(PREFIX_ROW_COUNT);
                    const expected = try temporalPrefixGeometry(
                        @intCast(row),
                        geometry.log_size,
                    );
                    if (!std.meta.eql(geometry, expected) or
                        geometry.roster_row != row or
                        placement.preprocessed_offset != preprocessed or
                        placement.main_offset != main or
                        placement.interaction_offset != interaction or
                        placement.constraint_offset != constraints or
                        placement.claimed_sum_index != row)
                    {
                        return error.InvalidPrefixCommitmentLayout;
                    }
                    preprocessed = std.math.add(
                        u32,
                        preprocessed,
                        geometry.preprocessed_columns,
                    ) catch return error.ArithmeticOverflow;
                    main = std.math.add(
                        u32,
                        main,
                        geometry.main_columns,
                    ) catch return error.ArithmeticOverflow;
                    interaction = std.math.add(
                        u32,
                        interaction,
                        geometry.interaction_columns,
                    ) catch return error.ArithmeticOverflow;
                    constraints = std.math.add(
                        u32,
                        constraints,
                        @as(u32, geometry.direct_constraints) +
                            geometry.interaction_batches,
                    ) catch return error.ArithmeticOverflow;
                }
                if (self.total_preprocessed_columns != preprocessed or
                    self.total_main_columns != main or
                    self.total_interaction_columns != interaction or
                    self.total_constraints != constraints or
                    !std.mem.eql(u8, &self.layout_sha_id, &prefixLayoutSha(self)))
                {
                    return error.InvalidPrefixCommitmentLayout;
                }
            }
        };

        pub const Error = pair_authority.Error || temporal.Error ||
            segment_artifact.Error || segment_publication.Error || manifest_mod.Error ||
            cohort_protocol.Error || statement_source.Error || statement_air.Error ||
            range_owner.Error || transcript_air.Error || std.mem.Allocator.Error ||
            statement_input_witness.Error || statement_semantics_witness.Error ||
            framework_interaction.Error || relation_interaction.Error ||
            error{
                ArithmeticOverflow,
                AliasedDestination,
                AuthorityIdentityMismatch,
                CaptureShapeMismatch,
                ChildTranscriptMismatch,
                DanglingPowTransaction,
                DestinationLengthMismatch,
                DestinationAlias,
                DestinationNotZero,
                InvalidPublicRecord,
                InvalidPackedRelationChallengeRow,
                InvalidPrefixCommitmentLayout,
                InvalidPrefixTreeReceipt,
                InvalidPrefixTreeWriter,
                InvalidRelationDomainCustody,
                InvalidTemporalPayloadAuthority,
                InvalidTraceShape,
                InvalidTranscriptRecorder,
                InvalidTranscriptManifest,
                NonBaseCircuitInput,
                PairSnapshotMismatch,
                ProductionCapabilityUnavailable,
                RowCountOutOfRange,
                SourceIdentityMismatch,
                UnsupportedFormat,
            };

        pub const ProductionStatus = enum(u8) {
            authenticated_adjacent_span_temporal_v2 = 2,
        };

        pub const CURRENT_STATUS: ProductionStatus =
            .authenticated_adjacent_span_temporal_v2;

        /// Exact successful-verifier sidecar, not a structurally similar local copy.
        /// SHA identities remain bytes; they are never reinterpreted as native
        /// Poseidon field digests.
        pub const TranscriptPrefixRequirementsV1 =
            segment_artifact.TranscriptPrefixV1;

        pub const CapabilitiesV2 = struct {
            format_version: u16 = FORMAT_VERSION,
            authenticated_temporal_pair: bool,
            rows_0_through_9_transcript: bool,
            rows_10_through_11_statement: bool,
            rows_12_through_16_canonical_inactive: bool,
            row_17_binary_control: bool,
            exact_rows_0_through_17_domain_custody: bool,
            rows_0_through_17_tree_writer: bool,

            pub fn ready(self: CapabilitiesV2) bool {
                return self.format_version == FORMAT_VERSION and
                    self.authenticated_temporal_pair and
                    self.rows_0_through_9_transcript and
                    self.rows_10_through_11_statement and
                    self.rows_12_through_16_canonical_inactive and
                    self.row_17_binary_control and
                    self.exact_rows_0_through_17_domain_custody and
                    self.rows_0_through_17_tree_writer;
            }

            pub fn requireProduction(self: CapabilitiesV2) Error!void {
                if (!self.ready()) return error.ProductionCapabilityUnavailable;
            }
        };

        pub const CURRENT_CAPABILITIES = CapabilitiesV2{
            .authenticated_temporal_pair = true,
            .rows_0_through_9_transcript = ROWS_0_THROUGH_9_EXACT_REPLAY_AVAILABLE and
                ROWS_0_THROUGH_9_TYPED_AIR_AVAILABLE and
                ROWS_0_THROUGH_9_EXTENDED_MANIFEST_AVAILABLE,
            .rows_10_through_11_statement = true,
            .rows_12_through_16_canonical_inactive = true,
            .row_17_binary_control = true,
            .exact_rows_0_through_17_domain_custody = ROWS_0_THROUGH_17_RELATION_DOMAIN_CUSTODY_AVAILABLE,
            .rows_0_through_17_tree_writer = ROWS_0_THROUGH_17_TREE_WRITER_AVAILABLE,
        };

        pub const SegmentPublication =
            segment_publication.VerifiedSegmentV2PublicationV1;
        pub const SegmentRecursiveWitness = segment_artifact.RecursiveWitnessV1;
        pub const OuterProofCapture = segment_artifact.OuterProofCapture;

        /// Derives the sole schedule geometry accepted for a successful outer proof.
        /// Both prefix row 0 and suffix rows 18--34 consume plans instantiated from
        /// this capture-derived shape, eliminating an inner/outer schedule split.
        pub fn outerScheduleShape(
            capture: *const OuterProofCapture,
        ) Error!schedule.ScheduleShape {
            return outerScheduleShapeForClaimCount(
                capture,
                segment_artifact.CLAIM_COUNT,
            );
        }

        /// Derives an exact verifier schedule for a recursively verified
        /// proof whose manifest owns `claimed_sum_count` physical claims.
        /// The retained leaf entry point above stays pinned to the SegmentV2
        /// count; higher recursion levels must provide their own manifest
        /// count instead of inheriting leaf geometry.
        pub fn outerScheduleShapeForClaimCount(
            capture: *const OuterProofCapture,
            claimed_sum_count: u32,
        ) Error!schedule.ScheduleShape {
            validateCaptureTranscriptShape(capture) catch |err| {
                std.debug.print(
                    "\nTEMPORAL_OUTER_SCHEDULE_FAIL stage=capture error={s}\n",
                    .{@errorName(err)},
                );
                return err;
            };
            if (claimed_sum_count == 0) return error.CaptureShapeMismatch;

            const query_count = capture.queries.raw.len;
            if (capture.queried_values.len % query_count != 0)
                return error.CaptureShapeMismatch;

            var tree_heights: [recursion.fixed_profile.TREE_COUNT]u32 = undefined;
            for (capture.trace_paths, &tree_heights) |path, *height|
                height.* = path.path_depth;

            var fold_widths_storage: [fri_verifier_circuit.MAX_FRI_LAYERS]u32 = undefined;
            const fold_widths = fold_widths_storage[0..capture.fri.layers.len];
            for (capture.fri.layers, fold_widths) |layer, *width|
                width.* = layer.fold_width;

            const lifting_log_size = std.math.add(
                u32,
                capture.fri.layers[0].path_depth,
                capture.fri.layers[0].fold_step,
            ) catch return error.ArithmeticOverflow;
            const sampled_value_count = std.math.cast(
                u32,
                capture.sampled_values.len,
            ) orelse return error.ArithmeticOverflow;
            const queried_values_per_query = std.math.cast(
                u32,
                capture.queried_values.len / query_count,
            ) orelse return error.ArithmeticOverflow;
            const query_count_u32 = std.math.cast(u32, query_count) orelse
                return error.ArithmeticOverflow;

            return transcript_shape.derive(
                .{
                    .lifting_log_size = lifting_log_size,
                    .log_blowup_factor = outer_admission.LOG_BLOWUP_FACTOR,
                    .log_last_layer_degree_bound = outer_admission.LOG_LAST_LAYER_DEGREE_BOUND,
                    .fold_widths = fold_widths,
                    .query_count = query_count_u32,
                },
                tree_heights,
                .{
                    .sampled_value_count = sampled_value_count,
                    .queried_values_per_query = queried_values_per_query,
                    .claimed_sum_count = claimed_sum_count,
                    .interaction_pow_bits = outer_admission.INTERACTION_POW_BITS,
                    .pcs_pow_bits = outer_admission.PCS_POW_BITS,
                },
            ) catch |err| {
                std.debug.print(
                    "\nTEMPORAL_OUTER_SCHEDULE_FAIL stage=derive error={s} " ++
                        "lifting={d} layers={d} claims={d} samples={d} " ++
                        "queried_per_query={d}\n",
                    .{
                        @errorName(err),
                        lifting_log_size,
                        fold_widths.len,
                        claimed_sum_count,
                        sampled_value_count,
                        queried_values_per_query,
                    },
                );
                return error.CaptureShapeMismatch;
            };
        }

        // Pointer-free result of replaying one successful SegmentV2 outer verifier.
        // The constructor accepts no checkpoint, relation draw, claim, or challenge:
        // all such values are consumed from the exact publication/witness/capture
        // triple admitted by `segment_artifact.preflight`.
    };
}
