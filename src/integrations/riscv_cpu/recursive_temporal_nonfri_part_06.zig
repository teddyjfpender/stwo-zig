//! Cohesive internal authority extracted from recursive_temporal_nonfri_source_v2.zig.

pub fn Namespace(comptime context: type) type {
    return struct {
        const std = context.d_std;
        const M31 = context.d_M31;
        const inactive = context.d_inactive;
        const leaf_authority = context.d_leaf_authority;
        const range_owner = context.d_range_owner;
        const schedule = context.d_schedule;
        const segment_public = context.d_segment_public;
        const statement_air = context.d_statement_air;
        const statement_source = context.d_statement_source;
        const statement_circuit = context.d_statement_circuit;
        const span_statement = context.d_span_statement;
        const temporal = context.d_temporal;
        const transcript_air = context.d_transcript_air;
        const segment_artifact = context.d_segment_artifact;
        const Digest = context.d_Digest;
        const PairAuthority = context.d_PairAuthority;
        const authenticatePreparedPairForSource = context.d_authenticatePreparedPairForSource;
        const FORMAT_VERSION = context.d_FORMAT_VERSION;
        const SCHEMA_VERSION = context.d_SCHEMA_VERSION;
        const IMPLEMENTED_ROW_COUNT = context.d_IMPLEMENTED_ROW_COUNT;
        const IMPLEMENTED_ROW_MASK = context.d_IMPLEMENTED_ROW_MASK;
        const IMPLEMENTED_ACTIVE_DOMAIN_MASKS = context.d_IMPLEMENTED_ACTIVE_DOMAIN_MASKS;
        const TranscriptProviderCall = context.d_TranscriptProviderCall;
        const TranscriptControlRow = context.d_TranscriptControlRow;
        const TranscriptBindingRowV2 = context.d_TranscriptBindingRowV2;
        const TranscriptStateRowV2 = context.d_TranscriptStateRowV2;
        const TranscriptWordRowV2 = context.d_TranscriptWordRowV2;
        const TemporalTranscriptPayloadRowV2 = context.d_TemporalTranscriptPayloadRowV2;
        const TemporalPowCheckRowV2 = context.d_TemporalPowCheckRowV2;
        const TemporalPowFrameRowV2 = context.d_TemporalPowFrameRowV2;
        const TemporalVerifierRandomnessRowV2 = context.d_TemporalVerifierRandomnessRowV2;
        const TemporalPackedRelationChallengeRowV2 = context.d_TemporalPackedRelationChallengeRowV2;
        const Error = context.d_Error;
        const ProductionStatus = context.d_ProductionStatus;
        const CURRENT_STATUS = context.d_CURRENT_STATUS;
        const TemporalChildTranscriptReplayV2 = context.d_TemporalChildTranscriptReplayV2;
        const deriveReplayAfterPreflight = context.d_deriveReplayAfterPreflight;
        const TranscriptRowRecorderV2 = context.d_TranscriptRowRecorderV2;
        const TemporalChildArtifactV2 = context.d_TemporalChildArtifactV2;
        const PreparedTranscriptRowsV2 = context.d_PreparedTranscriptRowsV2;
        const validateCaptureTranscriptShape = context.d_validateCaptureTranscriptShape;
        const publicFromPair = context.d_publicFromPair;
        const publicIdentity = context.d_publicIdentity;
        const statementSourceIdentity = context.d_statementSourceIdentity;
        const rowAuthorityIdentity = context.d_rowAuthorityIdentity;
        const transcriptTraceLogSize = context.d_transcriptTraceLogSize;
        const transcriptWordCount = context.d_transcriptWordCount;
        const transcriptPayloadCount = context.d_transcriptPayloadCount;
        const validateTranscriptRowsV2 = context.d_validateTranscriptRowsV2;
        const transcriptRowsAuthoritySha = context.d_transcriptRowsAuthoritySha;
        const statementId = context.d_statementId;
        const baseInputs = context.d_baseInputs;
        const rejectWorkspaceAliases = context.d_rejectWorkspaceAliases;
        const m31SlicesEql = context.d_m31SlicesEql;
        const secureSlicesEql = context.d_secureSlicesEql;
        const requireDigest = context.d_requireDigest;
        const requireSha = context.d_requireSha;
        const allZero = context.d_allZero;

        pub fn initPreparedTranscriptRowsV2(
            allocator: std.mem.Allocator,
            pair: *const PairAuthority,
            left: TemporalChildArtifactV2,
            right: TemporalChildArtifactV2,
        ) Error!PreparedTranscriptRowsV2 {
            try pair.validate();
            const artifacts = [_]TemporalChildArtifactV2{ left, right };
            var recorder = TranscriptRowRecorderV2.init(
                allocator,
                transcript_air.LEFT_RECURSION_VERIFIER_ID,
            );
            defer recorder.deinit();

            var lane_row_counts: [temporal.CHILD_COUNT]usize = undefined;
            var lane_operation_counts: [temporal.CHILD_COUNT]usize = undefined;
            var lane_frame_counts: [temporal.CHILD_COUNT]usize = undefined;
            var lane_word_counts: [temporal.CHILD_COUNT]usize = undefined;
            var lane_payload_counts: [temporal.CHILD_COUNT]usize = undefined;
            var child_replays: [temporal.CHILD_COUNT]TemporalChildTranscriptReplayV2 =
                undefined;
            inline for (0..temporal.CHILD_COUNT) |lane| {
                const artifact = artifacts[lane];
                if (!std.meta.eql(
                    artifact.publication.publication_id,
                    pair.source_bindings[lane].source_publication_id,
                )) return error.PairSnapshotMismatch;
                if (lane != 0) try recorder.beginLane(
                    transcript_air.RIGHT_RECURSION_VERIFIER_ID,
                );
                try segment_artifact.preflight(
                    artifact.capture,
                    artifact.publication,
                    artifact.witness,
                    artifact.manifest,
                );
                try validateCaptureTranscriptShape(artifact.capture);
                const first_row = recorder.rows.items.len;
                const first_frame = recorder.frames.items.len;
                child_replays[lane] = try deriveReplayAfterPreflight(
                    &recorder,
                    artifact.manifest,
                    artifact.publication,
                    artifact.witness,
                    artifact.capture,
                );
                try recorder.checkHealthy();
                lane_row_counts[lane] = recorder.rows.items.len - first_row;
                lane_operation_counts[lane] = recorder.operation_id;
                lane_frame_counts[lane] = recorder.hash_id;
                lane_word_counts[lane] = try transcriptWordCount(
                    recorder.frames.items[first_frame..],
                );
                lane_payload_counts[lane] = try transcriptPayloadCount(
                    recorder.frames.items[first_frame..],
                );
                if (lane_row_counts[lane] == 0 or
                    lane_operation_counts[lane] == 0 or
                    lane_frame_counts[lane] == 0 or lane_word_counts[lane] == 0 or
                    lane_payload_counts[lane] == 0)
                {
                    return error.InvalidTranscriptRecorder;
                }
            }

            const rows = try recorder.takeRows();
            errdefer allocator.free(rows);
            const operations = try recorder.takeOperations();
            errdefer allocator.free(operations);
            const frames = try recorder.takeFrames();
            errdefer allocator.free(frames);
            var result = PreparedTranscriptRowsV2{
                .allocator = allocator,
                .log_size = try transcriptTraceLogSize(rows.len),
                .pair_authority_id = pair.authority_id,
                .lane_row_counts = lane_row_counts,
                .lane_operation_counts = lane_operation_counts,
                .lane_frame_counts = lane_frame_counts,
                .lane_word_counts = lane_word_counts,
                .lane_payload_counts = lane_payload_counts,
                .child_replays = child_replays,
                .rows = rows,
                .operations = operations,
                .frames = frames,
                .authority_sha_id = undefined,
            };
            try validateTranscriptRowsV2(&result);
            result.authority_sha_id = transcriptRowsAuthoritySha(&result);
            try result.validate();
            return result;
        }

        pub fn typecheckTemporalTranscriptPreparation(
            allocator: std.mem.Allocator,
            pair: *const PairAuthority,
            left: TemporalChildArtifactV2,
            right: TemporalChildArtifactV2,
        ) !void {
            var prepared = try PreparedTranscriptRowsV2.init(
                allocator,
                pair,
                left,
                right,
            );
            defer prepared.deinit();
            try prepared.validateAgainstArtifacts(pair, left, right);
        }

        pub fn typecheckTemporalTranscriptWriters(
            prepared: *const PreparedTranscriptRowsV2,
            control_rows: []TranscriptControlRow,
            binding_rows: []TranscriptBindingRowV2,
            state_rows: []TranscriptStateRowV2,
            word_rows: []TranscriptWordRowV2,
            payload_rows: []TemporalTranscriptPayloadRowV2,
            pow_checks: []TemporalPowCheckRowV2,
            pow_frames: []TemporalPowFrameRowV2,
            relation_rows: []TemporalPackedRelationChallengeRowV2,
            randomness_rows: []TemporalVerifierRandomnessRowV2,
            provider_calls: []TranscriptProviderCall,
            main_columns: *[transcript_air.MAIN_COLUMN_COUNT][]M31,
        ) !void {
            _ = try prepared.controlLogSize();
            _ = try prepared.stateLogSize();
            _ = try prepared.wordLogSize();
            _ = try prepared.payloadLogSize();
            _ = try prepared.powLogSize();
            _ = try prepared.relationChallengeLogSize();
            _ = try prepared.randomnessLogSize();
            _ = try prepared.manifest();
            try prepared.fillControlRowsInto(control_rows);
            try prepared.fillBindingRowsInto(binding_rows);
            try prepared.fillStateRowsInto(state_rows);
            try prepared.fillWordRowsInto(word_rows);
            try prepared.fillPayloadRowsInto(payload_rows);
            try prepared.fillPowRowsInto(pow_checks, pow_frames);
            try prepared.fillRelationChallengeRowsInto(relation_rows);
            try prepared.validateRelationChallengeRows(relation_rows);
            try prepared.fillRandomnessRowsInto(randomness_rows);
            try prepared.fillProviderCallsInto(provider_calls);
            try prepared.fillMainInto(main_columns);
        }

        pub const TemporalParentPublicV2 = struct {
            format_version: u16 = FORMAT_VERSION,
            schema_version: u16 = SCHEMA_VERSION,
            status: ProductionStatus = CURRENT_STATUS,
            parent_height: u8,
            padding: [3]u8 = .{ 0, 0, 0 },
            parent_node_index: u64,
            pair_authority_id: Digest,
            adjacency_id: Digest,
            context_id: Digest,
            node_id: Digest,
            record_id: Digest,
            session_id: Digest,
            job_id: Digest,
            aggregator_vk_id: Digest,
            child_kinds: [temporal.CHILD_COUNT]temporal.ProofKind,
            child_ids: [temporal.CHILD_COUNT]Digest,
            child_publication_ids: [temporal.CHILD_COUNT]Digest,
            child_statement_ids: [temporal.CHILD_COUNT]Digest,
            parent_statement_id: Digest,
            identity: Digest,

            pub fn validate(self: *const TemporalParentPublicV2) Error!void {
                if (self.format_version != FORMAT_VERSION or
                    self.schema_version != SCHEMA_VERSION or
                    self.status != CURRENT_STATUS or
                    self.parent_height == 0 or
                    !allZero(&self.padding))
                {
                    return error.UnsupportedFormat;
                }
                inline for (.{
                    self.pair_authority_id,
                    self.adjacency_id,
                    self.context_id,
                    self.node_id,
                    self.record_id,
                    self.session_id,
                    self.job_id,
                    self.aggregator_vk_id,
                    self.parent_statement_id,
                    self.identity,
                }) |value| try requireDigest(value);
                for (self.child_ids) |value| try requireDigest(value);
                for (self.child_publication_ids) |value| try requireDigest(value);
                for (self.child_statement_ids) |value| try requireDigest(value);
                if (!std.meta.eql(self.identity, publicIdentity(self)))
                    return error.InvalidPublicRecord;
            }
        };

        /// Owned row-10/11 source.  Its public constructor has no statement, claim,
        /// relation, or child-role parameters: all three statement preimages come
        /// from the authenticated temporal pair snapshot.
        pub const PreparedRows10Through11V2 = struct {
            allocator: std.mem.Allocator,
            format_version: u16 = FORMAT_VERSION,
            schema_version: u16 = SCHEMA_VERSION,
            status: ProductionStatus = CURRENT_STATUS,
            public: TemporalParentPublicV2,
            left_statement: span_statement.SpanStatement,
            right_statement: span_statement.SpanStatement,
            parent_statement: span_statement.SpanStatement,
            left_words: span_statement.StatementWords,
            right_words: span_statement.StatementWords,
            parent_words: span_statement.StatementWords,
            circuit_evaluation: statement_circuit.Evaluation,
            statement_values: []M31,
            range: range_owner.Prepared,
            source_id: Digest,

            pub fn init(
                allocator: std.mem.Allocator,
                authority: *const statement_source.Authority,
                workspace: *statement_air.Workspace,
                pair: *const PairAuthority,
            ) Error!PreparedRows10Through11V2 {
                try pair.validate();
                const authenticated = try authenticatePreparedPairForSource(pair);
                try authority.validateSeals();
                try workspace.validate();

                const children = pair.prepared_root.authority_snapshot.children;
                const left_statement = try children[0].statement();
                const right_statement = try children[1].statement();
                const parent_statement = try span_statement.SpanStatement.fold(
                    left_statement,
                    right_statement,
                );
                const left_words = try left_statement.canonicalWords();
                const right_words = try right_statement.canonicalWords();
                const parent_words = try parent_statement.canonicalWords();
                if (!m31SlicesEql(&left_words, &children[0].statement_words) or
                    !m31SlicesEql(&right_words, &children[1].statement_words) or
                    !std.meta.eql(parent_statement, authenticated.pair.parent_statement) or
                    !m31SlicesEql(
                        &parent_words,
                        &authenticated.pair.parent_statement_words,
                    ))
                {
                    return error.PairSnapshotMismatch;
                }

                var circuit_evaluation = try authority.circuit.evaluate(
                    allocator,
                    statement_circuit.Witness.forBinary(
                        &left_words,
                        &right_words,
                        &parent_words,
                    ),
                );
                errdefer circuit_evaluation.deinit();
                const statement_values = try allocator.alloc(
                    M31,
                    statement_circuit.INPUT_COUNT,
                );
                errdefer allocator.free(statement_values);
                try baseInputs(circuit_evaluation.inputs(), statement_values);

                var range = try range_owner.Prepared.init(
                    allocator,
                    &workspace.range,
                    .{
                        .preprocessing = &authority.statement_semantics_preprocessing,
                        .values = statement_values,
                        .left = &left_words,
                        .right = &right_words,
                        .parent = &parent_words,
                    },
                );
                errdefer range.deinit();

                var result = PreparedRows10Through11V2{
                    .allocator = allocator,
                    .public = try publicFromPair(pair, authenticated),
                    .left_statement = left_statement,
                    .right_statement = right_statement,
                    .parent_statement = parent_statement,
                    .left_words = left_words,
                    .right_words = right_words,
                    .parent_words = parent_words,
                    .circuit_evaluation = circuit_evaluation,
                    .statement_values = statement_values,
                    .range = range,
                    .source_id = undefined,
                };
                result.source_id = statementSourceIdentity(&result);
                try result.validateAfterAuthenticatedPair(authority, workspace);
                return result;
            }

            pub fn deinit(self: *PreparedRows10Through11V2) void {
                self.range.deinit();
                self.allocator.free(self.statement_values);
                self.circuit_evaluation.deinit();
                self.* = undefined;
            }

            pub fn validateAgainstPair(
                self: *const PreparedRows10Through11V2,
                authority: *const statement_source.Authority,
                workspace: *statement_air.Workspace,
                pair: *const PairAuthority,
            ) Error!void {
                try pair.validate();
                const authenticated = try authenticatePreparedPairForSource(pair);
                const expected_public = try publicFromPair(pair, authenticated);
                if (!std.meta.eql(self.public, expected_public))
                    return error.PairSnapshotMismatch;
                try self.validateAfterAuthenticatedPair(authority, workspace);
            }

            /// Allocation-free hot validation used by the generic row-10/11 writer.
            /// Pair authentication is a cold ingress operation and is not repeated for
            /// each tree fill.
            pub fn validateHot(
                self: *const PreparedRows10Through11V2,
                authority: *const statement_source.Authority,
                workspace: *statement_air.Workspace,
            ) Error!void {
                try self.validateAfterAuthenticatedPair(authority, workspace);
            }

            fn validateAfterAuthenticatedPair(
                self: *const PreparedRows10Through11V2,
                authority: *const statement_source.Authority,
                workspace: *statement_air.Workspace,
            ) Error!void {
                if (self.format_version != FORMAT_VERSION or
                    self.schema_version != SCHEMA_VERSION or
                    self.status != CURRENT_STATUS)
                {
                    return error.UnsupportedFormat;
                }
                try self.public.validate();
                try authority.validateSeals();
                try workspace.validate();
                try rejectWorkspaceAliases(self, workspace);

                const expected_parent = try span_statement.SpanStatement.fold(
                    self.left_statement,
                    self.right_statement,
                );
                const expected_left_words = try self.left_statement.canonicalWords();
                const expected_right_words = try self.right_statement.canonicalWords();
                const expected_parent_words = try expected_parent.canonicalWords();
                if (!std.meta.eql(self.parent_statement, expected_parent) or
                    !m31SlicesEql(&self.left_words, &expected_left_words) or
                    !m31SlicesEql(&self.right_words, &expected_right_words) or
                    !m31SlicesEql(&self.parent_words, &expected_parent_words) or
                    !std.meta.eql(
                        self.public.parent_statement_id,
                        try statementId(&self.parent_words),
                    ) or
                    !std.meta.eql(self.source_id, statementSourceIdentity(self)) or
                    self.statement_values.len != statement_circuit.INPUT_COUNT or
                    !std.mem.eql(
                        u8,
                        &self.circuit_evaluation.circuit_identity,
                        &authority.circuit.identity_digest,
                    ) or
                    self.circuit_evaluation.inputs().len !=
                        statement_circuit.INPUT_COUNT or
                    self.circuit_evaluation.values().len !=
                        statement_circuit.NODE_COUNT)
                {
                    return error.SourceIdentityMismatch;
                }

                const replay = workspace.secure_storage[0 .. statement_circuit.INPUT_COUNT + statement_circuit.NODE_COUNT];
                const replay_inputs = replay[0..statement_circuit.INPUT_COUNT];
                const replay_values = replay[statement_circuit.INPUT_COUNT..];
                try authority.circuit.evaluateIntoAssumeValid(
                    statement_circuit.Witness.forBinary(
                        &self.left_words,
                        &self.right_words,
                        &self.parent_words,
                    ),
                    replay_inputs,
                    replay_values,
                );
                if (!secureSlicesEql(
                    replay_inputs,
                    self.circuit_evaluation.inputs(),
                ) or !secureSlicesEql(
                    replay_values,
                    self.circuit_evaluation.values(),
                )) return error.SourceIdentityMismatch;

                const expected_base =
                    workspace.logical_storage[0..statement_circuit.INPUT_COUNT];
                try baseInputs(replay_inputs, expected_base);
                if (!m31SlicesEql(expected_base, self.statement_values))
                    return error.SourceIdentityMismatch;
                try self.range.validateAgainst(&workspace.range, .{
                    .preprocessing = &authority.statement_semantics_preprocessing,
                    .values = self.statement_values,
                    .left = &self.left_words,
                    .right = &self.right_words,
                    .parent = &self.parent_words,
                });
            }
        };

        pub const ImplementedRowAuthority = enum(u8) {
            authenticated_temporal_statement = 1,
            canonical_inactive_binary = 2,
            binary_public_logup_control = 3,
        };

        /// Pointer-free custody seal for rows 10--17.  Claims are intentionally
        /// absent: they are generated only by the typed interaction writers.
        pub const Rows10Through17AuthorityV2 = struct {
            format_version: u16 = FORMAT_VERSION,
            schema_version: u16 = SCHEMA_VERSION,
            row_count: u8 = IMPLEMENTED_ROW_COUNT,
            padding: [3]u8 = .{ 0, 0, 0 },
            row_mask: u64 = IMPLEMENTED_ROW_MASK,
            active_domain_masks: [IMPLEMENTED_ROW_COUNT]u64 =
                IMPLEMENTED_ACTIVE_DOMAIN_MASKS,
            owners: [IMPLEMENTED_ROW_COUNT]ImplementedRowAuthority = .{
                .authenticated_temporal_statement,
                .authenticated_temporal_statement,
                .canonical_inactive_binary,
                .canonical_inactive_binary,
                .canonical_inactive_binary,
                .canonical_inactive_binary,
                .canonical_inactive_binary,
                .binary_public_logup_control,
            },
            statement_source_id: Digest,
            pair_authority_id: Digest,
            inactive_source_sha_id: [32]u8,
            inactive_prepared_sha_id: [32]u8,
            authority_id: Digest,

            pub fn init(
                statement: *const PreparedRows10Through11V2,
                statement_authority: *const statement_source.Authority,
                statement_workspace: *statement_air.Workspace,
                pair: *const PairAuthority,
                inactive_source: *const inactive.Source,
                inactive_prepared: *const inactive.Prepared,
                typed_public: *const segment_public.Source,
                vm_plan: *const schedule.Plan,
                recursion_plan: *const schedule.Plan,
                preprocessing: *const leaf_authority.Preprocessing,
            ) !Rows10Through17AuthorityV2 {
                try statement.validateAgainstPair(
                    statement_authority,
                    statement_workspace,
                    pair,
                );
                try inactive_source.validateAgainst(
                    typed_public,
                    vm_plan,
                    recursion_plan,
                    preprocessing,
                );
                try inactive_prepared.validateAgainst(
                    inactive_source,
                    typed_public,
                    vm_plan,
                    recursion_plan,
                    preprocessing,
                );
                var result = Rows10Through17AuthorityV2{
                    .statement_source_id = statement.source_id,
                    .pair_authority_id = pair.authority_id,
                    .inactive_source_sha_id = inactive_source.authority_seal,
                    .inactive_prepared_sha_id = inactive_prepared.authority_seal,
                    .authority_id = undefined,
                };
                result.authority_id = rowAuthorityIdentity(&result);
                try result.validate();
                return result;
            }

            pub fn validate(self: *const Rows10Through17AuthorityV2) Error!void {
                if (self.format_version != FORMAT_VERSION or
                    self.schema_version != SCHEMA_VERSION or
                    self.row_count != IMPLEMENTED_ROW_COUNT or
                    self.row_mask != IMPLEMENTED_ROW_MASK or
                    !std.meta.eql(
                        self.active_domain_masks,
                        IMPLEMENTED_ACTIVE_DOMAIN_MASKS,
                    ) or !std.meta.eql(self.owners, @as(
                    [IMPLEMENTED_ROW_COUNT]ImplementedRowAuthority,
                    .{
                        .authenticated_temporal_statement,
                        .authenticated_temporal_statement,
                        .canonical_inactive_binary,
                        .canonical_inactive_binary,
                        .canonical_inactive_binary,
                        .canonical_inactive_binary,
                        .canonical_inactive_binary,
                        .binary_public_logup_control,
                    },
                )) or !allZero(&self.padding)) {
                    return error.UnsupportedFormat;
                }
                try requireDigest(self.statement_source_id);
                try requireDigest(self.pair_authority_id);
                try requireSha(self.inactive_source_sha_id);
                try requireSha(self.inactive_prepared_sha_id);
                try requireDigest(self.authority_id);
                if (!std.meta.eql(self.authority_id, rowAuthorityIdentity(self)))
                    return error.AuthorityIdentityMismatch;
            }
        };

        // Pointer-free custody snapshot for the complete temporal-parent non-FRI
        // prefix.  It is append-only V3 because row 8 has a different committed AIR
        // geometry from frozen V1/V2.  The snapshot binds the ordered verifier-minted
        // children, their exact transcript replays, the folded parent statement,
        // rows 10--17 authority, all 47 relation-domain frames per child, and every
        // preprocessed/main/interaction placement before any tree write begins.
    };
}
