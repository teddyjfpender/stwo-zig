//! Cohesive internal authority extracted from recursive_temporal_nonfri_source_v2.zig.

pub fn Namespace(comptime context: type) type {
    return struct {
        const std = context.d_std;
        const inactive = context.d_inactive;
        const schedule = context.d_schedule;
        const statement_air = context.d_statement_air;
        const statement_source = context.d_statement_source;
        const temporal = context.d_temporal;
        const transcript_air = context.d_transcript_air;
        const transcript_component = context.d_transcript_component;
        const transcript_binding = context.d_transcript_binding;
        const transcript_state = context.d_transcript_state;
        const transcript_word = context.d_transcript_word;
        const transcript_payload = context.d_transcript_payload;
        const pow_check_air = context.d_pow_check_air;
        const verifier_randomness = context.d_verifier_randomness;
        const universal_binding = context.d_universal_binding;
        const packed_relation_challenge_v2 = context.d_packed_relation_challenge_v2;
        const control_air = context.d_control_air;
        const transcript_binding_air = context.d_transcript_binding_air;
        const transcript_state_air = context.d_transcript_state_air;
        const transcript_word_air = context.d_transcript_word_air;
        const pow_frame_air = context.d_pow_frame_air;
        const verifier_randomness_air = context.d_verifier_randomness_air;
        const statement_input_air = context.d_statement_input_air;
        const statement_semantics_air = context.d_statement_semantics_air;
        const Digest = context.d_Digest;
        const PairAuthority = context.d_PairAuthority;
        const TRANSCRIPT_ROW_COUNT = context.d_TRANSCRIPT_ROW_COUNT;
        const PREFIX_CUSTODY_FORMAT_VERSION = context.d_PREFIX_CUSTODY_FORMAT_VERSION;
        const PREFIX_CUSTODY_SCHEMA_VERSION = context.d_PREFIX_CUSTODY_SCHEMA_VERSION;
        const PREFIX_ROW_COUNT = context.d_PREFIX_ROW_COUNT;
        const TranscriptControlRow = context.d_TranscriptControlRow;
        const TranscriptBindingRowV2 = context.d_TranscriptBindingRowV2;
        const TranscriptStateRowV2 = context.d_TranscriptStateRowV2;
        const TranscriptWordRowV2 = context.d_TranscriptWordRowV2;
        const TemporalTranscriptPayloadRowV2 = context.d_TemporalTranscriptPayloadRowV2;
        const TemporalPowCheckRowV2 = context.d_TemporalPowCheckRowV2;
        const TemporalPowFrameRowV2 = context.d_TemporalPowFrameRowV2;
        const TemporalVerifierRandomnessRowV2 = context.d_TemporalVerifierRandomnessRowV2;
        const TemporalPackedRelationChallengeRowV2 = context.d_TemporalPackedRelationChallengeRowV2;
        const ControlRelation = context.d_ControlRelation;
        const TranscriptAirRelation = context.d_TranscriptAirRelation;
        const TranscriptBindingRelation = context.d_TranscriptBindingRelation;
        const TranscriptStateRelation = context.d_TranscriptStateRelation;
        const TranscriptWordRelation = context.d_TranscriptWordRelation;
        const TranscriptPayloadRelation = context.d_TranscriptPayloadRelation;
        const PowCheckRelation = context.d_PowCheckRelation;
        const PowFrameRelation = context.d_PowFrameRelation;
        const PackedRelationChallengeRelation = context.d_PackedRelationChallengeRelation;
        const VerifierRandomnessRelation = context.d_VerifierRandomnessRelation;
        const TemporalAirOwner = context.d_TemporalAirOwner;
        const TemporalTranscriptManifestV2 = context.d_TemporalTranscriptManifestV2;
        const TemporalPrefixCommitmentLayoutV3 = context.d_TemporalPrefixCommitmentLayoutV3;
        const Error = context.d_Error;
        const TemporalChildTranscriptReplayV2 = context.d_TemporalChildTranscriptReplayV2;
        const TemporalChildArtifactV2 = context.d_TemporalChildArtifactV2;
        const PreparedTranscriptRowsV2 = context.d_PreparedTranscriptRowsV2;
        const TemporalParentPublicV2 = context.d_TemporalParentPublicV2;
        const PreparedRows10Through11V2 = context.d_PreparedRows10Through11V2;
        const Rows10Through17AuthorityV2 = context.d_Rows10Through17AuthorityV2;
        const initTemporalRows0Through17CustodyInto = context.d_initTemporalRows0Through17CustodyInto;
        const prefixCustodyIdentity = context.d_prefixCustodyIdentity;
        const requireDigest = context.d_requireDigest;
        const requireSha = context.d_requireSha;
        const allZero = context.d_allZero;

        pub const TemporalRows0Through17CustodyV3 = struct {
            format_version: u16 = PREFIX_CUSTODY_FORMAT_VERSION,
            schema_version: u16 = PREFIX_CUSTODY_SCHEMA_VERSION,
            row_count: u8 = PREFIX_ROW_COUNT,
            padding: [3]u8 = .{ 0, 0, 0 },
            parent_public: TemporalParentPublicV2,
            transcript_manifest: TemporalTranscriptManifestV2,
            rows_10_through_17: Rows10Through17AuthorityV2,
            child_replays: [temporal.CHILD_COUNT]TemporalChildTranscriptReplayV2,
            child_relation_domain_sha_ids: [temporal.CHILD_COUNT][32]u8,
            commitment_layout: TemporalPrefixCommitmentLayoutV3,
            custody_id: Digest,

            /// Allocation-free hostile-mutation audit for an already cold-prepared
            /// snapshot. Source re-admission is intentionally a separate cold method.
            pub fn validate(
                self: *const TemporalRows0Through17CustodyV3,
            ) Error!void {
                if (self.format_version != PREFIX_CUSTODY_FORMAT_VERSION or
                    self.schema_version != PREFIX_CUSTODY_SCHEMA_VERSION or
                    self.row_count != PREFIX_ROW_COUNT or !allZero(&self.padding))
                {
                    return error.UnsupportedFormat;
                }
                try self.parent_public.validate();
                try self.transcript_manifest.validate();
                try self.rows_10_through_17.validate();
                for (&self.child_replays) |*replay| try replay.validate();
                for (self.child_relation_domain_sha_ids) |value| try requireSha(value);
                try self.commitment_layout.validate();
                try requireDigest(self.custody_id);

                const publications = [temporal.CHILD_COUNT]Digest{
                    self.child_replays[0].publication_id,
                    self.child_replays[1].publication_id,
                };
                const replay_ids = [temporal.CHILD_COUNT]Digest{
                    self.child_replays[0].replay_id,
                    self.child_replays[1].replay_id,
                };
                if (!std.meta.eql(
                    self.parent_public.pair_authority_id,
                    self.transcript_manifest.pair_authority_id,
                ) or !std.meta.eql(
                    self.parent_public.pair_authority_id,
                    self.rows_10_through_17.pair_authority_id,
                ) or !std.meta.eql(
                    self.parent_public.pair_authority_id,
                    self.commitment_layout.pair_authority_id,
                ) or !std.meta.eql(
                    self.parent_public.identity,
                    self.commitment_layout.parent_public_id,
                ) or !std.mem.eql(
                    u8,
                    &self.transcript_manifest.identity,
                    &self.commitment_layout.transcript_manifest_sha_id,
                ) or !std.meta.eql(
                    self.rows_10_through_17.authority_id,
                    self.commitment_layout.rows_10_through_17_authority_id,
                ) or !std.meta.eql(
                    publications,
                    self.parent_public.child_publication_ids,
                ) or !std.meta.eql(
                    publications,
                    self.commitment_layout.child_publication_ids,
                ) or !std.meta.eql(
                    replay_ids,
                    self.commitment_layout.child_replay_ids,
                ) or !std.meta.eql(
                    self.child_relation_domain_sha_ids,
                    self.commitment_layout.child_relation_domain_sha_ids,
                ) or !std.meta.eql(self.custody_id, prefixCustodyIdentity(self))) {
                    return error.SourceIdentityMismatch;
                }
            }

            /// Cold source re-admission. This deliberately repeats the exact
            /// transcript construction and artifact preflight; callers use `validate`
            /// on the subsequent allocation-free tree/interaction hot path.
            pub fn validateAgainstSources(
                self: *const TemporalRows0Through17CustodyV3,
                pair: *const PairAuthority,
                transcript_rows: *const PreparedTranscriptRowsV2,
                statement_rows: *const PreparedRows10Through11V2,
                statement_authority: *const statement_source.Authority,
                statement_workspace: *statement_air.Workspace,
                rows_10_through_17: *const Rows10Through17AuthorityV2,
                inactive_source: *const inactive.Source,
                vm_plan: *const schedule.Plan,
                recursion_plan: *const schedule.Plan,
                left: TemporalChildArtifactV2,
                right: TemporalChildArtifactV2,
            ) Error!void {
                var expected: TemporalRows0Through17CustodyV3 = undefined;
                try initTemporalRows0Through17CustodyInto(
                    &expected,
                    pair,
                    transcript_rows,
                    statement_rows,
                    statement_authority,
                    statement_workspace,
                    rows_10_through_17,
                    inactive_source,
                    vm_plan,
                    recursion_plan,
                    left,
                    right,
                );
                if (!std.meta.eql(self.*, expected))
                    return error.SourceIdentityMismatch;
            }
        };

        pub const TemporalTranscriptOwnersV3 = struct {
            control: TemporalAirOwner(control_air),
            transcript_air: TemporalAirOwner(transcript_component),
            transcript_binding: TemporalAirOwner(transcript_binding_air),
            transcript_state: TemporalAirOwner(transcript_state_air),
            transcript_word: TemporalAirOwner(transcript_word_air),
            transcript_payload: TemporalAirOwner(transcript_payload),
            pow_check: TemporalAirOwner(pow_check_air),
            pow_frame: TemporalAirOwner(pow_frame_air),
            packed_relation_challenge: TemporalAirOwner(
                packed_relation_challenge_v2,
            ),
            verifier_randomness: TemporalAirOwner(verifier_randomness_air),

            pub fn init(allocator: std.mem.Allocator) !TemporalTranscriptOwnersV3 {
                var control = try TemporalAirOwner(control_air).init(allocator);
                errdefer control.deinit();
                var transcript_air_value = try TemporalAirOwner(
                    transcript_component,
                ).init(allocator);
                errdefer transcript_air_value.deinit();
                var transcript_binding_value = try TemporalAirOwner(
                    transcript_binding_air,
                ).init(allocator);
                errdefer transcript_binding_value.deinit();
                var transcript_state_value = try TemporalAirOwner(
                    transcript_state_air,
                ).init(allocator);
                errdefer transcript_state_value.deinit();
                var transcript_word_value = try TemporalAirOwner(
                    transcript_word_air,
                ).init(allocator);
                errdefer transcript_word_value.deinit();
                var transcript_payload_value = try TemporalAirOwner(
                    transcript_payload,
                ).init(allocator);
                errdefer transcript_payload_value.deinit();
                var pow_check_value = try TemporalAirOwner(pow_check_air).init(
                    allocator,
                );
                errdefer pow_check_value.deinit();
                var pow_frame_value = try TemporalAirOwner(pow_frame_air).init(
                    allocator,
                );
                errdefer pow_frame_value.deinit();
                var packed_value = try TemporalAirOwner(
                    packed_relation_challenge_v2,
                ).init(allocator);
                errdefer packed_value.deinit();
                var randomness_value = try TemporalAirOwner(
                    verifier_randomness_air,
                ).init(allocator);
                errdefer randomness_value.deinit();
                return .{
                    .control = control,
                    .transcript_air = transcript_air_value,
                    .transcript_binding = transcript_binding_value,
                    .transcript_state = transcript_state_value,
                    .transcript_word = transcript_word_value,
                    .transcript_payload = transcript_payload_value,
                    .pow_check = pow_check_value,
                    .pow_frame = pow_frame_value,
                    .packed_relation_challenge = packed_value,
                    .verifier_randomness = randomness_value,
                };
            }

            pub fn validate(self: *const TemporalTranscriptOwnersV3) !void {
                try self.control.validate();
                try self.transcript_air.validate();
                try self.transcript_binding.validate();
                try self.transcript_state.validate();
                try self.transcript_word.validate();
                try self.transcript_payload.validate();
                try self.pow_check.validate();
                try self.pow_frame.validate();
                try self.packed_relation_challenge.validate();
                try self.verifier_randomness.validate();
            }

            pub fn deinit(self: *TemporalTranscriptOwnersV3) void {
                self.verifier_randomness.deinit();
                self.packed_relation_challenge.deinit();
                self.pow_frame.deinit();
                self.pow_check.deinit();
                self.transcript_payload.deinit();
                self.transcript_word.deinit();
                self.transcript_state.deinit();
                self.transcript_binding.deinit();
                self.transcript_air.deinit();
                self.control.deinit();
                self.* = undefined;
            }
        };

        pub const TemporalPrefixLogicalBuffersV3 = struct {
            allocator: std.mem.Allocator,
            control_typed: []TranscriptControlRow,
            binding_typed: []TranscriptBindingRowV2,
            state_typed: []TranscriptStateRowV2,
            word_typed: []TranscriptWordRowV2,
            payload_typed: []TemporalTranscriptPayloadRowV2,
            pow_check_typed: []TemporalPowCheckRowV2,
            pow_frame_typed: []TemporalPowFrameRowV2,
            packed_typed: []TemporalPackedRelationChallengeRowV2,
            randomness_typed: []TemporalVerifierRandomnessRowV2,
            control: []ControlRelation.Row,
            transcript_air: []TranscriptAirRelation.Row,
            transcript_binding: []TranscriptBindingRelation.Row,
            transcript_state: []TranscriptStateRelation.Row,
            transcript_word: []TranscriptWordRelation.Row,
            transcript_payload: []TranscriptPayloadRelation.Row,
            pow_check: []PowCheckRelation.Row,
            pow_frame: []PowFrameRelation.Row,
            packed_relation_challenge: []PackedRelationChallengeRelation.Row,
            verifier_randomness: []VerifierRandomnessRelation.Row,
            statement_input: []universal_binding.Binding(statement_input_air).Row,
            statement_semantics: []universal_binding.Binding(
                statement_semantics_air,
            ).Row,

            pub fn init(
                allocator: std.mem.Allocator,
                transcript_counts: [TRANSCRIPT_ROW_COUNT]u32,
                statement_input_count: usize,
                statement_semantics_count: usize,
            ) !TemporalPrefixLogicalBuffersV3 {
                const c0: usize = @intCast(transcript_counts[0]);
                const c1: usize = @intCast(transcript_counts[1]);
                const c2: usize = @intCast(transcript_counts[2]);
                const c3: usize = @intCast(transcript_counts[3]);
                const c4: usize = @intCast(transcript_counts[4]);
                const c5: usize = @intCast(transcript_counts[5]);
                const c6: usize = @intCast(transcript_counts[6]);
                const c7: usize = @intCast(transcript_counts[7]);
                const c8: usize = @intCast(transcript_counts[8]);
                const c9: usize = @intCast(transcript_counts[9]);

                const control_typed = try allocator.alloc(TranscriptControlRow, c0);
                errdefer allocator.free(control_typed);
                const binding_typed = try allocator.alloc(TranscriptBindingRowV2, c2);
                errdefer allocator.free(binding_typed);
                const state_typed = try allocator.alloc(TranscriptStateRowV2, c3);
                errdefer allocator.free(state_typed);
                const word_typed = try allocator.alloc(TranscriptWordRowV2, c4);
                errdefer allocator.free(word_typed);
                const payload_typed = try allocator.alloc(
                    TemporalTranscriptPayloadRowV2,
                    c5,
                );
                errdefer allocator.free(payload_typed);
                const pow_check_typed = try allocator.alloc(TemporalPowCheckRowV2, c6);
                errdefer allocator.free(pow_check_typed);
                const pow_frame_typed = try allocator.alloc(TemporalPowFrameRowV2, c7);
                errdefer allocator.free(pow_frame_typed);
                const packed_typed = try allocator.alloc(
                    TemporalPackedRelationChallengeRowV2,
                    c8,
                );
                errdefer allocator.free(packed_typed);
                const randomness_typed = try allocator.alloc(
                    TemporalVerifierRandomnessRowV2,
                    c9,
                );
                errdefer allocator.free(randomness_typed);

                const control = try allocator.alloc(ControlRelation.Row, c0);
                errdefer allocator.free(control);
                const transcript_air_rows = try allocator.alloc(
                    TranscriptAirRelation.Row,
                    c1,
                );
                errdefer allocator.free(transcript_air_rows);
                const transcript_binding_rows = try allocator.alloc(
                    TranscriptBindingRelation.Row,
                    c2,
                );
                errdefer allocator.free(transcript_binding_rows);
                const transcript_state_rows = try allocator.alloc(
                    TranscriptStateRelation.Row,
                    c3,
                );
                errdefer allocator.free(transcript_state_rows);
                const transcript_word_rows = try allocator.alloc(
                    TranscriptWordRelation.Row,
                    c4,
                );
                errdefer allocator.free(transcript_word_rows);
                const transcript_payload_rows = try allocator.alloc(
                    TranscriptPayloadRelation.Row,
                    c5,
                );
                errdefer allocator.free(transcript_payload_rows);
                const pow_check_rows = try allocator.alloc(PowCheckRelation.Row, c6);
                errdefer allocator.free(pow_check_rows);
                const pow_frame_rows = try allocator.alloc(PowFrameRelation.Row, c7);
                errdefer allocator.free(pow_frame_rows);
                const packed_rows = try allocator.alloc(
                    PackedRelationChallengeRelation.Row,
                    c8,
                );
                errdefer allocator.free(packed_rows);
                const randomness_rows = try allocator.alloc(
                    VerifierRandomnessRelation.Row,
                    c9,
                );
                errdefer allocator.free(randomness_rows);
                const statement_input_rows = try allocator.alloc(
                    universal_binding.Binding(statement_input_air).Row,
                    statement_input_count,
                );
                errdefer allocator.free(statement_input_rows);
                const statement_semantics_rows = try allocator.alloc(
                    universal_binding.Binding(statement_semantics_air).Row,
                    statement_semantics_count,
                );
                errdefer allocator.free(statement_semantics_rows);

                return .{
                    .allocator = allocator,
                    .control_typed = control_typed,
                    .binding_typed = binding_typed,
                    .state_typed = state_typed,
                    .word_typed = word_typed,
                    .payload_typed = payload_typed,
                    .pow_check_typed = pow_check_typed,
                    .pow_frame_typed = pow_frame_typed,
                    .packed_typed = packed_typed,
                    .randomness_typed = randomness_typed,
                    .control = control,
                    .transcript_air = transcript_air_rows,
                    .transcript_binding = transcript_binding_rows,
                    .transcript_state = transcript_state_rows,
                    .transcript_word = transcript_word_rows,
                    .transcript_payload = transcript_payload_rows,
                    .pow_check = pow_check_rows,
                    .pow_frame = pow_frame_rows,
                    .packed_relation_challenge = packed_rows,
                    .verifier_randomness = randomness_rows,
                    .statement_input = statement_input_rows,
                    .statement_semantics = statement_semantics_rows,
                };
            }

            pub fn deinit(self: *TemporalPrefixLogicalBuffersV3) void {
                const allocator = self.allocator;
                allocator.free(self.statement_semantics);
                allocator.free(self.statement_input);
                allocator.free(self.verifier_randomness);
                allocator.free(self.packed_relation_challenge);
                allocator.free(self.pow_frame);
                allocator.free(self.pow_check);
                allocator.free(self.transcript_payload);
                allocator.free(self.transcript_word);
                allocator.free(self.transcript_state);
                allocator.free(self.transcript_binding);
                allocator.free(self.transcript_air);
                allocator.free(self.control);
                allocator.free(self.randomness_typed);
                allocator.free(self.packed_typed);
                allocator.free(self.pow_frame_typed);
                allocator.free(self.pow_check_typed);
                allocator.free(self.payload_typed);
                allocator.free(self.word_typed);
                allocator.free(self.state_typed);
                allocator.free(self.binding_typed);
                allocator.free(self.control_typed);
                self.* = undefined;
            }
        };

        // Borrowed, already-authenticated sources for one temporal prefix tree fill.
        // No detached row, claim, challenge or placement enters this boundary.
    };
}
