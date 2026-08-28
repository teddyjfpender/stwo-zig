//! Cohesive internal authority extracted from recursive_temporal_nonfri_source_v2.zig.

pub fn Namespace(comptime context: type) type {
    return struct {
        const std = context.d_std;
        const M31 = context.d_M31;
        const QM31 = context.d_QM31;
        const recursion = context.d_recursion;
        const channel = context.d_channel;
        const schedule = context.d_schedule;
        const manifest_mod = context.d_manifest_mod;
        const transcript_program = context.d_transcript_program;
        const statement_air = context.d_statement_air;
        const temporal = context.d_temporal;
        const transcript_air = context.d_transcript_air;
        const transcript_payload = context.d_transcript_payload;
        const relation_challenge = context.d_relation_challenge;
        const verifier_randomness = context.d_verifier_randomness;
        const poseidon2 = context.d_poseidon2;
        const packed_relation_challenge_v2 = context.d_packed_relation_challenge_v2;
        const CHILD_PACKED_RELATION_DRAW_COUNT = context.d_CHILD_PACKED_RELATION_DRAW_COUNT;
        const PREFIX_ROW_COUNT = context.d_PREFIX_ROW_COUNT;
        const PREFIX_TREE_COUNT = context.d_PREFIX_TREE_COUNT;
        const PREFIX_TREE0_INDEX = context.d_PREFIX_TREE0_INDEX;
        const PREFIX_TREE1_INDEX = context.d_PREFIX_TREE1_INDEX;
        const PREFIX_TREE2_INDEX = context.d_PREFIX_TREE2_INDEX;
        const TranscriptProviderCall = context.d_TranscriptProviderCall;
        const TranscriptControlRow = context.d_TranscriptControlRow;
        const TranscriptBindingRowV2 = context.d_TranscriptBindingRowV2;
        const TranscriptStateRowV2 = context.d_TranscriptStateRowV2;
        const TranscriptWordRowV2 = context.d_TranscriptWordRowV2;
        const TemporalTranscriptPayloadRowV2 = context.d_TemporalTranscriptPayloadRowV2;
        const TemporalPayloadSourceKindV2 = context.d_TemporalPayloadSourceKindV2;
        const TemporalPowCheckRowV2 = context.d_TemporalPowCheckRowV2;
        const TemporalPowFrameRowV2 = context.d_TemporalPowFrameRowV2;
        const TemporalVerifierRandomnessRowV2 = context.d_TemporalVerifierRandomnessRowV2;
        const TemporalPackedRelationChallengeRowV2 = context.d_TemporalPackedRelationChallengeRowV2;
        const TemporalChildTranscriptReplayV2 = context.d_TemporalChildTranscriptReplayV2;
        const annotateNextDraw = context.d_annotateNextDraw;
        const RecordedFrameV2 = context.d_RecordedFrameV2;
        const TranscriptRowRecorderV2 = context.d_TranscriptRowRecorderV2;
        const PreparedTranscriptRowsV2 = context.d_PreparedTranscriptRowsV2;
        const TemporalParentPublicV2 = context.d_TemporalParentPublicV2;
        const Rows10Through17AuthorityV2 = context.d_Rows10Through17AuthorityV2;
        const TemporalRows0Through17CustodyV3 = context.d_TemporalRows0Through17CustodyV3;
        const TemporalPrefixTreeReceiptV3 = context.d_TemporalPrefixTreeReceiptV3;
        const prefixTreeReceipt = context.d_prefixTreeReceipt;
        const prefixTreeSha = context.d_prefixTreeSha;
        const prefixTreeReceiptSha = context.d_prefixTreeReceiptSha;
        const publicIdentity = context.d_publicIdentity;
        const rowAuthorityIdentity = context.d_rowAuthorityIdentity;
        const buildTemporalPrefixCommitmentLayout = context.d_buildTemporalPrefixCommitmentLayout;
        const prefixLayoutSha = context.d_prefixLayoutSha;
        const prefixCustodyIdentity = context.d_prefixCustodyIdentity;
        const transcriptTraceLogSize = context.d_transcriptTraceLogSize;
        const transcriptWordCount = context.d_transcriptWordCount;
        const transcriptPayloadCount = context.d_transcriptPayloadCount;
        const transcriptPowCount = context.d_transcriptPowCount;
        const transcriptRandomnessCount = context.d_transcriptRandomnessCount;
        const temporalControlRowCount = context.d_temporalControlRowCount;
        const transcriptRelationDrawCount = context.d_transcriptRelationDrawCount;
        const relationRowForFrame = context.d_relationRowForFrame;
        const validateTranscriptRecording = context.d_validateTranscriptRecording;
        const transcriptRowsAuthoritySha = context.d_transcriptRowsAuthoritySha;
        const transcriptManifestSha = context.d_transcriptManifestSha;
        const rowIndex = context.d_rowIndex;
        const m31SlicesEql = context.d_m31SlicesEql;
        const syntheticReplayForTest = context.d_syntheticReplayForTest;
        const TestPrefixTreeStorage = context.d_TestPrefixTreeStorage;

        test "temporal transcript recorder emits exact row-1 and provider cohort" {
            var recorder = TranscriptRowRecorderV2.init(
                std.testing.allocator,
                transcript_air.LEFT_RECURSION_VERIFIER_ID,
            );
            defer recorder.deinit();
            var native = channel.Channel{};

            const canonical = [_]M31{
                M31.fromCanonical(3),
                M31.fromCanonical(5),
                M31.fromCanonical(8),
            };
            recorder.mixCanonicalM31Words(&canonical);
            native.mixCanonicalM31Words(&canonical);
            recorder.mixU32s(&.{ 0xffff_ffff, 17 });
            native.mixU32s(&.{ 0xffff_ffff, 17 });
            const felt = QM31.fromU32Unchecked(1, 2, 3, 4);
            recorder.mixFelts(&.{felt});
            native.mixFelts(&.{felt});
            for (0..CHILD_PACKED_RELATION_DRAW_COUNT) |packed_index| {
                recorder.annotateNextDraw(.relation_draw, .{
                    @intCast(2 * packed_index),
                    packed_relation_challenge_v2.CHALLENGES_PER_DRAW,
                    packed_relation_challenge_v2.PACKING_FORMAT_VERSION,
                    0,
                });
                try std.testing.expectEqual(native.drawU32s(), recorder.drawU32s());
            }
            try std.testing.expectEqual(native.digestWords(), recorder.digestWords());
            try std.testing.expectEqual(native.n_draws, recorder.n_draws);

            const nonce: u64 = 0x1122_3344_5566_7788;
            try std.testing.expect(native.verifyPowNonce(0, nonce));
            try std.testing.expect(recorder.verifyPowNonce(0, nonce));
            native.mixU64(nonce);
            recorder.mixU64(nonce);
            try std.testing.expectEqual(native.digestWords(), recorder.digestWords());
            try std.testing.expectEqual(native.n_draws, recorder.n_draws);
            try std.testing.expectEqual(native.drawU32s(), recorder.drawU32s());
            try std.testing.expectEqual(@as(usize, 106), recorder.rows.items.len);

            const left_count = recorder.rows.items.len;
            const left_operation_count = recorder.operation_id;
            const left_frame_count = recorder.hash_id;
            try recorder.beginLane(transcript_air.RIGHT_RECURSION_VERIFIER_ID);
            native = .{};
            recorder.mixU32s(&.{91});
            native.mixU32s(&.{91});
            for (0..CHILD_PACKED_RELATION_DRAW_COUNT) |packed_index| {
                recorder.annotateNextDraw(.relation_draw, .{
                    @intCast(2 * packed_index),
                    packed_relation_challenge_v2.CHALLENGES_PER_DRAW,
                    packed_relation_challenge_v2.PACKING_FORMAT_VERSION,
                    0,
                });
                try std.testing.expectEqual(native.drawU32s(), recorder.drawU32s());
            }
            recorder.annotateNextDraw(.query_draw, .{ 0, 3, 5, 0 });
            try std.testing.expectEqual(native.drawU32s(), recorder.drawU32s());
            try std.testing.expectEqual(native.digestWords(), recorder.digestWords());
            const right_count = recorder.rows.items.len - left_count;
            const right_operation_count = recorder.operation_id;
            const right_frame_count = recorder.hash_id;
            try std.testing.expectEqual(@as(usize, 98), right_count);

            const rows = try recorder.takeRows();
            const operations = try recorder.takeOperations();
            const frames = try recorder.takeFrames();
            try validateTranscriptRecording(
                rows,
                operations,
                frames,
                .{ left_count, right_count },
                .{ left_operation_count, right_operation_count },
                .{ left_frame_count, right_frame_count },
            );
            try std.testing.expectEqual(@as(usize, 52), left_operation_count);
            try std.testing.expectEqual(@as(usize, 53), left_frame_count);
            try std.testing.expectEqual(@as(usize, 49), right_operation_count);
            try std.testing.expectEqual(@as(usize, 49), right_frame_count);
            try std.testing.expectEqual(@as(u32, 1), operations[left_operation_count - 1].terminal_mask);
            try std.testing.expectEqual(@as(u32, 1), operations[operations.len - 1].terminal_mask);
            try std.testing.expect(frames[51].pow_draw);
            try std.testing.expectEqual(@as(u32, 0), frames[51].draw_output_mask);
            for (rows) |row| {
                const provider = try transcript_air.providerCall(row);
                try std.testing.expect(!provider.wide);
                try std.testing.expect(provider.io);
                try std.testing.expect(provider.narrow_output == null);
                try std.testing.expectEqual(row.providerInput(), provider.input);
                var expected: [poseidon2.WIDTH]M31 = undefined;
                for (&expected, provider.input) |*destination, word|
                    destination.* = M31.fromCanonical(word);
                poseidon2.permute(&expected);
                try std.testing.expect(m31SlicesEql(&expected, &row.output));
            }

            var prepared = PreparedTranscriptRowsV2{
                .allocator = std.testing.allocator,
                .log_size = try transcriptTraceLogSize(rows.len),
                .pair_authority_id = .{27} ** channel.RATE,
                .lane_row_counts = .{ left_count, right_count },
                .lane_operation_counts = .{
                    left_operation_count,
                    right_operation_count,
                },
                .lane_frame_counts = .{ left_frame_count, right_frame_count },
                .lane_word_counts = .{
                    try transcriptWordCount(frames[0..left_frame_count]),
                    try transcriptWordCount(frames[left_frame_count..]),
                },
                .lane_payload_counts = .{
                    try transcriptPayloadCount(frames[0..left_frame_count]),
                    try transcriptPayloadCount(frames[left_frame_count..]),
                },
                .lane_claim_counts = [_]u32{
                    @intCast(manifest_mod.COMPONENT_COUNT),
                } ** temporal.CHILD_COUNT,
                .child_replays = .{
                    try syntheticReplayForTest(31),
                    try syntheticReplayForTest(47),
                },
                .rows = rows,
                .operations = operations,
                .frames = frames,
                .authority_sha_id = undefined,
            };
            defer prepared.deinit();
            prepared.authority_sha_id = transcriptRowsAuthoritySha(&prepared);
            try prepared.validate();

            // A complete temporal parent keeps the non-channel verifier schedule and
            // substitutes the independently replayed raw channel operations for the
            // V1 framed transcript steps. The raw operations remain live until row 2
            // consumes them; only the retained plan's close/complete rows terminate
            // the verifier control relation.
            var plans = try recursion.segment_profile.initPlans(
                std.testing.allocator,
                2,
                3,
            );
            defer plans.recursion.deinit();
            defer plans.vm.deinit();
            const complete_control_count = try temporalControlRowCount(
                prepared.operations.len,
                &plans.vm,
                &plans.recursion,
            );
            const complete_control_rows = try std.testing.allocator.alloc(
                TranscriptControlRow,
                complete_control_count,
            );
            defer std.testing.allocator.free(complete_control_rows);
            try prepared.fillControlRowsForPlansInto(
                complete_control_rows,
                &plans.vm,
                &plans.recursion,
            );
            const raw_operation_start = complete_control_rows.len -
                prepared.operations.len;
            for (
                complete_control_rows[raw_operation_start..],
                prepared.operations,
            ) |actual, expected| {
                var non_terminal = expected;
                non_terminal.terminal_mask = 0;
                try std.testing.expectEqual(non_terminal, actual);
            }
            var retained_recursion_rows: usize = 0;
            for (plans.recursion.steps) |step|
                retained_recursion_rows += @intFromBool(
                    transcript_program.effect(step) == null,
                );
            try std.testing.expectEqual(
                plans.vm.steps.len +
                    temporal.CHILD_COUNT * retained_recursion_rows +
                    prepared.operations.len,
                complete_control_rows.len,
            );
            const complete_manifest = try prepared.manifestForPlans(
                &plans.vm,
                &plans.recursion,
            );
            try std.testing.expectEqual(
                @as(u32, @intCast(complete_control_rows.len)),
                complete_manifest.logical_rows[rowIndex(.control)],
            );

            const control_rows = try std.testing.allocator.alloc(
                TranscriptControlRow,
                operations.len,
            );
            defer std.testing.allocator.free(control_rows);
            const binding_rows = try std.testing.allocator.alloc(
                TranscriptBindingRowV2,
                rows.len,
            );
            defer std.testing.allocator.free(binding_rows);
            const state_rows = try std.testing.allocator.alloc(
                TranscriptStateRowV2,
                frames.len,
            );
            defer std.testing.allocator.free(state_rows);
            const provider_calls = try std.testing.allocator.alloc(
                TranscriptProviderCall,
                rows.len,
            );
            defer std.testing.allocator.free(provider_calls);
            const word_rows = try std.testing.allocator.alloc(
                TranscriptWordRowV2,
                try transcriptWordCount(frames),
            );
            defer std.testing.allocator.free(word_rows);
            const pow_checks = try std.testing.allocator.alloc(
                TemporalPowCheckRowV2,
                transcriptPowCount(frames),
            );
            defer std.testing.allocator.free(pow_checks);
            const pow_frames = try std.testing.allocator.alloc(
                TemporalPowFrameRowV2,
                transcriptPowCount(frames),
            );
            defer std.testing.allocator.free(pow_frames);
            const relation_rows = try std.testing.allocator.alloc(
                TemporalPackedRelationChallengeRowV2,
                transcriptRelationDrawCount(frames),
            );
            defer std.testing.allocator.free(relation_rows);
            const randomness_rows = try std.testing.allocator.alloc(
                TemporalVerifierRandomnessRowV2,
                transcriptRandomnessCount(frames),
            );
            defer std.testing.allocator.free(randomness_rows);
            const payload_rows = try std.testing.allocator.alloc(
                TemporalTranscriptPayloadRowV2,
                try transcriptPayloadCount(frames),
            );
            defer std.testing.allocator.free(payload_rows);

            control_rows[0].tag = 0x5a5a;
            try std.testing.expectError(
                error.DestinationLengthMismatch,
                prepared.fillControlRowsInto(control_rows[0 .. control_rows.len - 1]),
            );
            try std.testing.expectEqual(@as(u32, 0x5a5a), control_rows[0].tag);
            try prepared.fillControlRowsInto(control_rows);
            try prepared.fillBindingRowsInto(binding_rows);
            try prepared.fillStateRowsInto(state_rows);
            try prepared.fillWordRowsInto(word_rows);
            try prepared.fillPayloadRowsInto(payload_rows);
            try prepared.fillPowRowsInto(pow_checks, pow_frames);
            relation_rows[0].preprocessing.tag = 0x5a5a;
            try std.testing.expectError(
                error.DestinationLengthMismatch,
                prepared.fillRelationChallengeRowsInto(
                    relation_rows[0 .. relation_rows.len - 1],
                ),
            );
            try std.testing.expectEqual(
                @as(u32, 0x5a5a),
                relation_rows[0].preprocessing.tag,
            );
            try prepared.fillRelationChallengeRowsInto(relation_rows);
            try prepared.validateRelationChallengeRows(relation_rows);
            try prepared.fillRandomnessRowsInto(randomness_rows);
            try prepared.fillProviderCallsInto(provider_calls);
            try std.testing.expectEqual(
                transcript_air.LEFT_RECURSION_VERIFIER_ID,
                control_rows[0].verifier_id,
            );
            try std.testing.expectEqual(
                transcript_air.RIGHT_RECURSION_VERIFIER_ID,
                control_rows[left_operation_count].verifier_id,
            );
            try std.testing.expectEqual(rows[0].chunk, binding_rows[0].main.chunks);
            try std.testing.expectEqual(frames[0].input_digest, state_rows[0].main.inputs);
            try std.testing.expectEqual(rows[0].providerInput(), provider_calls[0].input);
            try std.testing.expectEqual(@as(u32, 1), word_rows[0].preprocessing.is_payload);
            try std.testing.expect(word_rows[0].value.eql(canonical[0]));
            try std.testing.expectEqual(@as(u32, 0), word_rows[3].preprocessing.is_payload);
            try std.testing.expectEqual(@as(u32, 1), word_rows[3].preprocessing.constant_value);
            try std.testing.expectEqual(
                TemporalPayloadSourceKindV2.commitment,
                payload_rows[0].source_kind,
            );
            try std.testing.expect(payload_rows[0].value.eql(canonical[0]));
            try std.testing.expectEqual(@as(usize, 1), pow_checks.len);
            try std.testing.expectEqual(pow_checks[0].call_id, pow_frames[0].call_id);
            try std.testing.expectEqual(
                @as(usize, temporal.CHILD_COUNT * CHILD_PACKED_RELATION_DRAW_COUNT),
                relation_rows.len,
            );
            try std.testing.expectEqual(@as(u32, 0), relation_rows[0].preprocessing.args[0]);
            try std.testing.expectEqual(
                @as(u32, packed_relation_challenge_v2.PACKING_FORMAT_VERSION),
                relation_rows[0].preprocessing.args[2],
            );
            try std.testing.expectEqual(
                frames[3].output_digest,
                relation_rows[0].main.outputs,
            );
            try std.testing.expectEqual(
                frames[left_frame_count + 1].output_digest,
                relation_rows[CHILD_PACKED_RELATION_DRAW_COUNT].main.outputs,
            );
            try std.testing.expectEqual(@as(usize, 1), randomness_rows.len);
            try std.testing.expectEqual(
                verifier_randomness.Kind.raw_query,
                randomness_rows[0].preprocessing.kind,
            );

            const manifest = try prepared.manifest();
            try manifest.validate();
            try std.testing.expectEqual(
                @as(u32, @intCast(relation_rows.len)),
                manifest.logical_rows[rowIndex(.packed_relation_challenge)],
            );
            try std.testing.expectEqual(
                @as(u64, 0x3ff),
                manifest.typed_row_mask,
            );
            var version_confusion = manifest;
            version_confusion.packed_row_format_version += 1;
            version_confusion.identity = transcriptManifestSha(&version_confusion);
            try std.testing.expectError(
                error.InvalidTranscriptManifest,
                version_confusion.validate(),
            );
            version_confusion = manifest;
            version_confusion.frozen_v1_compatible = true;
            version_confusion.identity = transcriptManifestSha(&version_confusion);
            try std.testing.expectError(
                error.InvalidTranscriptManifest,
                version_confusion.validate(),
            );

            // Row-8 source mutation fleet: exact limb order, draw multiplicity,
            // frame order, and the V2 protocol discriminator are all authoritative.
            relation_rows[0].main.outputs[0] = relation_rows[0].main.outputs[0].add(
                M31.one(),
            );
            try std.testing.expectError(
                error.InvalidPackedRelationChallengeRow,
                prepared.validateRelationChallengeRows(relation_rows),
            );
            relation_rows[0].main.outputs = frames[3].output_digest;

            std.mem.swap(M31, &relation_rows[0].main.outputs[0], &relation_rows[0].main.outputs[1]);
            try std.testing.expectError(
                error.InvalidPackedRelationChallengeRow,
                prepared.validateRelationChallengeRows(relation_rows),
            );
            std.mem.swap(M31, &relation_rows[0].main.outputs[0], &relation_rows[0].main.outputs[1]);

            relation_rows[1] = relation_rows[0];
            try std.testing.expectError(
                error.InvalidPackedRelationChallengeRow,
                prepared.validateRelationChallengeRows(relation_rows),
            );
            relation_rows[1] = relationRowForFrame(frames[4]);
            std.mem.swap(
                TemporalPackedRelationChallengeRowV2,
                &relation_rows[0],
                &relation_rows[1],
            );
            try std.testing.expectError(
                error.InvalidPackedRelationChallengeRow,
                prepared.validateRelationChallengeRows(relation_rows),
            );
            std.mem.swap(
                TemporalPackedRelationChallengeRowV2,
                &relation_rows[0],
                &relation_rows[1],
            );
            try std.testing.expectError(
                error.DestinationLengthMismatch,
                prepared.validateRelationChallengeRows(
                    relation_rows[0 .. relation_rows.len - 1],
                ),
            );

            relation_rows[0].preprocessing.args[1] = 1;
            try std.testing.expectError(
                error.InvalidPackedRelationChallengeRow,
                prepared.validateRelationChallengeRows(relation_rows),
            );
            relation_rows[0].preprocessing.args[1] =
                packed_relation_challenge_v2.CHALLENGES_PER_DRAW;
            relation_rows[0].preprocessing.args[2] += 1;
            try std.testing.expectError(
                error.InvalidPackedRelationChallengeRow,
                prepared.validateRelationChallengeRows(relation_rows),
            );
            relation_rows[0].preprocessing.args[2] =
                packed_relation_challenge_v2.PACKING_FORMAT_VERSION;
            try prepared.validateRelationChallengeRows(relation_rows);

            const saved_frame_4 = prepared.frames[4];
            prepared.frames[4] = prepared.frames[3];
            prepared.authority_sha_id = transcriptRowsAuthoritySha(&prepared);
            try std.testing.expectError(
                error.InvalidTranscriptRecorder,
                prepared.validate(),
            );
            prepared.frames[4] = saved_frame_4;
            prepared.authority_sha_id = transcriptRowsAuthoritySha(&prepared);
            std.mem.swap(RecordedFrameV2, &prepared.frames[3], &prepared.frames[4]);
            prepared.authority_sha_id = transcriptRowsAuthoritySha(&prepared);
            try std.testing.expectError(
                error.InvalidTranscriptRecorder,
                prepared.validate(),
            );
            std.mem.swap(RecordedFrameV2, &prepared.frames[3], &prepared.frames[4]);
            prepared.authority_sha_id = transcriptRowsAuthoritySha(&prepared);

            prepared.frames[3].args[2] += 1;
            prepared.operations[3].args[2] += 1;
            prepared.authority_sha_id = transcriptRowsAuthoritySha(&prepared);
            try std.testing.expectError(
                error.InvalidTranscriptRecorder,
                prepared.validate(),
            );
            prepared.frames[3].args[2] =
                packed_relation_challenge_v2.PACKING_FORMAT_VERSION;
            prepared.operations[3].args[2] =
                packed_relation_challenge_v2.PACKING_FORMAT_VERSION;
            prepared.authority_sha_id = transcriptRowsAuthoritySha(&prepared);
            try prepared.validate();

            const trace_length = @as(usize, 1) << @intCast(prepared.log_size);
            const main_storage = try std.testing.allocator.alloc(
                M31,
                transcript_air.MAIN_COLUMN_COUNT * trace_length,
            );
            defer std.testing.allocator.free(main_storage);
            var main_columns: [transcript_air.MAIN_COLUMN_COUNT][]M31 = undefined;
            for (&main_columns, 0..) |*column, index|
                column.* = main_storage[index * trace_length ..][0..trace_length];
            try prepared.fillMainInto(&main_columns);
            try std.testing.expect(main_columns[0][0].eql(M31.one()));
            try std.testing.expect(main_columns[0][rows.len].isZero());

            prepared.rows[0].call_id += 1;
            try std.testing.expectError(
                error.InvalidTranscriptRecorder,
                prepared.validate(),
            );
            prepared.rows[0].call_id -= 1;
            try prepared.validate();

            // The enclosing V3 commitment layout derives all 18 geometries from the
            // typed owners. In particular row 8 must carry the packed V2 semantic
            // identity and cannot be re-sealed with the frozen row-8 geometry.
            const domain_sha_ids = try prepared.relationDomainShaIds();
            try std.testing.expect(!std.mem.eql(
                u8,
                &domain_sha_ids[0],
                &domain_sha_ids[1],
            ));
            var prefix_logs: [PREFIX_ROW_COUNT]u32 = undefined;
            for (manifest.log_sizes, 0..) |log_size, row|
                prefix_logs[row] = log_size;
            prefix_logs[10] = statement_air.STATEMENT_INPUT_LOG_SIZE;
            prefix_logs[11] = statement_air.STATEMENT_SEMANTICS_LOG_SIZE;
            for (prefix_logs[12..]) |*log_size| log_size.* = 4;

            var parent_public = TemporalParentPublicV2{
                .parent_height = 1,
                .parent_node_index = 0,
                .pair_authority_id = prepared.pair_authority_id,
                .adjacency_id = .{61} ** channel.RATE,
                .context_id = .{62} ** channel.RATE,
                .node_id = .{63} ** channel.RATE,
                .record_id = .{64} ** channel.RATE,
                .session_id = .{65} ** channel.RATE,
                .job_id = .{66} ** channel.RATE,
                .aggregator_vk_id = .{67} ** channel.RATE,
                .child_kinds = .{ .segment_leaf, .segment_leaf },
                .child_ids = .{
                    .{68} ** channel.RATE,
                    .{69} ** channel.RATE,
                },
                .child_publication_ids = .{
                    prepared.child_replays[0].publication_id,
                    prepared.child_replays[1].publication_id,
                },
                .child_statement_ids = .{
                    .{70} ** channel.RATE,
                    .{71} ** channel.RATE,
                },
                .parent_statement_id = .{72} ** channel.RATE,
                .identity = undefined,
            };
            parent_public.identity = publicIdentity(&parent_public);
            try parent_public.validate();

            var rows_10_through_17 = Rows10Through17AuthorityV2{
                .statement_source_id = .{73} ** channel.RATE,
                .pair_authority_id = prepared.pair_authority_id,
                .inactive_source_sha_id = .{74} ** 32,
                .inactive_prepared_sha_id = .{75} ** 32,
                .authority_id = undefined,
            };
            rows_10_through_17.authority_id = rowAuthorityIdentity(
                &rows_10_through_17,
            );
            try rows_10_through_17.validate();

            const layout = try buildTemporalPrefixCommitmentLayout(
                prefix_logs,
                prepared.pair_authority_id,
                parent_public.identity,
                manifest.identity,
                rows_10_through_17.authority_id,
                prepared.child_replays,
                domain_sha_ids,
            );
            try layout.validate();
            try std.testing.expectEqual(
                @as(u64, 0x0003_ffff),
                layout.row_mask,
            );
            try std.testing.expectEqual(
                @as(u64, 0x0000_7fff_ffff_ffff),
                layout.relation_domain_mask,
            );
            try std.testing.expectEqualSlices(
                u8,
                &packed_relation_challenge_v2.SEMANTIC_DIGEST,
                &layout.placements[rowIndex(.packed_relation_challenge)]
                    .geometry.semantic_digest,
            );
            try std.testing.expectEqual(
                @as(u16, packed_relation_challenge_v2.PREPROCESSED_COLUMN_COUNT),
                layout.placements[rowIndex(.packed_relation_challenge)]
                    .geometry.preprocessed_columns,
            );

            var custody = TemporalRows0Through17CustodyV3{
                .parent_public = parent_public,
                .transcript_manifest = manifest,
                .rows_10_through_17 = rows_10_through_17,
                .child_replays = prepared.child_replays,
                .child_relation_domain_sha_ids = domain_sha_ids,
                .commitment_layout = layout,
                .custody_id = undefined,
            };
            custody.custody_id = prefixCustodyIdentity(&custody);
            try custody.validate();

            // Exact Tree0/Tree1/Tree2 storage is deterministic across independent
            // owners: column order, component offsets, trace lengths and every cell
            // participate in the pointer-free receipt.  These are storage receipts,
            // not a production-verification claim; the capability remains false.
            var tree_receipts: [PREFIX_TREE_COUNT]TemporalPrefixTreeReceiptV3 =
                undefined;
            for (&tree_receipts, 0..) |*saved_receipt, tree| {
                var first = try TestPrefixTreeStorage.init(
                    std.testing.allocator,
                    &layout,
                    tree,
                );
                defer first.deinit();
                var second = try TestPrefixTreeStorage.init(
                    std.testing.allocator,
                    &layout,
                    tree,
                );
                defer second.deinit();
                const seed: u32 = @intCast(101 + tree);
                first.fillDeterministic(seed);
                second.fillDeterministic(seed);
                const first_receipt = try prefixTreeReceipt(
                    &custody,
                    tree,
                    first.columns,
                );
                const second_receipt = try prefixTreeReceipt(
                    &custody,
                    tree,
                    second.columns,
                );
                try std.testing.expectEqual(first_receipt, second_receipt);
                try std.testing.expectEqualSlices(
                    u8,
                    &prefixTreeSha(&custody, tree, first.columns),
                    &prefixTreeSha(&custody, tree, second.columns),
                );
                saved_receipt.* = first_receipt;
            }

            // One-at-a-time boundary mutations: exact placement/layout, authenticated
            // relation domain, and ordered children must each fail independently.
            var shifted_layout = layout;
            shifted_layout.placements[1].main_offset += 1;
            shifted_layout.layout_sha_id = prefixLayoutSha(&shifted_layout);
            try std.testing.expectError(
                error.InvalidPrefixCommitmentLayout,
                shifted_layout.validate(),
            );
            var wrong_layout_receipt = tree_receipts[PREFIX_TREE1_INDEX];
            wrong_layout_receipt.layout_sha_id[0] ^= 1;
            wrong_layout_receipt.identity = prefixTreeReceiptSha(
                &wrong_layout_receipt,
            );
            try std.testing.expectError(
                error.InvalidPrefixTreeReceipt,
                wrong_layout_receipt.validate(&custody),
            );
            var wrong_domain_custody = custody;
            wrong_domain_custody.child_relation_domain_sha_ids[0][0] ^= 1;
            wrong_domain_custody.custody_id = prefixCustodyIdentity(
                &wrong_domain_custody,
            );
            try std.testing.expectError(
                error.SourceIdentityMismatch,
                tree_receipts[PREFIX_TREE2_INDEX].validate(&wrong_domain_custody),
            );

            var frozen_row_8 = layout;
            frozen_row_8.placements[rowIndex(.packed_relation_challenge)]
                .geometry.semantic_digest = recursion.air.relation_challenge
                .SEMANTIC_DIGEST;
            frozen_row_8.layout_sha_id = prefixLayoutSha(&frozen_row_8);
            try std.testing.expectError(
                error.InvalidPrefixCommitmentLayout,
                frozen_row_8.validate(),
            );
            var wrong_registry = layout;
            wrong_registry.relation_registry_sha_id[0] ^= 1;
            wrong_registry.layout_sha_id = prefixLayoutSha(&wrong_registry);
            try std.testing.expectError(
                error.InvalidPrefixCommitmentLayout,
                wrong_registry.validate(),
            );
            var frozen_payload_layout = layout;
            frozen_payload_layout.temporal_payload_authority_sha_id =
                transcript_payload.SEMANTIC_DIGEST;
            frozen_payload_layout.layout_sha_id = prefixLayoutSha(
                &frozen_payload_layout,
            );
            try std.testing.expectError(
                error.InvalidPrefixCommitmentLayout,
                frozen_payload_layout.validate(),
            );
            var duplicate_domains = layout;
            duplicate_domains.child_relation_domain_sha_ids[1] =
                duplicate_domains.child_relation_domain_sha_ids[0];
            duplicate_domains.layout_sha_id = prefixLayoutSha(&duplicate_domains);
            try std.testing.expectError(error.DuplicateChild, duplicate_domains.validate());

            var swapped = custody;
            std.mem.swap(
                TemporalChildTranscriptReplayV2,
                &swapped.child_replays[0],
                &swapped.child_replays[1],
            );
            swapped.custody_id = prefixCustodyIdentity(&swapped);
            try std.testing.expectError(error.SourceIdentityMismatch, swapped.validate());
            try std.testing.expectError(
                error.SourceIdentityMismatch,
                tree_receipts[PREFIX_TREE0_INDEX].validate(&swapped),
            );
            var omitted = custody;
            omitted.child_replays[1].replay_id = .{0} ** channel.RATE;
            omitted.custody_id = prefixCustodyIdentity(&omitted);
            try std.testing.expectError(error.InvalidPublicRecord, omitted.validate());
            var cross_session = custody;
            cross_session.parent_public.session_id[0] +%= 1;
            try std.testing.expectError(
                error.InvalidPublicRecord,
                cross_session.validate(),
            );
            var cross_statement = custody;
            cross_statement.parent_public.child_statement_ids[1][0] +%= 1;
            try std.testing.expectError(
                error.InvalidPublicRecord,
                cross_statement.validate(),
            );
        }
    };
}
