//! Cohesive internal authority extracted from recursive_temporal_nonfri_source_v2.zig.

pub fn Namespace(comptime context: type) type {
    return struct {
        const std = context.d_std;
        const M31 = context.d_M31;
        const QM31 = context.d_QM31;
        const m31 = context.d_m31;
        const recursion = context.d_recursion;
        const channel = context.d_channel;
        const cohort_protocol = context.d_cohort_protocol;
        const manifest_mod = context.d_manifest_mod;
        const statement_air = context.d_statement_air;
        const span_statement = context.d_span_statement;
        const temporal = context.d_temporal;
        const transcript_air = context.d_transcript_air;
        const transcript_control = context.d_transcript_control;
        const relation_challenge = context.d_relation_challenge;
        const packed_relation_challenge_v2 = context.d_packed_relation_challenge_v2;
        const Digest = context.d_Digest;
        const FIRST_IMPLEMENTED_ROW = context.d_FIRST_IMPLEMENTED_ROW;
        const LAST_IMPLEMENTED_ROW = context.d_LAST_IMPLEMENTED_ROW;
        const IMPLEMENTED_ROW_COUNT = context.d_IMPLEMENTED_ROW_COUNT;
        const TRANSCRIPT_ROW_COUNT = context.d_TRANSCRIPT_ROW_COUNT;
        const IMPLEMENTED_ROW_MASK = context.d_IMPLEMENTED_ROW_MASK;
        const TRANSCRIPT_ROW_MASK = context.d_TRANSCRIPT_ROW_MASK;
        const HEAP_ALLOCATIONS_PER_ROW_AUTHORITY = context.d_HEAP_ALLOCATIONS_PER_ROW_AUTHORITY;
        const CALLER_AUTHORED_CLAIMS_ACCEPTED = context.d_CALLER_AUTHORED_CLAIMS_ACCEPTED;
        const FROZEN_SPLIT_ROLE_ADAPTER_USED = context.d_FROZEN_SPLIT_ROLE_ADAPTER_USED;
        const ROWS_10_THROUGH_17_AVAILABLE = context.d_ROWS_10_THROUGH_17_AVAILABLE;
        const ROWS_0_THROUGH_9_AVAILABLE = context.d_ROWS_0_THROUGH_9_AVAILABLE;
        const ROWS_0_THROUGH_9_EXACT_REPLAY_AVAILABLE = context.d_ROWS_0_THROUGH_9_EXACT_REPLAY_AVAILABLE;
        const ROWS_0_THROUGH_9_TYPED_AIR_AVAILABLE = context.d_ROWS_0_THROUGH_9_TYPED_AIR_AVAILABLE;
        const ROWS_0_THROUGH_9_EXTENDED_MANIFEST_AVAILABLE = context.d_ROWS_0_THROUGH_9_EXTENDED_MANIFEST_AVAILABLE;
        const ROWS_0_THROUGH_17_COMMITMENT_LAYOUT_AVAILABLE = context.d_ROWS_0_THROUGH_17_COMMITMENT_LAYOUT_AVAILABLE;
        const ROWS_0_THROUGH_17_RELATION_DOMAIN_CUSTODY_AVAILABLE = context.d_ROWS_0_THROUGH_17_RELATION_DOMAIN_CUSTODY_AVAILABLE;
        const ROWS_0_THROUGH_17_TREE_WRITER_AVAILABLE = context.d_ROWS_0_THROUGH_17_TREE_WRITER_AVAILABLE;
        const TRANSCRIPT_ROW_1_TYPED_AIR_AVAILABLE = context.d_TRANSCRIPT_ROW_1_TYPED_AIR_AVAILABLE;
        const TRANSCRIPT_POSEIDON_PROVIDER_AVAILABLE = context.d_TRANSCRIPT_POSEIDON_PROVIDER_AVAILABLE;
        const TRANSCRIPT_ROWS_0_THROUGH_3_TYPED_AIR_AVAILABLE = context.d_TRANSCRIPT_ROWS_0_THROUGH_3_TYPED_AIR_AVAILABLE;
        const TRANSCRIPT_ROWS_0_THROUGH_4_TYPED_AIR_AVAILABLE = context.d_TRANSCRIPT_ROWS_0_THROUGH_4_TYPED_AIR_AVAILABLE;
        const TRANSCRIPT_ROWS_0_THROUGH_7_TYPED_AIR_AVAILABLE = context.d_TRANSCRIPT_ROWS_0_THROUGH_7_TYPED_AIR_AVAILABLE;
        const TRANSCRIPT_ROWS_6_7_9_TYPED_AIR_AVAILABLE = context.d_TRANSCRIPT_ROWS_6_7_9_TYPED_AIR_AVAILABLE;
        const TRANSCRIPT_ROW_8_PACKED_V2_TYPED_AIR_AVAILABLE = context.d_TRANSCRIPT_ROW_8_PACKED_V2_TYPED_AIR_AVAILABLE;
        const TYPED_TRANSCRIPT_ROW_MASK = context.d_TYPED_TRANSCRIPT_ROW_MASK;
        const CHILD_QUERY_COUNT = context.d_CHILD_QUERY_COUNT;
        const CHILD_COMMITMENT_COUNT = context.d_CHILD_COMMITMENT_COUNT;
        const CHILD_RELATION_DRAW_COUNT = context.d_CHILD_RELATION_DRAW_COUNT;
        const CHILD_PACKED_RELATION_DRAW_COUNT = context.d_CHILD_PACKED_RELATION_DRAW_COUNT;
        const TRANSCRIPT_ROWS_AUTHORITY_DOMAIN = context.d_TRANSCRIPT_ROWS_AUTHORITY_DOMAIN;
        const TRANSCRIPT_MANIFEST_AUTHORITY_DOMAIN = context.d_TRANSCRIPT_MANIFEST_AUTHORITY_DOMAIN;
        const PREFIX_ROW_COUNT = context.d_PREFIX_ROW_COUNT;
        const PREFIX_ROW_MASK = context.d_PREFIX_ROW_MASK;
        const PREFIX_TYPED_ROW_MASK = context.d_PREFIX_TYPED_ROW_MASK;
        const RELATION_DOMAIN_COUNT = context.d_RELATION_DOMAIN_COUNT;
        const EXACT_PREFIX_RELATION_DOMAIN_MASK = context.d_EXACT_PREFIX_RELATION_DOMAIN_MASK;
        const TEMPORAL_PAYLOAD_SOURCE_KIND_COUNT = context.d_TEMPORAL_PAYLOAD_SOURCE_KIND_COUNT;
        const TEMPORAL_PAYLOAD_PUBLIC_GEOMETRY_KIND = context.d_TEMPORAL_PAYLOAD_PUBLIC_GEOMETRY_KIND;
        const TEMPORAL_PAYLOAD_RELATION_DOMAIN_MASK = context.d_TEMPORAL_PAYLOAD_RELATION_DOMAIN_MASK;
        const TranscriptAirRow = context.d_TranscriptAirRow;
        const TranscriptControlRow = context.d_TranscriptControlRow;
        const TemporalTranscriptRowV2 = context.d_TemporalTranscriptRowV2;
        const TemporalTranscriptManifestV2 = context.d_TemporalTranscriptManifestV2;
        const TemporalPayloadAuthorityV2 = context.d_TemporalPayloadAuthorityV2;
        const TemporalPrefixCommitmentLayoutV3 = context.d_TemporalPrefixCommitmentLayoutV3;
        const Error = context.d_Error;
        const TranscriptPrefixRequirementsV1 = context.d_TranscriptPrefixRequirementsV1;
        const TemporalChildTranscriptReplayV2 = context.d_TemporalChildTranscriptReplayV2;
        const TemporalTranscriptOperationTag = context.d_TemporalTranscriptOperationTag;
        const RecordedFrameV2 = context.d_RecordedFrameV2;
        const PreparedTranscriptRowsV2 = context.d_PreparedTranscriptRowsV2;
        const TemporalParentPublicV2 = context.d_TemporalParentPublicV2;
        const PreparedRows10Through11V2 = context.d_PreparedRows10Through11V2;
        const Rows10Through17AuthorityV2 = context.d_Rows10Through17AuthorityV2;
        const TemporalRows0Through17CustodyV3 = context.d_TemporalRows0Through17CustodyV3;
        const TemporalPrefixTreeReceiptV3 = context.d_TemporalPrefixTreeReceiptV3;
        const TemporalPrefixInteractionsV3 = context.d_TemporalPrefixInteractionsV3;
        const TemporalPrefixDomainAuditsV3 = context.d_TemporalPrefixDomainAuditsV3;
        const transcriptWordCount = context.d_transcriptWordCount;
        const transcriptPayloadCount = context.d_transcriptPayloadCount;
        const validatePackedRelationFrameSchedule = context.d_validatePackedRelationFrameSchedule;

        pub fn validateTranscriptRowsV2(
            source: *const PreparedTranscriptRowsV2,
        ) Error!void {
            try validateTranscriptRecording(
                source.rows,
                source.operations,
                source.frames,
                source.lane_row_counts,
                source.lane_operation_counts,
                source.lane_frame_counts,
            );
            try validatePackedRelationFrameSchedule(
                source.frames,
                source.lane_frame_counts,
            );
            var frame_at: usize = 0;
            inline for (0..temporal.CHILD_COUNT) |lane| {
                const frame_end = frame_at + source.lane_frame_counts[lane];
                if (source.lane_word_counts[lane] !=
                    try transcriptWordCount(source.frames[frame_at..frame_end]) or
                    source.lane_payload_counts[lane] !=
                        try transcriptPayloadCount(source.frames[frame_at..frame_end]))
                {
                    return error.InvalidTranscriptRecorder;
                }
                frame_at = frame_end;
            }
        }

        pub fn validateTranscriptRecording(
            rows: []const TranscriptAirRow,
            operations: []const TranscriptControlRow,
            frames: []const RecordedFrameV2,
            lane_row_counts: [temporal.CHILD_COUNT]usize,
            lane_operation_counts: [temporal.CHILD_COUNT]usize,
            lane_frame_counts: [temporal.CHILD_COUNT]usize,
        ) Error!void {
            var lane_start: usize = 0;
            var operation_start: usize = 0;
            var frame_start: usize = 0;
            inline for (0..temporal.CHILD_COUNT) |lane| {
                const lane_count = lane_row_counts[lane];
                const operation_count = lane_operation_counts[lane];
                const frame_count = lane_frame_counts[lane];
                const lane_end = std.math.add(
                    usize,
                    lane_start,
                    lane_count,
                ) catch return error.ArithmeticOverflow;
                const operation_end = std.math.add(
                    usize,
                    operation_start,
                    operation_count,
                ) catch return error.ArithmeticOverflow;
                const frame_end = std.math.add(
                    usize,
                    frame_start,
                    frame_count,
                ) catch return error.ArithmeticOverflow;
                if (lane_count == 0 or operation_count == 0 or frame_count == 0 or
                    lane_end > rows.len or operation_end > operations.len or
                    frame_end > frames.len)
                {
                    return error.InvalidTranscriptRecorder;
                }
                const verifier_id = if (lane == 0)
                    transcript_air.LEFT_RECURSION_VERIFIER_ID
                else
                    transcript_air.RIGHT_RECURSION_VERIFIER_ID;
                const lane_operations = operations[operation_start..operation_end];
                for (lane_operations, 0..) |operation, sequence| {
                    _ = transcript_control.logicalRow(operation, .binary_node);
                    if (operation.segment_mask != 0 or operation.binary_mask != 1 or
                        operation.verifier_id != verifier_id or
                        operation.sequence != sequence or operation.tag == 0 or
                        operation.tag > @intFromEnum(TemporalTranscriptOperationTag.query_draw) or
                        operation.terminal_mask != @intFromBool(
                            sequence + 1 == operation_count,
                        ))
                    {
                        return error.InvalidTranscriptRecorder;
                    }
                    for (operation.args) |arg| if (arg >= m31.Modulus)
                        return error.InvalidTranscriptRecorder;
                }
                for (rows[lane_start..lane_end], 0..) |row, local_call| {
                    _ = try transcript_air.logicalRow(row);
                    if (row.verifier_id != verifier_id or
                        row.call_id != local_call)
                    {
                        return error.InvalidTranscriptRecorder;
                    }
                    const first = local_call == 0 or row.step == 0;
                    if (first != (row.is_first == 1))
                        return error.InvalidTranscriptRecorder;
                    if (local_call == 0) {
                        if (row.hash_id != 0 or row.step != 0 or
                            !allM31Zero(&row.previous))
                        {
                            return error.InvalidTranscriptRecorder;
                        }
                    } else {
                        const previous = rows[lane_start + local_call - 1];
                        if (row.step == 0) {
                            if (row.hash_id != previous.hash_id + 1 or
                                !allM31Zero(&row.previous))
                            {
                                return error.InvalidTranscriptRecorder;
                            }
                        } else if (row.hash_id != previous.hash_id or
                            row.step != previous.step + 1 or
                            row.is_draw != previous.is_draw or
                            !m31SlicesEql(&row.previous, &previous.output))
                        {
                            return error.InvalidTranscriptRecorder;
                        }
                    }
                    const expected_last = local_call + 1 == lane_count or
                        rows[lane_start + local_call + 1].hash_id != row.hash_id;
                    if (expected_last != (row.is_last == 1))
                        return error.InvalidTranscriptRecorder;
                }
                const lane_frames = frames[frame_start..frame_end];
                var next_call: usize = 0;
                var next_sequence: u32 = 0;
                var mix_ordinal: u32 = 0;
                for (lane_frames, 0..) |frame, local_frame| {
                    if (frame.verifier_id != verifier_id or
                        frame.hash_id != local_frame or
                        frame.first_call_id != next_call or frame.call_count == 0 or
                        frame.sequence >= operation_count or
                        frame.payload_word_count >= m31.Modulus)
                    {
                        return error.InvalidTranscriptRecorder;
                    }
                    const expected_call_count = std.math.divCeil(
                        usize,
                        channel.RATE + @as(usize, frame.payload_word_count) + 1,
                        channel.RATE,
                    ) catch return error.ArithmeticOverflow;
                    if (frame.call_count != expected_call_count)
                        return error.InvalidTranscriptRecorder;
                    const operation = lane_operations[frame.sequence];
                    if (frame.tag != operation.tag or
                        !std.meta.eql(frame.args, operation.args) or
                        (local_frame == 0 and frame.sequence != 0) or
                        frame.sequence < next_sequence or frame.sequence > next_sequence + 1)
                    {
                        return error.InvalidTranscriptRecorder;
                    }
                    if (frame.sequence == next_sequence + 1)
                        next_sequence = frame.sequence;
                    const call_end = std.math.add(
                        usize,
                        next_call,
                        frame.call_count,
                    ) catch return error.ArithmeticOverflow;
                    if (call_end > lane_count) return error.InvalidTranscriptRecorder;
                    const first_call = rows[lane_start + next_call];
                    const last_call = rows[lane_start + call_end - 1];
                    const is_draw = frame.purpose == .draw;
                    if (first_call.is_first != 1 or last_call.is_last != 1 or
                        (first_call.is_draw == 1) != is_draw or
                        (last_call.is_draw == 1) != is_draw or
                        frame.pow_draw and (!is_draw or
                            frame.tag != @intFromEnum(
                                TemporalTranscriptOperationTag.verify_pow,
                            )) or
                        !m31SlicesEql(&frame.input_digest, &first_call.chunk) or
                        !m31SlicesEql(
                            &frame.output_digest,
                            last_call.output[0..channel.RATE],
                        ))
                    {
                        return error.InvalidTranscriptRecorder;
                    }
                    if (frame.purpose == .mix) {
                        var consumers: u32 = 0;
                        for (lane_frames[local_frame + 1 ..]) |following| {
                            consumers += 1;
                            if (following.purpose == .mix) break;
                        }
                        if (frame.input_state_key != mix_ordinal or
                            frame.output_state_key != mix_ordinal + 1 or
                            frame.initial_mask != @intFromBool(mix_ordinal == 0) or
                            frame.state_consume_mask != @intFromBool(mix_ordinal > 0) or
                            frame.state_produce_multiplicity != consumers or
                            frame.draw_output_mask != 0)
                        {
                            return error.InvalidTranscriptRecorder;
                        }
                        mix_ordinal += 1;
                    } else if (mix_ordinal == 0 or
                        frame.input_state_key != mix_ordinal or
                        frame.output_state_key != mix_ordinal or
                        frame.initial_mask != 0 or frame.state_consume_mask != 1 or
                        frame.state_produce_multiplicity != 0 or
                        frame.draw_output_mask != @intFromBool(!frame.pow_draw))
                    {
                        return error.InvalidTranscriptRecorder;
                    }
                    next_call = call_end;
                }
                if (next_call != lane_count or next_sequence + 1 != operation_count)
                    return error.InvalidTranscriptRecorder;
                lane_start = lane_end;
                operation_start = operation_end;
                frame_start = frame_end;
            }
            if (lane_start != rows.len or operation_start != operations.len or
                frame_start != frames.len)
            {
                return error.InvalidTranscriptRecorder;
            }
        }

        pub fn transcriptRowsAuthoritySha(
            value: *const PreparedTranscriptRowsV2,
        ) [32]u8 {
            var hash = std.crypto.hash.sha2.Sha256.init(.{});
            hash.update(TRANSCRIPT_ROWS_AUTHORITY_DOMAIN);
            shaInt(&hash, u16, value.format_version);
            shaInt(&hash, u16, value.schema_version);
            shaInt(&hash, u8, value.lane_count);
            shaInt(&hash, u32, value.log_size);
            for (value.pair_authority_id) |word| shaInt(&hash, u32, word);
            for (value.lane_row_counts) |count| shaInt(&hash, u64, count);
            for (value.lane_operation_counts) |count| shaInt(&hash, u64, count);
            for (value.lane_frame_counts) |count| shaInt(&hash, u64, count);
            for (value.lane_word_counts) |count| shaInt(&hash, u64, count);
            for (value.lane_payload_counts) |count| shaInt(&hash, u64, count);
            for (value.lane_claim_counts) |count| shaInt(&hash, u32, count);
            for (value.child_replays) |replay|
                for (replay.replay_id) |word| shaInt(&hash, u32, word);
            shaInt(&hash, u64, value.rows.len);
            for (value.rows) |row| {
                shaInt(&hash, u32, row.enabler);
                shaInt(&hash, u32, row.verifier_id);
                shaInt(&hash, u32, row.call_id);
                shaInt(&hash, u32, row.hash_id);
                shaInt(&hash, u32, row.step);
                shaInt(&hash, u32, row.is_first);
                shaInt(&hash, u32, row.is_last);
                shaInt(&hash, u32, row.is_draw);
                for (row.previous) |word| shaInt(&hash, u32, word.toU32());
                for (row.chunk) |word| shaInt(&hash, u32, word.toU32());
                for (row.output) |word| shaInt(&hash, u32, word.toU32());
            }
            shaInt(&hash, u64, value.operations.len);
            for (value.operations) |operation| {
                shaInt(&hash, u32, operation.segment_mask);
                shaInt(&hash, u32, operation.binary_mask);
                shaInt(&hash, u32, operation.verifier_id);
                shaInt(&hash, u32, operation.sequence);
                shaInt(&hash, u32, operation.tag);
                for (operation.args) |arg| shaInt(&hash, u32, arg);
                shaInt(&hash, u32, operation.terminal_mask);
            }
            shaInt(&hash, u64, value.frames.len);
            for (value.frames) |frame| {
                shaInt(&hash, u32, frame.verifier_id);
                shaInt(&hash, u32, frame.sequence);
                shaInt(&hash, u32, frame.tag);
                for (frame.args) |arg| shaInt(&hash, u32, arg);
                shaInt(&hash, u32, frame.hash_id);
                shaInt(&hash, u32, frame.first_call_id);
                shaInt(&hash, u32, frame.call_count);
                shaInt(&hash, u32, frame.payload_word_count);
                shaInt(&hash, u32, @intFromEnum(frame.purpose));
                shaInt(&hash, u8, @intFromBool(frame.pow_draw));
                for (frame.input_digest) |word| shaInt(&hash, u32, word.toU32());
                for (frame.output_digest) |word| shaInt(&hash, u32, word.toU32());
                shaInt(&hash, u32, frame.input_state_key);
                shaInt(&hash, u32, frame.output_state_key);
                shaInt(&hash, u32, frame.initial_mask);
                shaInt(&hash, u32, frame.state_consume_mask);
                shaInt(&hash, u32, frame.state_produce_multiplicity);
                shaInt(&hash, u32, frame.draw_output_mask);
            }
            return hash.finalResult();
        }

        pub fn transcriptManifestSha(
            value: *const TemporalTranscriptManifestV2,
        ) [32]u8 {
            var hash = std.crypto.hash.sha2.Sha256.init(.{});
            hash.update(TRANSCRIPT_MANIFEST_AUTHORITY_DOMAIN);
            shaInt(&hash, u16, value.format_version);
            shaInt(&hash, u16, value.schema_version);
            shaInt(&hash, u8, @intFromBool(value.frozen_v1_compatible));
            shaInt(&hash, u8, value.row_count);
            shaInt(&hash, u64, value.row_mask);
            shaInt(&hash, u64, value.typed_row_mask);
            shaInt(&hash, u32, value.packed_row_format_version);
            shaInt(&hash, u8, value.challenges_per_draw);
            shaInt(&hash, u8, value.limbs_per_challenge);
            for (value.logical_rows) |count| shaInt(&hash, u32, count);
            for (value.log_sizes) |log_size| shaInt(&hash, u8, log_size);
            for (value.pair_authority_id) |word| shaInt(&hash, u32, word);
            hash.update(&value.transcript_rows_authority_sha_id);
            hash.update(&value.packed_row_semantic_digest);
            return hash.finalResult();
        }

        pub fn rowIndex(row: TemporalTranscriptRowV2) usize {
            return @intFromEnum(row);
        }

        pub fn validateTranscriptDestinations(
            columns: *const [transcript_air.MAIN_COLUMN_COUNT][]M31,
            trace_length: usize,
            source: *const PreparedTranscriptRowsV2,
        ) Error!void {
            const source_ranges = [_]ByteRange{
                try objectRange(source),
                try byteRange(source.rows),
                try byteRange(source.operations),
                try byteRange(source.frames),
            };
            var destination_ranges: [transcript_air.MAIN_COLUMN_COUNT]ByteRange =
                undefined;
            for (columns, &destination_ranges, 0..) |column, *range, index| {
                if (column.len != trace_length)
                    return error.DestinationLengthMismatch;
                range.* = try byteRange(column);
                for (destination_ranges[0..index]) |prior|
                    if (range.overlaps(prior)) return error.AliasedDestination;
                for (source_ranges) |source_range|
                    if (range.overlaps(source_range)) return error.AliasedDestination;
            }
        }

        pub fn validateTypedRowDestination(
            destination: anytype,
            expected_length: usize,
            source: *const PreparedTranscriptRowsV2,
        ) Error!void {
            if (destination.len != expected_length)
                return error.DestinationLengthMismatch;
            const output = try byteRange(destination);
            inline for (.{
                try objectRange(source),
                try byteRange(source.rows),
                try byteRange(source.operations),
                try byteRange(source.frames),
            }) |input| if (output.overlaps(input)) return error.AliasedDestination;
        }

        pub fn validateTwoTypedDestinations(
            first: anytype,
            second: anytype,
            expected_length: usize,
            source: *const PreparedTranscriptRowsV2,
        ) Error!void {
            try validateTypedRowDestination(first, expected_length, source);
            try validateTypedRowDestination(second, expected_length, source);
            if ((try byteRange(first)).overlaps(try byteRange(second)))
                return error.AliasedDestination;
        }

        pub fn shaInt(hash: anytype, comptime T: type, value: anytype) void {
            var bytes: [@sizeOf(T)]u8 = undefined;
            std.mem.writeInt(T, &bytes, @intCast(value), .little);
            hash.update(&bytes);
        }

        pub const IdentityHasher = struct {
            inner: channel.CanonicalWordHasher,

            pub fn init(domain: u32) IdentityHasher {
                return .{ .inner = channel.CanonicalWordHasher.init(domain) };
            }

            pub fn addU32(self: *IdentityHasher, value: anytype) void {
                const exact: u32 = @intCast(value);
                std.debug.assert(exact < m31.Modulus);
                self.inner.update(&.{M31.fromCanonical(exact)});
            }

            pub fn addU64(self: *IdentityHasher, value: u64) void {
                self.addU32(@as(u32, @truncate(value & 0xffff)));
                self.addU32(@as(u32, @truncate((value >> 16) & 0xffff)));
                self.addU32(@as(u32, @truncate((value >> 32) & 0xffff)));
                self.addU32(@as(u32, @truncate(value >> 48)));
            }

            pub fn digest(self: *IdentityHasher, value: Digest) void {
                for (value) |word| self.addU32(word);
            }

            pub fn words(self: *IdentityHasher, value: []const M31) void {
                self.inner.update(value);
            }

            pub fn qm31(self: *IdentityHasher, value: QM31) void {
                self.words(&value.toM31Array());
            }

            pub fn sha(self: *IdentityHasher, value: [32]u8) void {
                self.addU32(value.len);
                var index: usize = 0;
                while (index < value.len) : (index += 2) {
                    self.addU32(@as(u32, value[index]) |
                        (@as(u32, value[index + 1]) << 8));
                }
            }

            pub fn finalize(self: *IdentityHasher) Digest {
                return self.inner.finalize();
            }
        };

        pub fn statementId(words: *const span_statement.StatementWords) Error!Digest {
            _ = try span_statement.SpanStatement.fromCanonicalWords(words);
            var canonical: [span_statement.SPAN_STATEMENT_CANONICAL_WORDS]u32 =
                undefined;
            for (words, &canonical) |word, *destination|
                destination.* = word.toU32();
            return recursion.protocol.statementId(&canonical);
        }

        pub fn baseInputs(inputs: []const QM31, destination: []M31) Error!void {
            if (inputs.len != destination.len) return error.SourceIdentityMismatch;
            for (inputs, destination) |input, *output| {
                const words = input.toM31Array();
                if (!words[1].isZero() or !words[2].isZero() or !words[3].isZero())
                    return error.NonBaseCircuitInput;
                output.* = words[0];
            }
        }

        pub fn rejectWorkspaceAliases(
            prepared: *const PreparedRows10Through11V2,
            workspace: *const statement_air.Workspace,
        ) Error!void {
            const destinations = [_]ByteRange{
                try byteRange(workspace.logical_storage),
                try byteRange(workspace.secure_storage),
                try byteRange(workspace.range.counter.values),
            };
            const sources = [_]ByteRange{
                try objectRange(prepared),
                try byteRange(prepared.statement_values),
                try byteRange(prepared.circuit_evaluation.storage),
                try byteRange(prepared.range.provider().counter.values),
            };
            for (destinations, 0..) |destination, index| {
                for (destinations[0..index]) |prior|
                    if (destination.overlaps(prior)) return error.SourceIdentityMismatch;
                for (sources) |source|
                    if (destination.overlaps(source)) return error.SourceIdentityMismatch;
            }
        }

        pub const ByteRange = struct {
            start: usize,
            end: usize,

            pub fn overlaps(self: ByteRange, other: ByteRange) bool {
                return self.start < other.end and other.start < self.end;
            }
        };

        pub fn objectRange(value: anytype) Error!ByteRange {
            return byteRange(std.mem.asBytes(value));
        }

        pub fn byteRange(values: anytype) Error!ByteRange {
            const bytes = std.mem.sliceAsBytes(values);
            const start = @intFromPtr(bytes.ptr);
            return .{
                .start = start,
                .end = std.math.add(usize, start, bytes.len) catch
                    return error.SourceIdentityMismatch,
            };
        }

        pub fn metaSlicesEql(
            comptime T: type,
            left: []const T,
            right: []const T,
        ) bool {
            if (left.len != right.len) return false;
            for (left, right) |a, b| if (!std.meta.eql(a, b)) return false;
            return true;
        }

        pub fn m31SlicesEql(left: []const M31, right: []const M31) bool {
            if (left.len != right.len) return false;
            for (left, right) |a, b| if (!a.eql(b)) return false;
            return true;
        }

        pub fn secureSlicesEql(left: []const QM31, right: []const QM31) bool {
            if (left.len != right.len) return false;
            for (left, right) |a, b| if (!a.eql(b)) return false;
            return true;
        }

        pub fn requireDigest(value: Digest) Error!void {
            var aggregate: u32 = 0;
            for (value) |word| {
                if (word >= m31.Modulus) return error.InvalidPublicRecord;
                aggregate |= word;
            }
            if (aggregate == 0) return error.InvalidPublicRecord;
        }

        pub fn requireSha(value: [32]u8) Error!void {
            if (std.mem.allEqual(u8, &value, 0)) return error.InvalidPublicRecord;
        }

        pub fn requireCanonical(value: QM31) Error!void {
            for (value.toM31Array()) |word|
                if (word.toU32() >= m31.Modulus) return error.InvalidPublicRecord;
        }

        pub fn allZero(bytes: []const u8) bool {
            return std.mem.allEqual(u8, bytes, 0);
        }

        pub fn allM31Zero(words: []const M31) bool {
            for (words) |word| if (!word.isZero()) return false;
            return true;
        }

        pub fn domainBit(index: u6) u64 {
            return @as(u64, 1) << index;
        }

        pub fn rangeMask(first: usize, count: usize) u64 {
            std.debug.assert(count > 0 and first + count <= 64);
            return ((@as(u64, 1) << @intCast(count)) - 1) << @intCast(first);
        }

        pub fn assertPointerFree(comptime T: type) void {
            switch (@typeInfo(T)) {
                .pointer, .optional => @compileError("temporal row authority retains a pointer"),
                .array => |array| assertPointerFree(array.child),
                .@"struct" => |info| inline for (info.fields) |field|
                    assertPointerFree(field.type),
                .@"union" => |info| inline for (info.fields) |field|
                    assertPointerFree(field.type),
                else => {},
            }
        }

        comptime {
            if (FIRST_IMPLEMENTED_ROW != 10 or LAST_IMPLEMENTED_ROW != 17 or
                IMPLEMENTED_ROW_COUNT != 8 or TRANSCRIPT_ROW_COUNT != 10 or
                IMPLEMENTED_ROW_MASK != 0x0003_fc00 or
                TRANSCRIPT_ROW_MASK != 0x0000_03ff or
                HEAP_ALLOCATIONS_PER_ROW_AUTHORITY != 0 or
                CALLER_AUTHORED_CLAIMS_ACCEPTED or FROZEN_SPLIT_ROLE_ADAPTER_USED or
                !ROWS_10_THROUGH_17_AVAILABLE or !ROWS_0_THROUGH_9_AVAILABLE or
                !ROWS_0_THROUGH_9_EXACT_REPLAY_AVAILABLE or
                !ROWS_0_THROUGH_9_TYPED_AIR_AVAILABLE or
                !ROWS_0_THROUGH_9_EXTENDED_MANIFEST_AVAILABLE or
                !ROWS_0_THROUGH_17_COMMITMENT_LAYOUT_AVAILABLE or
                !ROWS_0_THROUGH_17_RELATION_DOMAIN_CUSTODY_AVAILABLE or
                ROWS_0_THROUGH_17_TREE_WRITER_AVAILABLE or
                PREFIX_ROW_COUNT != 18 or PREFIX_ROW_MASK != 0x0003_ffff or
                PREFIX_TYPED_ROW_MASK != PREFIX_ROW_MASK or
                RELATION_DOMAIN_COUNT != 47 or
                EXACT_PREFIX_RELATION_DOMAIN_MASK != 0x0000_7fff_ffff_ffff or
                TEMPORAL_PAYLOAD_SOURCE_KIND_COUNT != 13 or
                TEMPORAL_PAYLOAD_PUBLIC_GEOMETRY_KIND != 13 or
                TEMPORAL_PAYLOAD_RELATION_DOMAIN_MASK != 0x0300_0000 or
                !TRANSCRIPT_ROW_1_TYPED_AIR_AVAILABLE or
                !TRANSCRIPT_POSEIDON_PROVIDER_AVAILABLE or
                !TRANSCRIPT_ROWS_0_THROUGH_3_TYPED_AIR_AVAILABLE or
                !TRANSCRIPT_ROWS_0_THROUGH_4_TYPED_AIR_AVAILABLE or
                !TRANSCRIPT_ROWS_0_THROUGH_7_TYPED_AIR_AVAILABLE or
                !TRANSCRIPT_ROWS_6_7_9_TYPED_AIR_AVAILABLE or
                !TRANSCRIPT_ROW_8_PACKED_V2_TYPED_AIR_AVAILABLE or
                TYPED_TRANSCRIPT_ROW_MASK != 0x0000_03ff or
                CHILD_QUERY_COUNT != 3 or CHILD_RELATION_DRAW_COUNT != 94 or
                CHILD_PACKED_RELATION_DRAW_COUNT != 47 or
                CHILD_COMMITMENT_COUNT != 4 or manifest_mod.COMPONENT_COUNT != 39 or
                cohort_protocol.MEASURED_TOTAL_POSEIDON_CALLS != 1_193)
            {
                @compileError("temporal non-FRI V2 authority contract drifted");
            }
            if (std.mem.eql(
                u8,
                &packed_relation_challenge_v2.SEMANTIC_DIGEST,
                &recursion.air.relation_challenge.SEMANTIC_DIGEST,
            )) {
                @compileError("temporal V3 prefix accidentally collapsed into frozen row 8");
            }
            assertPointerFree(TranscriptPrefixRequirementsV1);
            assertPointerFree(TemporalChildTranscriptReplayV2);
            assertPointerFree(TemporalPayloadAuthorityV2);
            assertPointerFree(TemporalParentPublicV2);
            assertPointerFree(Rows10Through17AuthorityV2);
            assertPointerFree(TemporalPrefixCommitmentLayoutV3);
            assertPointerFree(TemporalRows0Through17CustodyV3);
            assertPointerFree(TemporalPrefixTreeReceiptV3);
            assertPointerFree(TemporalPrefixInteractionsV3);
            assertPointerFree(TemporalPrefixDomainAuditsV3);
        }
    };
}
