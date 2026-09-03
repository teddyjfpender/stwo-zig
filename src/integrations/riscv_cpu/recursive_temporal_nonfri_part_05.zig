//! Cohesive internal authority extracted from recursive_temporal_nonfri_source_v2.zig.

pub fn Namespace(comptime context: type) type {
    return struct {
        const std = context.d_std;
        const M31 = context.d_M31;
        const m31 = context.d_m31;
        const recursion = context.d_recursion;
        const channel = context.d_channel;
        const schedule = context.d_schedule;
        const temporal = context.d_temporal;
        const transcript_air = context.d_transcript_air;
        const transcript_component = context.d_transcript_component;
        const transcript_binding = context.d_transcript_binding;
        const transcript_state = context.d_transcript_state;
        const transcript_word = context.d_transcript_word;
        const pow_check_air = context.d_pow_check_air;
        const verifier_randomness = context.d_verifier_randomness;
        const packed_relation_challenge_v2 = context.d_packed_relation_challenge_v2;
        const pow_frame_air = context.d_pow_frame_air;
        const Digest = context.d_Digest;
        const PairAuthority = context.d_PairAuthority;
        const TRANSCRIPT_ROW_COUNT = context.d_TRANSCRIPT_ROW_COUNT;
        const CHILD_QUERY_COUNT = context.d_CHILD_QUERY_COUNT;
        const TRANSCRIPT_ROWS_FORMAT_VERSION = context.d_TRANSCRIPT_ROWS_FORMAT_VERSION;
        const TRANSCRIPT_ROWS_SCHEMA_VERSION = context.d_TRANSCRIPT_ROWS_SCHEMA_VERSION;
        const TranscriptAirRow = context.d_TranscriptAirRow;
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
        const TemporalTranscriptManifestV2 = context.d_TemporalTranscriptManifestV2;
        const Error = context.d_Error;
        const TemporalChildTranscriptReplayV2 = context.d_TemporalChildTranscriptReplayV2;
        const TemporalTranscriptOperationTag = context.d_TemporalTranscriptOperationTag;
        const RecordedFrameV2 = context.d_RecordedFrameV2;
        const TemporalChildArtifactV2 = context.d_TemporalChildArtifactV2;
        const initPreparedTranscriptRowsV2 = context.d_initPreparedTranscriptRowsV2;
        const relationDomainShaForLane = context.d_relationDomainShaForLane;
        const transcriptTraceLogSize = context.d_transcriptTraceLogSize;
        const transcriptWordCount = context.d_transcriptWordCount;
        const transcriptPayloadCount = context.d_transcriptPayloadCount;
        const TemporalPayloadClassificationStateV2 = context.d_TemporalPayloadClassificationStateV2;
        const classifyTemporalPayloadFrame = context.d_classifyTemporalPayloadFrame;
        const transcriptPowCount = context.d_transcriptPowCount;
        const randomnessDescriptor = context.d_randomnessDescriptor;
        const transcriptRandomnessCount = context.d_transcriptRandomnessCount;
        const temporalControlRowCount = context.d_temporalControlRowCount;
        const appendControlPlanRows = context.d_appendControlPlanRows;
        const transcriptRelationDrawCount = context.d_transcriptRelationDrawCount;
        const relationRowForFrame = context.d_relationRowForFrame;
        const validatePackedRelationRowsAgainstFrames = context.d_validatePackedRelationRowsAgainstFrames;
        const validateTranscriptRowsV2 = context.d_validateTranscriptRowsV2;
        const transcriptRowsAuthoritySha = context.d_transcriptRowsAuthoritySha;
        const transcriptManifestSha = context.d_transcriptManifestSha;
        const validateTranscriptDestinations = context.d_validateTranscriptDestinations;
        const validateTypedRowDestination = context.d_validateTypedRowDestination;
        const validateTwoTypedDestinations = context.d_validateTwoTypedDestinations;
        const objectRange = context.d_objectRange;
        const byteRange = context.d_byteRange;
        const metaSlicesEql = context.d_metaSlicesEql;
        const requireDigest = context.d_requireDigest;
        const allZero = context.d_allZero;

        pub const PreparedTranscriptRowsV2 = struct {
            allocator: std.mem.Allocator,
            format_version: u16 = TRANSCRIPT_ROWS_FORMAT_VERSION,
            schema_version: u16 = TRANSCRIPT_ROWS_SCHEMA_VERSION,
            lane_count: u8 = temporal.CHILD_COUNT,
            padding: [3]u8 = .{ 0, 0, 0 },
            log_size: u32,
            pair_authority_id: Digest,
            lane_row_counts: [temporal.CHILD_COUNT]usize,
            lane_operation_counts: [temporal.CHILD_COUNT]usize,
            lane_frame_counts: [temporal.CHILD_COUNT]usize,
            lane_word_counts: [temporal.CHILD_COUNT]usize,
            lane_payload_counts: [temporal.CHILD_COUNT]usize,
            /// Exact number of interaction claims mixed by each admitted
            /// child transcript before its public-wire boundary. SegmentV2
            /// uses 39; a universal temporal parent uses 36.
            lane_claim_counts: [temporal.CHILD_COUNT]u32,
            child_replays: [temporal.CHILD_COUNT]TemporalChildTranscriptReplayV2,
            rows: []TranscriptAirRow,
            operations: []TranscriptControlRow,
            frames: []RecordedFrameV2,
            authority_sha_id: [32]u8,

            pub fn init(
                allocator: std.mem.Allocator,
                pair: *const PairAuthority,
                left: TemporalChildArtifactV2,
                right: TemporalChildArtifactV2,
            ) Error!PreparedTranscriptRowsV2 {
                return initPreparedTranscriptRowsV2(allocator, pair, left, right);
            }

            pub fn deinit(self: *PreparedTranscriptRowsV2) void {
                self.allocator.free(self.frames);
                self.allocator.free(self.operations);
                self.allocator.free(self.rows);
                self.* = undefined;
            }

            pub fn validate(self: *const PreparedTranscriptRowsV2) Error!void {
                try transcript_component.SourceAuthority.pinned().validate();
                const expected_rows = std.math.add(
                    usize,
                    self.lane_row_counts[0],
                    self.lane_row_counts[1],
                ) catch return error.ArithmeticOverflow;
                const expected_operations = std.math.add(
                    usize,
                    self.lane_operation_counts[0],
                    self.lane_operation_counts[1],
                ) catch return error.ArithmeticOverflow;
                const expected_frames = std.math.add(
                    usize,
                    self.lane_frame_counts[0],
                    self.lane_frame_counts[1],
                ) catch return error.ArithmeticOverflow;
                const expected_words = std.math.add(
                    usize,
                    self.lane_word_counts[0],
                    self.lane_word_counts[1],
                ) catch return error.ArithmeticOverflow;
                const expected_payloads = std.math.add(
                    usize,
                    self.lane_payload_counts[0],
                    self.lane_payload_counts[1],
                ) catch return error.ArithmeticOverflow;
                if (self.format_version != TRANSCRIPT_ROWS_FORMAT_VERSION or
                    !context.d_validTranscriptRowsSchema(self.schema_version) or
                    self.lane_count != temporal.CHILD_COUNT or
                    !allZero(&self.padding) or
                    self.log_size != try transcriptTraceLogSize(self.rows.len) or
                    self.rows.len != expected_rows or
                    self.operations.len != expected_operations or
                    self.frames.len != expected_frames or
                    expected_words != try transcriptWordCount(self.frames) or
                    expected_payloads != try transcriptPayloadCount(self.frames))
                {
                    return error.InvalidTranscriptRecorder;
                }
                for (self.lane_claim_counts) |claim_count|
                    if (claim_count == 0 or claim_count >= m31.Modulus)
                        return error.InvalidTranscriptRecorder;
                try requireDigest(self.pair_authority_id);
                for (&self.child_replays) |*replay| try replay.validate();
                try validateTranscriptRowsV2(self);
                if (!std.mem.eql(
                    u8,
                    &self.authority_sha_id,
                    &transcriptRowsAuthoritySha(self),
                )) return error.AuthorityIdentityMismatch;
            }

            pub fn validateAgainstArtifacts(
                self: *const PreparedTranscriptRowsV2,
                pair: *const PairAuthority,
                left: TemporalChildArtifactV2,
                right: TemporalChildArtifactV2,
            ) Error!void {
                try self.validate();
                var expected = try PreparedTranscriptRowsV2.init(
                    self.allocator,
                    pair,
                    left,
                    right,
                );
                defer expected.deinit();
                if (self.format_version != expected.format_version or
                    self.schema_version != expected.schema_version or
                    self.lane_count != expected.lane_count or
                    self.log_size != expected.log_size or
                    !std.meta.eql(self.pair_authority_id, expected.pair_authority_id) or
                    !std.meta.eql(self.lane_row_counts, expected.lane_row_counts) or
                    !std.meta.eql(
                        self.lane_operation_counts,
                        expected.lane_operation_counts,
                    ) or !std.meta.eql(
                    self.lane_frame_counts,
                    expected.lane_frame_counts,
                ) or !std.meta.eql(
                    self.lane_word_counts,
                    expected.lane_word_counts,
                ) or !std.meta.eql(
                    self.lane_payload_counts,
                    expected.lane_payload_counts,
                ) or !std.meta.eql(
                    self.lane_claim_counts,
                    expected.lane_claim_counts,
                ) or
                    !std.meta.eql(self.child_replays, expected.child_replays) or
                    !metaSlicesEql(TranscriptAirRow, self.rows, expected.rows) or
                    !metaSlicesEql(
                        TranscriptControlRow,
                        self.operations,
                        expected.operations,
                    ) or !metaSlicesEql(
                    RecordedFrameV2,
                    self.frames,
                    expected.frames,
                ) or !std.mem.eql(
                    u8,
                    &self.authority_sha_id,
                    &expected.authority_sha_id,
                )) {
                    return error.AuthorityIdentityMismatch;
                }
            }

            /// One allocation-free seal per ordered child lane over all 47 registry
            /// domains. Every domain consumes exactly one packed row carrying its
            /// `(z, alpha)` pair; no caller-supplied challenge enters this boundary.
            pub fn relationDomainShaIds(
                self: *const PreparedTranscriptRowsV2,
            ) Error![temporal.CHILD_COUNT][32]u8 {
                try self.validate();
                var result: [temporal.CHILD_COUNT][32]u8 = undefined;
                var frame_base: usize = 0;
                inline for (0..temporal.CHILD_COUNT) |lane| {
                    const frame_end = frame_base + self.lane_frame_counts[lane];
                    result[lane] = try relationDomainShaForLane(
                        self.frames[frame_base..frame_end],
                        lane,
                    );
                    frame_base = frame_end;
                }
                std.debug.assert(frame_base == self.frames.len);
                return result;
            }

            pub fn controlLogSize(self: *const PreparedTranscriptRowsV2) Error!u32 {
                try self.validate();
                return transcriptTraceLogSize(self.operations.len);
            }

            pub fn stateLogSize(self: *const PreparedTranscriptRowsV2) Error!u32 {
                try self.validate();
                return transcriptTraceLogSize(self.frames.len);
            }

            pub fn wordLogSize(self: *const PreparedTranscriptRowsV2) Error!u32 {
                try self.validate();
                return transcriptTraceLogSize(try transcriptWordCount(self.frames));
            }

            pub fn payloadLogSize(self: *const PreparedTranscriptRowsV2) Error!u32 {
                try self.validate();
                return transcriptTraceLogSize(try transcriptPayloadCount(self.frames));
            }

            pub fn powLogSize(self: *const PreparedTranscriptRowsV2) Error!u32 {
                try self.validate();
                return transcriptTraceLogSize(transcriptPowCount(self.frames));
            }

            pub fn randomnessLogSize(
                self: *const PreparedTranscriptRowsV2,
            ) Error!u32 {
                try self.validate();
                return transcriptTraceLogSize(transcriptRandomnessCount(self.frames));
            }

            pub fn relationChallengeLogSize(
                self: *const PreparedTranscriptRowsV2,
            ) Error!u32 {
                try self.validate();
                return transcriptTraceLogSize(transcriptRelationDrawCount(self.frames));
            }

            pub fn manifest(
                self: *const PreparedTranscriptRowsV2,
            ) Error!TemporalTranscriptManifestV2 {
                return self.manifestWithControlRowCount(self.operations.len);
            }

            /// Binds row 0 to the verifier-owned complete step machine rather than
            /// the narrower set of transcript calls retained for rows 1--9.
            pub fn manifestForPlans(
                self: *const PreparedTranscriptRowsV2,
                vm_plan: *const schedule.Plan,
                recursion_plan: *const schedule.Plan,
            ) Error!TemporalTranscriptManifestV2 {
                return self.manifestWithControlRowCount(
                    try temporalControlRowCount(
                        self.operations.len,
                        vm_plan,
                        recursion_plan,
                    ),
                );
            }

            fn manifestWithControlRowCount(
                self: *const PreparedTranscriptRowsV2,
                control_row_count: usize,
            ) Error!TemporalTranscriptManifestV2 {
                try self.validate();
                const counts = [TRANSCRIPT_ROW_COUNT]usize{
                    control_row_count,
                    self.rows.len,
                    self.rows.len,
                    self.frames.len,
                    try transcriptWordCount(self.frames),
                    try transcriptPayloadCount(self.frames),
                    transcriptPowCount(self.frames),
                    transcriptPowCount(self.frames),
                    transcriptRelationDrawCount(self.frames),
                    transcriptRandomnessCount(self.frames),
                };
                var logical_rows: [TRANSCRIPT_ROW_COUNT]u32 = undefined;
                var log_sizes: [TRANSCRIPT_ROW_COUNT]u8 = undefined;
                for (counts, 0..) |count, index| {
                    if (count >= m31.Modulus) return error.RowCountOutOfRange;
                    logical_rows[index] = @intCast(count);
                    log_sizes[index] = @intCast(try transcriptTraceLogSize(count));
                }
                var result = TemporalTranscriptManifestV2{
                    .logical_rows = logical_rows,
                    .log_sizes = log_sizes,
                    .pair_authority_id = self.pair_authority_id,
                    .transcript_rows_authority_sha_id = self.authority_sha_id,
                    .identity = undefined,
                };
                result.identity = transcriptManifestSha(&result);
                try result.validate();
                return result;
            }

            pub fn fillControlRowsInto(
                self: *const PreparedTranscriptRowsV2,
                destination: []TranscriptControlRow,
            ) Error!void {
                try self.validate();
                try validateTypedRowDestination(
                    destination,
                    self.operations.len,
                    self,
                );
                @memcpy(destination, self.operations);
            }

            /// Allocation-free row-0 writer for the complete VM/recursive verifier
            /// schedule. Transcript replay remains the authority for rows 1--9; row 0
            /// must additionally emit non-channel computation and closure steps.
            pub fn fillControlRowsForPlansInto(
                self: *const PreparedTranscriptRowsV2,
                destination: []TranscriptControlRow,
                vm_plan: *const schedule.Plan,
                recursion_plan: *const schedule.Plan,
            ) Error!void {
                try self.validate();
                const expected = try temporalControlRowCount(
                    self.operations.len,
                    vm_plan,
                    recursion_plan,
                );
                if (destination.len != expected)
                    return error.DestinationLengthMismatch;
                var at: usize = 0;
                appendControlPlanRows(
                    destination,
                    &at,
                    vm_plan,
                    0,
                    1,
                    0,
                    .all,
                );
                appendControlPlanRows(
                    destination,
                    &at,
                    recursion_plan,
                    1,
                    0,
                    1,
                    .non_transcript,
                );
                appendControlPlanRows(
                    destination,
                    &at,
                    recursion_plan,
                    2,
                    0,
                    1,
                    .non_transcript,
                );
                // The ordinary outer verifier is a raw Poseidon channel rather than
                // V1's separately framed transcript program. Its authenticated
                // low-level operations therefore replace -- never duplicate -- the
                // transcript-bearing recursion-plan steps above. They are not
                // terminal in the complete parent: row 2 consumes every operation,
                // and the retained plan's close/complete rows terminate the verifier.
                for (self.operations) |operation| {
                    destination[at] = operation;
                    destination[at].terminal_mask = 0;
                    at += 1;
                }
                std.debug.assert(at == destination.len);
            }

            pub fn fillBindingRowsInto(
                self: *const PreparedTranscriptRowsV2,
                destination: []TranscriptBindingRowV2,
            ) Error!void {
                try self.validate();
                try validateTypedRowDestination(destination, self.rows.len, self);

                var row_base: usize = 0;
                var frame_base: usize = 0;
                var output_at: usize = 0;
                inline for (0..temporal.CHILD_COUNT) |lane| {
                    const frame_end = frame_base + self.lane_frame_counts[lane];
                    for (self.frames[frame_base..frame_end], 0..) |frame, frame_index| {
                        const operation_first = frame_index == 0 or
                            self.frames[frame_base + frame_index - 1].sequence !=
                                frame.sequence;
                        for (0..frame.call_count) |step| {
                            const call = self.rows[row_base + frame.first_call_id + step];
                            destination[output_at] = .{
                                .preprocessing = .{
                                    .row_mask = 1,
                                    .segment_mask = 0,
                                    .binary_mask = 1,
                                    .verifier_id = frame.verifier_id,
                                    .sequence = frame.sequence,
                                    .tag = frame.tag,
                                    .args = frame.args,
                                    .call_id = call.call_id,
                                    .hash_id = call.hash_id,
                                    .hash_step = call.step,
                                    .is_first = call.is_first,
                                    .is_last = call.is_last,
                                    .is_draw = call.is_draw,
                                    .is_operation_first = @intFromBool(
                                        operation_first and step == 0,
                                    ),
                                    .pow_final_mask = @intFromBool(
                                        frame.pow_draw and call.is_last == 1,
                                    ),
                                },
                                .main = .{
                                    .enabler = 1,
                                    .chunks = call.chunk,
                                    .outputs = if (call.is_last == 1)
                                        call.output[0..channel.RATE].*
                                    else
                                        .{M31.zero()} ** channel.RATE,
                                },
                            };
                            _ = transcript_binding.logicalInputs(
                                destination[output_at].main,
                                destination[output_at].preprocessing,
                                .binary_node,
                            );
                            output_at += 1;
                        }
                    }
                    row_base += self.lane_row_counts[lane];
                    frame_base = frame_end;
                }
                std.debug.assert(output_at == destination.len);
            }

            pub fn fillStateRowsInto(
                self: *const PreparedTranscriptRowsV2,
                destination: []TranscriptStateRowV2,
            ) Error!void {
                try self.validate();
                try validateTypedRowDestination(destination, self.frames.len, self);
                for (destination, self.frames) |*target, frame| {
                    target.* = .{
                        .preprocessing = .{
                            .row_mask = 1,
                            .segment_mask = 0,
                            .binary_mask = 1,
                            .verifier_id = frame.verifier_id,
                            .sequence = frame.sequence,
                            .tag = frame.tag,
                            .args = frame.args,
                            .hash_id = frame.hash_id,
                            .input_state_key = frame.input_state_key,
                            .output_state_key = frame.output_state_key,
                            .initial_mask = frame.initial_mask,
                            .state_consume_mask = frame.state_consume_mask,
                            .state_produce_multiplicity = frame.state_produce_multiplicity,
                            .draw_output_mask = frame.draw_output_mask,
                        },
                        .main = .{
                            .enabler = 1,
                            .inputs = frame.input_digest,
                            .outputs = frame.output_digest,
                        },
                    };
                    _ = transcript_state.logicalInputs(
                        target.main,
                        target.preprocessing,
                        .binary_node,
                    );
                }
            }

            pub fn fillWordRowsInto(
                self: *const PreparedTranscriptRowsV2,
                destination: []TranscriptWordRowV2,
            ) Error!void {
                try self.validate();
                const word_count = try transcriptWordCount(self.frames);
                try validateTypedRowDestination(destination, word_count, self);

                var row_base: usize = 0;
                var frame_base: usize = 0;
                var output_at: usize = 0;
                inline for (0..temporal.CHILD_COUNT) |lane| {
                    const frame_end = frame_base + self.lane_frame_counts[lane];
                    for (self.frames[frame_base..frame_end]) |frame| {
                        const padded_words: usize =
                            @as(usize, frame.call_count) * channel.RATE;
                        const payload_end = channel.RATE + frame.payload_word_count;
                        for (channel.RATE..padded_words) |word_index| {
                            const call = self.rows[
                                row_base + frame.first_call_id +
                                    word_index / channel.RATE
                            ];
                            const word = call.chunk[word_index % channel.RATE];
                            const is_payload = frame.purpose == .mix and
                                word_index < payload_end;
                            destination[output_at] = .{
                                .preprocessing = .{
                                    .row_mask = 1,
                                    .segment_mask = 0,
                                    .binary_mask = 1,
                                    .verifier_id = frame.verifier_id,
                                    .sequence = frame.sequence,
                                    .tag = frame.tag,
                                    .args = frame.args,
                                    .hash_id = frame.hash_id,
                                    .word_index = @intCast(word_index),
                                    .is_payload = @intFromBool(is_payload),
                                    .payload_index = if (is_payload)
                                        @intCast(word_index - channel.RATE)
                                    else
                                        0,
                                    .constant_value = if (is_payload)
                                        0
                                    else
                                        word.toU32(),
                                },
                                .value = if (is_payload) word else M31.zero(),
                            };
                            _ = try transcript_word.logicalRow(
                                destination[output_at].preprocessing,
                                destination[output_at].value,
                                .binary_node,
                            );
                            output_at += 1;
                        }
                    }
                    row_base += self.lane_row_counts[lane];
                    frame_base = frame_end;
                }
                std.debug.assert(output_at == destination.len);
            }

            pub fn fillPayloadRowsInto(
                self: *const PreparedTranscriptRowsV2,
                destination: []TemporalTranscriptPayloadRowV2,
            ) Error!void {
                try self.validate();
                const payload_count = try transcriptPayloadCount(self.frames);
                try validateTypedRowDestination(destination, payload_count, self);

                var row_base: usize = 0;
                var frame_base: usize = 0;
                var output_at: usize = 0;
                inline for (0..temporal.CHILD_COUNT) |lane| {
                    const frame_end = frame_base + self.lane_frame_counts[lane];
                    var classification = TemporalPayloadClassificationStateV2{};
                    for (self.frames[frame_base..frame_end]) |frame| {
                        if (frame.purpose != .mix) continue;
                        const descriptor = try classifyTemporalPayloadFrame(
                            frame,
                            &classification,
                            self.lane_claim_counts[lane],
                        );
                        for (0..frame.payload_word_count) |payload_index| {
                            const word_index = channel.RATE + payload_index;
                            const call = self.rows[
                                row_base + frame.first_call_id +
                                    word_index / channel.RATE
                            ];
                            const value = call.chunk[word_index % channel.RATE];
                            const coordinate = descriptor.coordinate(payload_index);
                            destination[output_at] = .{
                                .verifier_id = frame.verifier_id,
                                .instruction_index = frame.sequence,
                                .tag = frame.tag,
                                .args = frame.args,
                                .payload_index = @intCast(payload_index),
                                .source_kind = descriptor.source_kind,
                                .item_index = coordinate.item_index,
                                .limb_index = coordinate.limb_index,
                                .constant_mask = descriptor.constant_mask,
                                .input_use_count = descriptor.input_use_count,
                                .source_hash_id = frame.hash_id,
                                .source_word_index = @intCast(word_index),
                                .value = value,
                            };
                            output_at += 1;
                        }
                    }
                    row_base += self.lane_row_counts[lane];
                    frame_base = frame_end;
                }
                std.debug.assert(output_at == destination.len);
            }

            pub fn fillPowRowsInto(
                self: *const PreparedTranscriptRowsV2,
                checks: []TemporalPowCheckRowV2,
                frames_out: []TemporalPowFrameRowV2,
            ) Error!void {
                try self.validate();
                const pow_count = transcriptPowCount(self.frames);
                try validateTwoTypedDestinations(
                    checks,
                    frames_out,
                    pow_count,
                    self,
                );
                var at: usize = 0;
                for (self.frames) |frame| {
                    if (!frame.pow_draw) continue;
                    const pow_kind: pow_check_air.PowKind = switch (frame.tag) {
                        pow_frame_air.INTERACTION_CONTROL_TAG => .interaction,
                        pow_frame_air.PCS_CONTROL_TAG => .pcs,
                        else => return error.InvalidTranscriptRecorder,
                    };
                    var word_bits: [31]u32 = undefined;
                    var active_bits: [31]u32 = undefined;
                    const word = frame.output_digest[0];
                    for (&word_bits, &active_bits, 0..) |*word_bit, *active, bit| {
                        word_bit.* = (word.toU32() >> @intCast(bit)) & 1;
                        active.* = @intFromBool(bit < frame.args[0]);
                    }
                    const call_id = frame.first_call_id + frame.call_count - 1;
                    checks[at] = .{
                        .verifier_id = frame.verifier_id,
                        .pow_kind = pow_kind,
                        .call_id = call_id,
                        .bits = frame.args[0],
                        .word = word,
                        .word_bits = word_bits,
                        .active_bits = active_bits,
                    };
                    frames_out[at] = .{
                        .verifier_id = frame.verifier_id,
                        .sequence = frame.sequence,
                        .pow_kind = pow_kind,
                        .hash_id = frame.hash_id,
                        .call_id = call_id,
                        .bits = frame.args[0],
                        .words = frame.output_digest,
                    };
                    at += 1;
                }
                std.debug.assert(at == pow_count);
            }

            pub fn fillRandomnessRowsInto(
                self: *const PreparedTranscriptRowsV2,
                destination: []TemporalVerifierRandomnessRowV2,
            ) Error!void {
                try self.validate();
                const count = transcriptRandomnessCount(self.frames);
                try validateTypedRowDestination(destination, count, self);
                var at: usize = 0;
                var lane_draw_index: u32 = 0;
                var previous_verifier: u32 = 0;
                for (self.frames) |frame| {
                    const descriptor = randomnessDescriptor(frame) orelse continue;
                    if (frame.verifier_id != previous_verifier) {
                        previous_verifier = frame.verifier_id;
                        lane_draw_index = 0;
                    }
                    var multiplicities = [_]u32{0} ** channel.RATE;
                    for (multiplicities[0..descriptor.word_count]) |*value|
                        value.* = descriptor.kind.semanticUseCount();
                    destination[at] = .{
                        .preprocessing = .{
                            .row_mask = 1,
                            .segment_mask = 0,
                            .binary_mask = 1,
                            .verifier_id = frame.verifier_id,
                            .sequence = frame.sequence,
                            .tag = frame.tag,
                            .args = frame.args,
                            .kind = descriptor.kind,
                            .item_base = descriptor.item_base,
                            .query_items = @intFromBool(descriptor.query_items),
                            .multiplicities = multiplicities,
                            .draw_index = lane_draw_index,
                        },
                        .main = .{ .enabler = 1, .outputs = frame.output_digest },
                    };
                    _ = verifier_randomness.logicalInputs(
                        destination[at].main,
                        destination[at].preprocessing,
                        .binary_node,
                    );
                    lane_draw_index += 1;
                    at += 1;
                }
                std.debug.assert(at == destination.len);
            }

            /// Allocation-free, failure-atomic row-8 writer.  The cold source
            /// validation proves the exact 47 packed draws per lane before the first
            /// store; each destination row then consumes one unchanged eight-word
            /// transcript frame and emits two ordered four-limb challenge tuples.
            pub fn fillRelationChallengeRowsInto(
                self: *const PreparedTranscriptRowsV2,
                destination: []TemporalPackedRelationChallengeRowV2,
            ) Error!void {
                try self.validate();
                const count = transcriptRelationDrawCount(self.frames);
                try validateTypedRowDestination(destination, count, self);

                var at: usize = 0;
                for (self.frames) |frame| {
                    if (frame.tag != @intFromEnum(
                        TemporalTranscriptOperationTag.relation_draw,
                    )) continue;
                    destination[at] = relationRowForFrame(frame);
                    _ = packed_relation_challenge_v2.logicalInputs(
                        destination[at].main,
                        destination[at].preprocessing,
                        .binary_node,
                    );
                    at += 1;
                }
                std.debug.assert(at == destination.len);
            }

            pub fn validateRelationChallengeRows(
                self: *const PreparedTranscriptRowsV2,
                rows_to_validate: []const TemporalPackedRelationChallengeRowV2,
            ) Error!void {
                try self.validate();
                try validatePackedRelationRowsAgainstFrames(
                    rows_to_validate,
                    self.frames,
                );
            }

            /// Allocation-free, failure-atomic writer into the existing row-1 SoA.
            pub fn fillMainInto(
                self: *const PreparedTranscriptRowsV2,
                columns: *[transcript_air.MAIN_COLUMN_COUNT][]M31,
            ) Error!void {
                try self.validate();
                const trace_length = @as(usize, 1) << @intCast(self.log_size);
                try validateTranscriptDestinations(columns, trace_length, self);

                for (columns) |column| @memset(column, M31.zero());
                for (self.rows, 0..) |row, row_index| {
                    const values = row.values();
                    for (columns, values) |column, value| column[row_index] = value;
                }
            }

            /// Publishes the exact full 31-bit query words drawn by each authenticated
            /// child transcript. These are deliberately not the low-bit projected
            /// Merkle positions retained in `child_replays.raw_queries`: row 20 binds
            /// all 31 transcript-authenticated bits before applying its verifier-owned
            /// lifting-domain mask.
            pub fn fillQueryWordsInto(
                self: *const PreparedTranscriptRowsV2,
                destination: *[temporal.CHILD_COUNT][CHILD_QUERY_COUNT]M31,
            ) Error!void {
                try self.validate();
                destination.* = @splat(@splat(M31.zero()));
                var seen = [_]bool{false} ** temporal.CHILD_COUNT;
                for (self.frames) |frame| {
                    if (frame.tag != @intFromEnum(
                        TemporalTranscriptOperationTag.query_draw,
                    )) continue;
                    const lane: usize = switch (frame.verifier_id) {
                        transcript_air.LEFT_RECURSION_VERIFIER_ID => 0,
                        transcript_air.RIGHT_RECURSION_VERIFIER_ID => 1,
                        else => return error.InvalidTranscriptRecorder,
                    };
                    if (seen[lane] or frame.purpose != .draw or frame.pow_draw or
                        frame.args[0] != 0 or frame.args[1] != CHILD_QUERY_COUNT or
                        frame.args[2] == 0 or frame.args[2] >= 31 or
                        frame.args[3] != 0 or frame.draw_output_mask != 1)
                    {
                        return error.InvalidTranscriptRecorder;
                    }
                    const mask = (@as(u32, 1) << @intCast(frame.args[2])) - 1;
                    for (
                        &destination[lane],
                        frame.output_digest[0..CHILD_QUERY_COUNT],
                        self.child_replays[lane].raw_queries,
                    ) |*target, full, projected| {
                        target.* = full;
                        if ((full.toU32() & mask) != projected)
                            return error.ChildTranscriptMismatch;
                    }
                    seen[lane] = true;
                }
                for (seen) |value| if (!value)
                    return error.InvalidTranscriptRecorder;
            }

            /// Converts the exact row-1 inputs into the shared row-34 Poseidon ABI.
            /// The permutation output is already constrained by the provider AIR, so
            /// this bridge never recomputes it on the hot path.
            pub fn fillProviderCallsInto(
                self: *const PreparedTranscriptRowsV2,
                destination: []TranscriptProviderCall,
            ) Error!void {
                try self.validate();
                if (destination.len != self.rows.len)
                    return error.DestinationLengthMismatch;
                const output_range = try byteRange(destination);
                if (output_range.overlaps(try objectRange(self)) or
                    output_range.overlaps(try byteRange(self.rows)) or
                    output_range.overlaps(try byteRange(self.operations)) or
                    output_range.overlaps(try byteRange(self.frames)))
                {
                    return error.AliasedDestination;
                }

                for (destination, self.rows) |*target, row| target.* = .{
                    .input = row.providerInput(),
                    .wide = false,
                    .io = true,
                    .narrow_output = null,
                };
            }
        };
    };
}
