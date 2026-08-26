//! Cohesive internal authority extracted from recursive_temporal_nonfri_source_v2.zig.

pub fn Namespace(comptime context: type) type {
    return struct {
        const std = context.d_std;
        const recursion = context.d_recursion;
        const channel = context.d_channel;
        const manifest_mod = context.d_manifest_mod;
        const schedule = context.d_schedule;
        const transcript_program = context.d_transcript_program;
        const temporal = context.d_temporal;
        const verifier_randomness = context.d_verifier_randomness;
        const packed_relation_challenge_v2 = context.d_packed_relation_challenge_v2;
        const CHILD_COMMITMENT_COUNT = context.d_CHILD_COMMITMENT_COUNT;
        const CHILD_RELATION_DRAW_COUNT = context.d_CHILD_RELATION_DRAW_COUNT;
        const CHILD_PACKED_RELATION_DRAW_COUNT = context.d_CHILD_PACKED_RELATION_DRAW_COUNT;
        const TranscriptControlRow = context.d_TranscriptControlRow;
        const TemporalPayloadSourceKindV2 = context.d_TemporalPayloadSourceKindV2;
        const PUBLIC_WIRE_BOUNDARY_CLAIMED_SUM_ITEM_INDEX = context.d_PUBLIC_WIRE_BOUNDARY_CLAIMED_SUM_ITEM_INDEX;
        const TemporalPackedRelationChallengeRowV2 = context.d_TemporalPackedRelationChallengeRowV2;
        const Error = context.d_Error;
        const TemporalTranscriptOperationTag = context.d_TemporalTranscriptOperationTag;
        const RecordedFrameV2 = context.d_RecordedFrameV2;

        pub const TemporalPayloadClassificationStateV2 = struct {
            canonical_frame: u32 = 0,
            felt_frame: u32 = 0,
        };

        pub const TemporalPayloadCoordinateV2 = struct {
            item_index: u32,
            limb_index: u32,
        };

        pub const TemporalPayloadDescriptorV2 = struct {
            source_kind: TemporalPayloadSourceKindV2,
            item_base: u32,
            limb_width: u32,
            constant_mask: u32,
            input_use_count: u32,

            pub fn coordinate(
                self: TemporalPayloadDescriptorV2,
                payload_index: usize,
            ) TemporalPayloadCoordinateV2 {
                const index: u32 = @intCast(payload_index);
                return .{
                    .item_index = self.item_base + index / self.limb_width,
                    .limb_index = index % self.limb_width,
                };
            }
        };

        pub fn classifyTemporalPayloadFrame(
            frame: RecordedFrameV2,
            state: *TemporalPayloadClassificationStateV2,
        ) Error!TemporalPayloadDescriptorV2 {
            if (frame.purpose != .mix or frame.payload_word_count == 0)
                return error.InvalidTranscriptRecorder;
            const tag: TemporalTranscriptOperationTag = @enumFromInt(frame.tag);
            return switch (tag) {
                .mix_canonical_words => blk: {
                    const ordinal = state.canonical_frame;
                    state.canonical_frame += 1;
                    break :blk if (ordinal < CHILD_COMMITMENT_COUNT)
                        .{
                            .source_kind = .commitment,
                            .item_base = ordinal,
                            .limb_width = channel.RATE,
                            .constant_mask = 0,
                            .input_use_count = 1,
                        }
                    else
                        .{
                            .source_kind = .fri_commitment,
                            .item_base = ordinal - @as(u32, CHILD_COMMITMENT_COUNT),
                            .limb_width = channel.RATE,
                            .constant_mask = 0,
                            .input_use_count = 1,
                        };
                },
                .mix_u32s => .{
                    .source_kind = .public_geometry,
                    .item_base = frame.sequence,
                    .limb_width = frame.payload_word_count,
                    .constant_mask = 1,
                    .input_use_count = 0,
                },
                .mix_felts => blk: {
                    const ordinal = state.felt_frame;
                    state.felt_frame += 1;
                    if (ordinal < manifest_mod.COMPONENT_COUNT) break :blk .{
                        .source_kind = .claimed_sum,
                        .item_base = ordinal,
                        .limb_width = 4,
                        .constant_mask = 0,
                        .input_use_count = 1,
                    };
                    if (ordinal == manifest_mod.COMPONENT_COUNT) break :blk .{
                        .source_kind = .claimed_sum,
                        .item_base = PUBLIC_WIRE_BOUNDARY_CLAIMED_SUM_ITEM_INDEX,
                        .limb_width = 4,
                        .constant_mask = 0,
                        .input_use_count = 1,
                    };
                    if (ordinal == manifest_mod.COMPONENT_COUNT + 1) break :blk .{
                        .source_kind = .sampled_value,
                        .item_base = 0,
                        .limb_width = 4,
                        .constant_mask = 0,
                        .input_use_count = 2,
                    };
                    if (ordinal == manifest_mod.COMPONENT_COUNT + 2) break :blk .{
                        .source_kind = .last_layer_coefficient,
                        .item_base = 0,
                        .limb_width = 4,
                        .constant_mask = 0,
                        .input_use_count = 1,
                    };
                    return error.InvalidTranscriptRecorder;
                },
                .verify_pow => .{
                    .source_kind = .pcs_pow_nonce,
                    .item_base = 0,
                    .limb_width = 4,
                    .constant_mask = 0,
                    .input_use_count = 0,
                },
                .mix_u64 => .{
                    .source_kind = .pcs_pow_nonce,
                    .item_base = 0,
                    .limb_width = 4,
                    .constant_mask = 0,
                    .input_use_count = 0,
                },
                else => error.InvalidTranscriptRecorder,
            };
        }

        pub fn transcriptPowCount(frames: []const RecordedFrameV2) usize {
            var result: usize = 0;
            for (frames) |frame| result += @intFromBool(frame.pow_draw);
            return result;
        }

        pub const TemporalRandomnessDescriptorV2 = struct {
            kind: verifier_randomness.Kind,
            item_base: u32,
            query_items: bool,
            word_count: usize,
        };

        pub fn randomnessDescriptor(
            frame: RecordedFrameV2,
        ) ?TemporalRandomnessDescriptorV2 {
            const tag: TemporalTranscriptOperationTag = @enumFromInt(frame.tag);
            return switch (tag) {
                .composition_draw => .{
                    .kind = .composition_randomness,
                    .item_base = 0,
                    .query_items = false,
                    .word_count = 4,
                },
                .oods_draw => .{
                    .kind = .oods_point,
                    .item_base = 0,
                    .query_items = false,
                    .word_count = 4,
                },
                .deep_draw => .{
                    .kind = .deep_randomness,
                    .item_base = 0,
                    .query_items = false,
                    .word_count = 4,
                },
                .fri_alpha_draw => .{
                    .kind = .fri_alpha,
                    .item_base = frame.args[0],
                    .query_items = false,
                    .word_count = 4,
                },
                .query_draw => .{
                    .kind = .raw_query,
                    .item_base = frame.args[0],
                    .query_items = true,
                    .word_count = frame.args[1],
                },
                else => null,
            };
        }

        pub fn transcriptRandomnessCount(frames: []const RecordedFrameV2) usize {
            var result: usize = 0;
            for (frames) |frame| result += @intFromBool(
                randomnessDescriptor(frame) != null,
            );
            return result;
        }

        pub fn temporalControlRowCount(
            operation_count: usize,
            vm_plan: *const schedule.Plan,
            recursion_plan: *const schedule.Plan,
        ) Error!usize {
            vm_plan.validate() catch return error.InvalidTranscriptManifest;
            recursion_plan.validate() catch return error.InvalidTranscriptManifest;
            if (vm_plan.schema != .vm or recursion_plan.schema != .recursion)
                return error.InvalidTranscriptManifest;

            var non_transcript_recursion_rows: usize = 0;
            for (recursion_plan.steps) |step|
                non_transcript_recursion_rows += @intFromBool(
                    transcript_program.effect(step) == null,
                );
            const recursive_rows = std.math.mul(
                usize,
                non_transcript_recursion_rows,
                temporal.CHILD_COUNT,
            ) catch return error.ArithmeticOverflow;
            const planned_rows = std.math.add(
                usize,
                vm_plan.steps.len,
                recursive_rows,
            ) catch return error.ArithmeticOverflow;
            return std.math.add(
                usize,
                planned_rows,
                operation_count,
            ) catch return error.ArithmeticOverflow;
        }

        pub const ControlPlanSelection = enum { all, non_transcript };

        pub fn appendControlPlanRows(
            destination: []TranscriptControlRow,
            at: *usize,
            plan: *const schedule.Plan,
            verifier_id: u32,
            segment_mask: u32,
            binary_mask: u32,
            selection: ControlPlanSelection,
        ) void {
            for (plan.steps, 0..) |step, sequence| {
                if (selection == .non_transcript and
                    transcript_program.effect(step) != null)
                {
                    continue;
                }
                const encoded = step.encode();
                destination[at.*] = .{
                    .segment_mask = segment_mask,
                    .binary_mask = binary_mask,
                    .verifier_id = verifier_id,
                    .sequence = @intCast(sequence),
                    .tag = encoded.tag,
                    .args = encoded.args,
                    .terminal_mask = @intFromBool(step.terminal()),
                };
                at.* += 1;
            }
        }

        pub fn transcriptRelationDrawCount(frames: []const RecordedFrameV2) usize {
            var result: usize = 0;
            for (frames) |frame| result += @intFromBool(
                frame.tag == @intFromEnum(TemporalTranscriptOperationTag.relation_draw),
            );
            return result;
        }

        pub fn relationRowForFrame(
            frame: RecordedFrameV2,
        ) TemporalPackedRelationChallengeRowV2 {
            return .{
                .preprocessing = .{
                    .segment_mask = 0,
                    .binary_mask = 1,
                    .public_masks = .{ 0, 0 },
                    .verifier_id = frame.verifier_id,
                    .sequence = frame.sequence,
                    .tag = frame.tag,
                    .args = frame.args,
                },
                .main = .{ .outputs = frame.output_digest },
            };
        }

        pub fn validatePackedRelationRowsAgainstFrames(
            rows: []const TemporalPackedRelationChallengeRowV2,
            frames: []const RecordedFrameV2,
        ) Error!void {
            if (rows.len != transcriptRelationDrawCount(frames))
                return error.DestinationLengthMismatch;
            var at: usize = 0;
            for (frames) |frame| {
                if (frame.tag != @intFromEnum(
                    TemporalTranscriptOperationTag.relation_draw,
                )) continue;
                try packed_relation_challenge_v2.validateRow(rows[at]);
                if (!std.meta.eql(rows[at], relationRowForFrame(frame)))
                    return error.InvalidPackedRelationChallengeRow;
                at += 1;
            }
            std.debug.assert(at == rows.len);
        }

        pub fn validatePackedRelationFrameSchedule(
            frames: []const RecordedFrameV2,
            lane_frame_counts: [temporal.CHILD_COUNT]usize,
        ) Error!void {
            var frame_at: usize = 0;
            inline for (0..temporal.CHILD_COUNT) |lane| {
                const frame_end = std.math.add(
                    usize,
                    frame_at,
                    lane_frame_counts[lane],
                ) catch return error.ArithmeticOverflow;
                if (frame_end > frames.len) return error.InvalidTranscriptRecorder;
                var expected_first_challenge: u32 = 0;
                var packed_draw_count: usize = 0;
                var relation_block_started = false;
                var relation_block_finished = false;
                for (frames[frame_at..frame_end]) |frame| {
                    const is_relation = frame.tag == @intFromEnum(
                        TemporalTranscriptOperationTag.relation_draw,
                    );
                    if (!is_relation) {
                        if (relation_block_started) relation_block_finished = true;
                        continue;
                    }
                    if (relation_block_finished or frame.purpose != .draw or
                        frame.pow_draw or frame.payload_word_count != 2 or
                        frame.args[0] != expected_first_challenge or
                        frame.args[1] !=
                            packed_relation_challenge_v2.CHALLENGES_PER_DRAW or
                        frame.args[2] !=
                            packed_relation_challenge_v2.PACKING_FORMAT_VERSION or
                        frame.args[3] != 0 or frame.draw_output_mask != 1)
                    {
                        return error.InvalidTranscriptRecorder;
                    }
                    relation_block_started = true;
                    expected_first_challenge = std.math.add(
                        u32,
                        expected_first_challenge,
                        packed_relation_challenge_v2.CHALLENGES_PER_DRAW,
                    ) catch return error.ArithmeticOverflow;
                    packed_draw_count += 1;
                }
                if (packed_draw_count != CHILD_PACKED_RELATION_DRAW_COUNT or
                    expected_first_challenge != CHILD_RELATION_DRAW_COUNT)
                {
                    return error.InvalidTranscriptRecorder;
                }
                frame_at = frame_end;
            }
            if (frame_at != frames.len) return error.InvalidTranscriptRecorder;
        }
    };
}
