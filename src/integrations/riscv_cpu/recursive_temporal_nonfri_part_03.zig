//! Cohesive internal authority extracted from recursive_temporal_nonfri_source_v2.zig.

pub fn Namespace(comptime context: type) type {
    return struct {
        const std = context.d_std;
        const M31 = context.d_M31;
        const QM31 = context.d_QM31;
        const m31 = context.d_m31;
        const channel = context.d_channel;
        const transcript_air = context.d_transcript_air;
        const poseidon2 = context.d_poseidon2;
        const Digest = context.d_Digest;
        const TranscriptAirRow = context.d_TranscriptAirRow;
        const TranscriptControlRow = context.d_TranscriptControlRow;
        const Error = context.d_Error;
        const annotateNextDraw = context.d_annotateNextDraw;
        const TemporalTranscriptOperationTag = context.d_TemporalTranscriptOperationTag;
        const RecordedFrameV2 = context.d_RecordedFrameV2;
        const RecorderPayload = context.d_RecorderPayload;
        const PendingPow = context.d_PendingPow;
        const OperationContextV2 = context.d_OperationContextV2;
        const NextDrawOperationV2 = context.d_NextDrawOperationV2;

        pub const TranscriptRowRecorderV2 = struct {
            allocator: std.mem.Allocator,
            rows: std.ArrayList(TranscriptAirRow) = .empty,
            operations: std.ArrayList(TranscriptControlRow) = .empty,
            frames: std.ArrayList(RecordedFrameV2) = .empty,
            verifier_id: u32,
            digest: Digest = .{0} ** channel.RATE,
            n_draws: u32 = 0,
            call_id: usize = 0,
            hash_id: usize = 0,
            operation_id: usize = 0,
            lane_frame_start: usize = 0,
            lane_operation_start: usize = 0,
            lane_open: bool = true,
            current_operation: ?OperationContextV2 = null,
            next_draw_operation: ?NextDrawOperationV2 = null,
            pending_pow: ?PendingPow = null,
            failure: ?enum {
                out_of_memory,
                row_count_out_of_range,
                invalid_state,
            } = null,

            pub fn init(
                allocator: std.mem.Allocator,
                verifier_id: u32,
            ) TranscriptRowRecorderV2 {
                return .{ .allocator = allocator, .verifier_id = verifier_id };
            }

            pub fn deinit(self: *TranscriptRowRecorderV2) void {
                self.frames.deinit(self.allocator);
                self.operations.deinit(self.allocator);
                self.rows.deinit(self.allocator);
                self.* = undefined;
            }

            pub fn beginLane(
                self: *TranscriptRowRecorderV2,
                verifier_id: u32,
            ) Error!void {
                try self.checkHealthy();
                if (self.pending_pow != null) return error.DanglingPowTransaction;
                try self.finishLane();
                self.verifier_id = verifier_id;
                self.digest = .{0} ** channel.RATE;
                self.n_draws = 0;
                self.call_id = 0;
                self.hash_id = 0;
                self.operation_id = 0;
                self.lane_frame_start = self.frames.items.len;
                self.lane_operation_start = self.operations.items.len;
                self.lane_open = true;
            }

            pub fn digestWords(self: *const TranscriptRowRecorderV2) Digest {
                return self.digest;
            }

            pub fn mixCanonicalM31Words(
                self: *TranscriptRowRecorderV2,
                words: []const M31,
            ) void {
                if (self.pending_pow != null) {
                    self.failure = self.failure orelse .invalid_state;
                    return;
                }
                self.startOperation(.mix_canonical_words, .{
                    self.lengthArg(words.len), 0, 0, 0,
                });
                self.mixPayloadRaw(.{ .canonical = words });
                self.endOperation();
            }

            pub fn mixU32s(
                self: *TranscriptRowRecorderV2,
                words: []const u32,
            ) void {
                if (self.pending_pow != null) {
                    self.failure = self.failure orelse .invalid_state;
                    return;
                }
                self.startOperation(.mix_u32s, .{
                    self.lengthArg(words.len), 0, 0, 0,
                });
                self.mixPayloadRaw(.{ .u32s = words });
                self.endOperation();
            }

            pub fn mixFelts(
                self: *TranscriptRowRecorderV2,
                felts: []const QM31,
            ) void {
                if (self.pending_pow != null) {
                    self.failure = self.failure orelse .invalid_state;
                    return;
                }
                self.startOperation(.mix_felts, .{
                    self.lengthArg(felts.len), 0, 0, 0,
                });
                self.mixPayloadRaw(.{ .felts = felts });
                self.endOperation();
            }

            pub fn mixU64(self: *TranscriptRowRecorderV2, value: u64) void {
                if (self.pending_pow) |pending| {
                    if (pending.nonce != value) {
                        self.failure = self.failure orelse .invalid_state;
                        return;
                    }
                    // `verifyPowNonce` records the candidate mix/draw transaction.
                    // The production channel then persists that same nonce mix; do
                    // not emit or execute the identical permutation a second time.
                    self.digest = pending.absorbed_digest;
                    self.n_draws = 0;
                    self.pending_pow = null;
                    return;
                }
                self.startOperation(.mix_u64, .{ 0, 0, 0, 0 });
                self.mixPayloadRaw(.{ .u64_value = value });
                self.endOperation();
            }

            pub fn drawU32s(self: *TranscriptRowRecorderV2) Digest {
                const operation = self.next_draw_operation orelse NextDrawOperationV2{
                    .tag = TemporalTranscriptOperationTag.draw,
                    .args = .{ self.n_draws, 0, 0, 0 },
                };
                self.next_draw_operation = null;
                self.startOperation(operation.tag, operation.args);
                const output = self.recordFrame(.draw, .{
                    .draw_count = self.n_draws,
                }, false);
                self.n_draws +%= 1;
                self.endOperation();
                return output;
            }

            pub fn drawSecureFelt(self: *TranscriptRowRecorderV2) QM31 {
                const words = self.drawU32s();
                return QM31.fromU32Unchecked(words[0], words[1], words[2], words[3]);
            }

            pub fn verifyPowNonce(
                self: *TranscriptRowRecorderV2,
                bits: u32,
                nonce: u64,
            ) bool {
                if (bits > channel.MAX_POW_BITS or self.pending_pow != null)
                    return false;
                const original_digest = self.digest;
                const original_draw_count = self.n_draws;
                self.startOperation(.verify_pow, .{ bits, 0, 0, 0 });
                self.mixPayloadRaw(.{ .u64_value = nonce });
                const absorbed_digest = self.digest;
                const words = self.recordFrame(.draw, .{
                    .draw_count = self.n_draws,
                }, true);
                self.endOperation();
                const valid = @ctz(words[0]) >= bits;
                self.digest = original_digest;
                self.n_draws = original_draw_count;
                if (valid) self.pending_pow = .{
                    .nonce = nonce,
                    .absorbed_digest = absorbed_digest,
                };
                return valid;
            }

            pub fn takeRows(self: *TranscriptRowRecorderV2) Error![]TranscriptAirRow {
                try self.checkHealthy();
                if (self.pending_pow != null) return error.DanglingPowTransaction;
                try self.finishLane();
                return self.rows.toOwnedSlice(self.allocator);
            }

            pub fn takeOperations(
                self: *TranscriptRowRecorderV2,
            ) Error![]TranscriptControlRow {
                try self.checkHealthy();
                if (self.lane_open or self.current_operation != null)
                    return error.InvalidTranscriptRecorder;
                return self.operations.toOwnedSlice(self.allocator);
            }

            pub fn takeFrames(self: *TranscriptRowRecorderV2) Error![]RecordedFrameV2 {
                try self.checkHealthy();
                if (self.lane_open or self.current_operation != null)
                    return error.InvalidTranscriptRecorder;
                return self.frames.toOwnedSlice(self.allocator);
            }

            fn lengthArg(self: *TranscriptRowRecorderV2, length: usize) u32 {
                if (length >= m31.Modulus) {
                    self.failure = self.failure orelse .row_count_out_of_range;
                    return 0;
                }
                return @intCast(length);
            }

            pub fn annotateNextDraw(
                self: *TranscriptRowRecorderV2,
                tag: TemporalTranscriptOperationTag,
                args: [4]u32,
            ) void {
                if (self.next_draw_operation != null or
                    tag == .mix_canonical_words or tag == .mix_u32s or
                    tag == .mix_felts or tag == .mix_u64 or tag == .verify_pow)
                {
                    self.failure = self.failure orelse .invalid_state;
                    return;
                }
                self.next_draw_operation = .{ .tag = tag, .args = args };
            }

            fn startOperation(
                self: *TranscriptRowRecorderV2,
                tag: TemporalTranscriptOperationTag,
                args: [4]u32,
            ) void {
                if (!self.lane_open or self.current_operation != null or
                    self.operation_id >= m31.Modulus)
                {
                    self.failure = self.failure orelse .invalid_state;
                    return;
                }
                const operation = OperationContextV2{
                    .sequence = @as(u32, @intCast(self.operation_id)),
                    .tag = @intFromEnum(tag),
                    .args = args,
                };
                self.current_operation = operation;
                if (self.failure == null) {
                    self.operations.append(self.allocator, .{
                        .segment_mask = 0,
                        .binary_mask = 1,
                        .verifier_id = self.verifier_id,
                        .sequence = operation.sequence,
                        .tag = operation.tag,
                        .args = operation.args,
                        .terminal_mask = 0,
                    }) catch {
                        self.failure = .out_of_memory;
                    };
                }
                self.operation_id += 1;
            }

            fn endOperation(self: *TranscriptRowRecorderV2) void {
                if (self.current_operation == null) {
                    self.failure = self.failure orelse .invalid_state;
                    return;
                }
                self.current_operation = null;
            }

            fn finishLane(self: *TranscriptRowRecorderV2) Error!void {
                try self.checkHealthy();
                if (!self.lane_open) return;
                if (self.pending_pow != null) return error.DanglingPowTransaction;
                if (self.current_operation != null or self.next_draw_operation != null or
                    self.operations.items.len == self.lane_operation_start or
                    self.frames.items.len == self.lane_frame_start)
                {
                    return error.InvalidTranscriptRecorder;
                }
                self.operations.items[self.operations.items.len - 1].terminal_mask = 1;

                var mix_ordinal: u32 = 0;
                const frames = self.frames.items[self.lane_frame_start..];
                for (frames, 0..) |*frame, frame_index| {
                    if (frame.purpose == .mix) {
                        frame.input_state_key = mix_ordinal;
                        frame.output_state_key = mix_ordinal + 1;
                        frame.initial_mask = @intFromBool(mix_ordinal == 0);
                        frame.state_consume_mask = @intFromBool(mix_ordinal > 0);
                        var consumers: u32 = 0;
                        for (frames[frame_index + 1 ..]) |following| {
                            consumers += 1;
                            if (following.purpose == .mix) break;
                        }
                        frame.state_produce_multiplicity = consumers;
                        frame.draw_output_mask = 0;
                        mix_ordinal += 1;
                    } else {
                        if (mix_ordinal == 0) return error.InvalidTranscriptRecorder;
                        frame.input_state_key = mix_ordinal;
                        frame.output_state_key = mix_ordinal;
                        frame.initial_mask = 0;
                        frame.state_consume_mask = 1;
                        frame.state_produce_multiplicity = 0;
                        frame.draw_output_mask = @intFromBool(!frame.pow_draw);
                    }
                }
                self.lane_open = false;
            }

            pub fn checkHealthy(self: *const TranscriptRowRecorderV2) Error!void {
                if (self.failure) |failure| return switch (failure) {
                    .out_of_memory => error.OutOfMemory,
                    .row_count_out_of_range => error.RowCountOutOfRange,
                    .invalid_state => error.InvalidTranscriptRecorder,
                };
            }

            fn mixPayloadRaw(
                self: *TranscriptRowRecorderV2,
                payload: RecorderPayload,
            ) void {
                self.digest = self.recordFrame(.mix, payload, false);
                self.n_draws = 0;
            }

            fn recordFrame(
                self: *TranscriptRowRecorderV2,
                purpose: transcript_air.HashPurpose,
                payload: RecorderPayload,
                pow_draw: bool,
            ) Digest {
                const operation = self.current_operation orelse {
                    self.failure = self.failure orelse .invalid_state;
                    return .{0} ** channel.RATE;
                };
                const payload_count = payload.wordCount();
                const word_count = std.math.add(
                    usize,
                    channel.RATE,
                    payload_count,
                ) catch {
                    self.failure = self.failure orelse .row_count_out_of_range;
                    return .{0} ** channel.RATE;
                };
                const marked_count = std.math.add(usize, word_count, 1) catch {
                    self.failure = self.failure orelse .row_count_out_of_range;
                    return .{0} ** channel.RATE;
                };
                const call_count = std.math.divCeil(
                    usize,
                    marked_count,
                    channel.RATE,
                ) catch unreachable;
                if (self.call_id + call_count >= m31.Modulus or
                    self.hash_id >= m31.Modulus or payload_count >= m31.Modulus)
                {
                    self.failure = self.failure orelse .row_count_out_of_range;
                }

                var previous = [_]M31{M31.zero()} ** poseidon2.WIDTH;
                var input_digest: [channel.RATE]M31 = undefined;
                for (&input_digest, self.digest) |*destination, word|
                    destination.* = M31.fromCanonical(word);
                for (0..call_count) |step| {
                    var chunk: [channel.RATE]M31 = undefined;
                    for (&chunk, 0..) |*destination, lane| {
                        const index = step * channel.RATE + lane;
                        destination.* = if (index < channel.RATE)
                            M31.fromCanonical(self.digest[index])
                        else if (index < word_count)
                            payload.word(index - channel.RATE)
                        else if (index == word_count)
                            M31.one()
                        else
                            M31.zero();
                    }
                    var input = previous;
                    for (input[0..channel.RATE], chunk, 0..) |*lane, word, lane_index|
                        lane.* = previous[lane_index].add(word);
                    var output = input;
                    poseidon2.permute(&output);

                    if (self.failure == null) {
                        self.rows.append(self.allocator, .{
                            .enabler = 1,
                            .verifier_id = self.verifier_id,
                            .call_id = @intCast(self.call_id),
                            .hash_id = @intCast(self.hash_id),
                            .step = @intCast(step),
                            .is_first = @intFromBool(step == 0),
                            .is_last = @intFromBool(step + 1 == call_count),
                            .is_draw = @intFromBool(purpose == .draw),
                            .previous = previous,
                            .chunk = chunk,
                            .output = output,
                        }) catch {
                            self.failure = .out_of_memory;
                        };
                    }
                    previous = output;
                    self.call_id += 1;
                }
                self.hash_id += 1;

                var result: Digest = undefined;
                for (&result, previous[0..channel.RATE]) |*destination, word|
                    destination.* = word.toU32();
                if (self.failure == null) {
                    self.frames.append(self.allocator, .{
                        .verifier_id = self.verifier_id,
                        .sequence = operation.sequence,
                        .tag = operation.tag,
                        .args = operation.args,
                        .hash_id = @intCast(self.hash_id - 1),
                        .first_call_id = @intCast(self.call_id - call_count),
                        .call_count = @intCast(call_count),
                        .payload_word_count = @intCast(payload_count),
                        .purpose = purpose,
                        .pow_draw = pow_draw,
                        .input_digest = input_digest,
                        .output_digest = previous[0..channel.RATE].*,
                    }) catch {
                        self.failure = .out_of_memory;
                    };
                }
                return result;
            }
        };
    };
}
