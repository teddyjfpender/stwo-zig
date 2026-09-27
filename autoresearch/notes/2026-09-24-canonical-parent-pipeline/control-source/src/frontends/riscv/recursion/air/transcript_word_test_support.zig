//! Exactness, schedule, source-rigidity, and performance gates for row 4.

const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const m31 = stwo_core.fields.m31;
const QM31 = stwo_core.fields.qm31.QM31;
const degree = @import("../../air/lang/degree.zig");
const static_profile = @import("../../air/lang/static_profile.zig");
const types = @import("../../air/lang/types.zig");
const poseidon2 = @import("../../air/memory_commitment/poseidon2.zig");
const fixed_profile = @import("../fixed_profile.zig");
const protocol = @import("../protocol.zig");
const channel = @import("../poseidon2_channel.zig");
const component = @import("transcript_word.zig");
const interaction_mod = @import("transcript_word_relation.zig");
const witness = @import("transcript_word_witness.zig");
const trace_mod = @import("pow_frame_witness.zig");
const check_witness = @import("pow_check_witness.zig");
const schedule = @import("verifier_schedule.zig");
const support = @import("test_support.zig");

// Shared fixtures and mutation helpers for this conformance suite.

pub const FullFixture = struct {
    plans: PlanFixture,
    preprocessing: witness.Preprocessed,
    vm: TraceStorage,
    left: TraceStorage,
    right: TraceStorage,

    pub fn init(allocator: std.mem.Allocator) !FullFixture {
        var plans = try PlanFixture.init(allocator);
        errdefer plans.deinit();
        var preprocessing = try witness.Preprocessed.init(
            allocator,
            &plans.vm,
            &plans.recursion,
        );
        errdefer preprocessing.deinit();
        var vm = try TraceStorage.init(
            allocator,
            preprocessing.rows[0..preprocessing.vm_row_count],
            101,
        );
        errdefer vm.deinit();
        const left_start = preprocessing.vm_row_count;
        const right_start = left_start + preprocessing.recursion_row_count;
        var left = try TraceStorage.init(
            allocator,
            preprocessing.rows[left_start..right_start],
            211,
        );
        errdefer left.deinit();
        return .{
            .plans = plans,
            .preprocessing = preprocessing,
            .vm = vm,
            .left = left,
            .right = try TraceStorage.init(
                allocator,
                preprocessing.rows[right_start..],
                307,
            ),
        };
    }

    pub fn deinit(self: *FullFixture) void {
        self.right.deinit();
        self.left.deinit();
        self.vm.deinit();
        self.preprocessing.deinit();
        self.plans.deinit();
        self.* = undefined;
    }
};

pub const PlanFixture = struct {
    vm: schedule.Plan,
    recursion: schedule.Plan,

    pub fn init(allocator: std.mem.Allocator) !PlanFixture {
        const shape = try testShape();
        var vm = try schedule.Plan.init(
            allocator,
            try schedule.ProgramSpec.init(.vm, 3, 2, 3, 2),
            shape,
        );
        errdefer vm.deinit();
        return .{
            .vm = vm,
            .recursion = try schedule.Plan.init(
                allocator,
                try schedule.ProgramSpec.init(.recursion, 3, 0, 3, 2),
                shape,
            ),
        };
    }

    pub fn deinit(self: *PlanFixture) void {
        self.recursion.deinit();
        self.vm.deinit();
        self.* = undefined;
    }
};

pub const PendingPow = struct {
    nonce: u64,
    bits: u32,
};

pub const TraceStorage = struct {
    allocator: std.mem.Allocator,
    words: []M31,
    calls: []trace_mod.PoseidonCall,
    frames: []trace_mod.HashFrame,
    checks: []check_witness.Check,
    trace: witness.TranscriptTrace,

    pub fn init(
        allocator: std.mem.Allocator,
        lane_rows: []const witness.Row,
        seed: u32,
    ) !TraceStorage {
        var frame_count: usize = 0;
        var word_count: usize = 0;
        var call_count: usize = 0;
        var check_count: usize = 0;
        var row_at: usize = 0;
        while (row_at < lane_rows.len) {
            const end = groupEnd(lane_rows, row_at);
            const group = lane_rows[row_at..end];
            if (group[0].hash_id != frame_count) return error.InvalidTestFixture;
            const purpose = groupPurpose(group);
            const raw_count = rawWordCount(group, purpose);
            word_count = try std.math.add(usize, word_count, raw_count);
            call_count = try std.math.add(
                usize,
                call_count,
                @as(usize, @intCast(group[group.len - 1].word_index + 1)) /
                    component.RATE,
            );
            check_count += @intFromBool(
                purpose == .mix and (group[0].tag == 6 or group[0].tag == 20),
            );
            frame_count += 1;
            row_at = end;
        }

        const words = try allocator.alloc(M31, word_count);
        errdefer allocator.free(words);
        const calls = try allocator.alloc(trace_mod.PoseidonCall, call_count);
        errdefer allocator.free(calls);
        const frames = try allocator.alloc(trace_mod.HashFrame, frame_count);
        errdefer allocator.free(frames);
        const checks = try allocator.alloc(check_witness.Check, check_count);
        errdefer allocator.free(checks);

        var word_at: usize = 0;
        var call_at: usize = 0;
        var frame_at: usize = 0;
        var check_at: usize = 0;
        var pending_pow: ?PendingPow = null;
        row_at = 0;
        while (row_at < lane_rows.len) {
            const end = groupEnd(lane_rows, row_at);
            const group = lane_rows[row_at..end];
            const purpose = groupPurpose(group);
            const raw_count = rawWordCount(group, purpose);
            const frame_words = words[word_at..][0..raw_count];
            for (frame_words[0..component.DIGEST_WORD_COUNT], 0..) |*word, lane| {
                word.* = fixtureWord(seed, group[0].hash_id, @intCast(lane));
            }
            const nonce = fixtureNonce(seed, group[0].hash_id);
            for (component.DIGEST_WORD_COUNT..raw_count) |index| {
                const row = group[index - component.DIGEST_WORD_COUNT];
                if (row.word_index != index) return error.InvalidTestFixture;
                frame_words[index] = if (row.is_payload == 0)
                    M31.fromCanonical(row.constant_value)
                else if (group[0].tag == 6 or group[0].tag == 20)
                    M31.fromCanonical(@truncate(
                        (nonce >> @intCast(16 * row.payload_index)) & 0xffff,
                    ))
                else
                    fixtureWord(seed + 1, row.hash_id, row.payload_index);
            }

            const first_call = call_at;
            const expected_calls = @as(
                usize,
                @intCast(group[group.len - 1].word_index + 1),
            ) / component.RATE;
            var previous: [16]M31 = .{M31.zero()} ** 16;
            for (0..expected_calls) |step| {
                var input = previous;
                for (0..component.RATE) |lane| {
                    const stream_index = step * component.RATE + lane;
                    const chunk = if (stream_index < frame_words.len)
                        frame_words[stream_index]
                    else if (stream_index == frame_words.len)
                        M31.one()
                    else
                        M31.zero();
                    input[lane] = input[lane].add(chunk);
                }
                var output = input;
                poseidon2.permute(&output);
                calls[call_at] = .{
                    .id = .{
                        .call_id = @intCast(call_at),
                        .hash_id = @intCast(frame_at),
                        .step = @intCast(step),
                    },
                    .input = input,
                    .output = output,
                };
                previous = output;
                call_at += 1;
            }
            frames[frame_at] = .{
                .hash_id = @intCast(frame_at),
                .first_call_id = @intCast(first_call),
                .call_count = @intCast(expected_calls),
                .purpose = purpose,
                .words = frame_words,
                .output = previous,
            };
            if (purpose == .mix and (group[0].tag == 6 or group[0].tag == 20)) {
                if (pending_pow != null) return error.InvalidTestFixture;
                pending_pow = .{ .nonce = nonce, .bits = group[0].args[0] };
            } else if (purpose == .draw and pending_pow != null) {
                const pending = pending_pow.?;
                checks[check_at] = .{
                    .call_id = @intCast(call_at - 1),
                    .nonce = pending.nonce,
                    .bits = pending.bits,
                    .word = previous[0],
                };
                check_at += 1;
                pending_pow = null;
            }
            word_at += raw_count;
            frame_at += 1;
            row_at = end;
        }
        if (word_at != words.len or call_at != calls.len or
            frame_at != frames.len or check_at != checks.len or pending_pow != null)
        {
            return error.InvalidTestFixture;
        }
        const trace = witness.TranscriptTrace{
            .poseidon_calls = calls,
            .hash_frames = frames,
            .pow_checks = checks,
        };
        try trace.validate();
        return .{
            .allocator = allocator,
            .words = words,
            .calls = calls,
            .frames = frames,
            .checks = checks,
            .trace = trace,
        };
    }

    pub fn deinit(self: *TraceStorage) void {
        self.allocator.free(self.checks);
        self.allocator.free(self.frames);
        self.allocator.free(self.calls);
        self.allocator.free(self.words);
        self.* = undefined;
    }
};

pub fn groupEnd(rows: []const witness.Row, start: usize) usize {
    const hash_id = rows[start].hash_id;
    var end = start + 1;
    while (end < rows.len and rows[end].hash_id == hash_id) end += 1;
    return end;
}

pub fn groupPurpose(rows: []const witness.Row) trace_mod.HashPurpose {
    return if (rows[0].constant_value == component.TRANSCRIPT_OPERATION_TAG)
        .mix
    else
        .draw;
}

pub fn rawWordCount(
    rows: []const witness.Row,
    purpose: trace_mod.HashPurpose,
) usize {
    if (purpose == .draw) return component.RATE + 2;
    var payload_count: usize = 0;
    for (rows) |row| payload_count += @intFromBool(row.is_payload == 1);
    return 2 * component.RATE + payload_count;
}

pub fn fixtureNonce(seed: u32, hash_id: u32) u64 {
    return (@as(u64, seed) << 32) | hash_id;
}

pub fn fixtureWord(seed: u32, hash_id: u32, index: u32) M31 {
    const wide = @as(u64, seed) * 65_537 +
        @as(u64, hash_id) * 257 + @as(u64, index) + 1;
    return M31.fromCanonical(@intCast(wide % (m31.Modulus - 1) + 1));
}

pub fn findRow(
    preprocessing: *const witness.Preprocessed,
    verifier_id: u32,
    is_payload: u32,
    require_nonzero_constant: bool,
) usize {
    for (preprocessing.rows, 0..) |row, index| {
        if (row.verifier_id == verifier_id and row.is_payload == is_payload and
            (!require_nonzero_constant or is_payload == 1 or row.constant_value != 0))
        {
            return index;
        }
    }
    unreachable;
}

pub fn expectBatchValues(
    preprocessing: *const witness.Preprocessed,
    batch: *const witness.PreparedBatch,
    kind: witness.ProofKind,
    source: witness.Source,
) !void {
    try std.testing.expectEqual(preprocessing.rows.len, batch.values.len);
    for (preprocessing.rows, batch.values) |row, value| {
        const active = switch (kind) {
            .segment_leaf => row.segment_mask == 1,
            .binary_node => row.binary_mask == 1,
            .empty_leaf => false,
        };
        if (!active or row.is_payload == 0) {
            try std.testing.expect(value.isZero());
            continue;
        }
        const trace: *const witness.TranscriptTrace = switch (source) {
            .segment_leaf => |trace| trace,
            .binary_node => |binary| if (row.verifier_id == witness.LEFT_RECURSION_VERIFIER_ID)
                binary.left
            else
                binary.right,
            .empty_leaf => unreachable,
        };
        try std.testing.expect(value.eql(
            trace.hash_frames[row.hash_id].words[row.word_index],
        ));
    }
}

pub fn expectSatisfied(
    definition: *const component.Definition,
    row: [component.LOGICAL_INPUT_COUNT]M31,
) !void {
    const values = try support.evaluateArena(std.testing.allocator, &definition.arena, &row);
    defer std.testing.allocator.free(values);
    for (definition.roots) |root|
        try std.testing.expect(values[types.idIndex(root)].isZero());
}

pub fn expectAnyRootNonzero(
    definition: *const component.Definition,
    row: [component.LOGICAL_INPUT_COUNT]M31,
) !void {
    const values = try support.evaluateArena(std.testing.allocator, &definition.arena, &row);
    defer std.testing.allocator.free(values);
    for (definition.roots) |root| {
        if (!values[types.idIndex(root)].isZero()) return;
    }
    return error.TestUnexpectedResult;
}

pub fn splitColumns(
    comptime count: usize,
    size: usize,
    storage: []M31,
    columns: *[count][]M31,
) void {
    for (columns, 0..) |*column, index|
        column.* = storage[index * size ..][0..size];
}

pub fn componentFailureCase(allocator: std.mem.Allocator) !void {
    var definition = try component.build(allocator);
    defer definition.deinit();
}

pub fn preprocessingFailureCase(
    allocator: std.mem.Allocator,
    vm: *const schedule.Plan,
    recursion: *const schedule.Plan,
) !void {
    var preprocessing = try witness.Preprocessed.init(allocator, vm, recursion);
    defer preprocessing.deinit();
}

pub fn batchFailureCase(
    allocator: std.mem.Allocator,
    preprocessing: *const witness.Preprocessed,
    vm: *const schedule.Plan,
    recursion: *const schedule.Plan,
    source: witness.Source,
) !void {
    var batch = try witness.PreparedBatch.init(
        allocator,
        preprocessing,
        vm,
        recursion,
        source,
    );
    defer batch.deinit();
}

pub fn testShape() !fixed_profile.ProofShapeV1 {
    const fri = try fixed_profile.FriSchedule.init(8, protocol.PCS_CONFIG.fri_config);
    return .{
        .air_program_id = channel.hashBytes("word-air", 0x5450),
        .preprocessing_id = channel.hashBytes("word-pre", 0x5450),
        .table_layout_id = channel.hashBytes("word-layout", 0x5450),
        .table_count = 16,
        .claimed_sum_count = 4,
        .sampled_value_count = 8,
        .preprocessed_column_count = 4,
        .tree_column_counts = .{ 4, 4, 4, 4 },
        .tree_heights = .{ 9, 9, 9, 9 },
        .column_log_degree = 8,
        .proof_wire_bytes = 1024,
        .fri = fri,
    };
}
