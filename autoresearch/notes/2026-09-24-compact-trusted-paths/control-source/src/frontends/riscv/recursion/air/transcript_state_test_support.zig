//! Exactness, cancellation, mutation, and performance gates for universal row 3.

const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const degree = @import("../../air/lang/degree.zig");
const digest = @import("../../air/lang/digest.zig");
const relation = @import("../../air/lang/relation.zig");
const static_profile = @import("../../air/lang/static_profile.zig");
const component = @import("transcript_state.zig");
const direct_program = @import("direct_constraint_program.zig");
const interaction_mod = @import("transcript_state_relation.zig");
const binding_component = @import("transcript_binding.zig");
const binding_relation = @import("transcript_binding_relation.zig");
const binding_witness = @import("transcript_binding_witness.zig");
const pow_check_witness = @import("pow_check_witness.zig");
const pow_frame_witness = @import("pow_frame_witness.zig");
const challenge_component = @import("relation_challenge.zig");
const challenge_relation = @import("relation_challenge_relation.zig");
const challenge_witness = @import("relation_challenge_witness.zig");
const schedule = @import("verifier_schedule.zig");
const universal = @import("universal_challenges.zig");
const witness = @import("transcript_state_witness.zig");

// Shared fixtures and mutation helpers for this conformance suite.

pub const Fixture = struct {
    vm: schedule.Plan,
    recursion: schedule.Plan,
    call_preprocessing: binding_witness.Preprocessed,
    preprocessing: witness.Preprocessed,
    segment: OwnedTrace,
    left: OwnedTrace,
    right: OwnedTrace,

    pub fn init(allocator: std.mem.Allocator) !Fixture {
        const shape = try testShape();
        var vm = try schedule.Plan.init(
            allocator,
            try schedule.ProgramSpec.init(.vm, 4, 2, 3, 2),
            shape,
        );
        errdefer vm.deinit();
        var recursion = try schedule.Plan.init(
            allocator,
            try schedule.ProgramSpec.init(.recursion, 4, 0, 3, 2),
            shape,
        );
        errdefer recursion.deinit();
        var call_preprocessing = try binding_witness.Preprocessed.init(
            allocator,
            &vm,
            &recursion,
        );
        errdefer call_preprocessing.deinit();
        var preprocessing = try witness.Preprocessed.init(allocator, &call_preprocessing);
        errdefer preprocessing.deinit();
        var segment = try OwnedTrace.init(
            allocator,
            &vm,
            call_preprocessing.rows[0..call_preprocessing.vm_call_count],
            1000,
        );
        errdefer segment.deinit();
        const recursion_start = call_preprocessing.vm_call_count;
        const recursion_rows = call_preprocessing.rows[recursion_start .. recursion_start + call_preprocessing.recursion_call_count];
        var left = try OwnedTrace.init(allocator, &recursion, recursion_rows, 3000);
        errdefer left.deinit();
        return .{
            .vm = vm,
            .recursion = recursion,
            .call_preprocessing = call_preprocessing,
            .preprocessing = preprocessing,
            .segment = segment,
            .left = left,
            .right = try OwnedTrace.init(allocator, &recursion, recursion_rows, 5000),
        };
    }

    pub fn deinit(self: *Fixture) void {
        self.right.deinit();
        self.left.deinit();
        self.segment.deinit();
        self.preprocessing.deinit();
        self.call_preprocessing.deinit();
        self.recursion.deinit();
        self.vm.deinit();
        self.* = undefined;
    }

    pub fn segmentSource(self: *const Fixture) witness.Source {
        return .{ .segment_leaf = .{ .plan = &self.vm, .trace = &self.segment.trace } };
    }

    pub fn binarySource(self: *const Fixture) witness.Source {
        return .{ .binary_node = .{
            .left = .{ .plan = &self.recursion, .trace = &self.left.trace },
            .right = .{ .plan = &self.recursion, .trace = &self.right.trace },
        } };
    }

    pub fn segmentBindingSource(self: *const Fixture) binding_witness.Source {
        return .{ .segment_leaf = .{ .plan = &self.vm, .trace = &self.segment.trace } };
    }
};

pub const OwnedTrace = struct {
    allocator: std.mem.Allocator,
    trace: witness.TranscriptTrace,
    word_storage: [][]M31,

    pub fn init(
        allocator: std.mem.Allocator,
        plan: *const schedule.Plan,
        rows: []const binding_witness.PreprocessedRow,
        seed: u32,
    ) !OwnedTrace {
        var frame_count: usize = 0;
        var pow_count: usize = 0;
        for (rows) |row| {
            frame_count += @intFromBool(row.is_first == 1);
            pow_count += @intFromBool(row.pow_final_mask == 1);
        }
        const calls = try allocator.alloc(witness.PoseidonCall, rows.len);
        errdefer allocator.free(calls);
        const frames = try allocator.alloc(witness.HashFrame, frame_count);
        errdefer allocator.free(frames);
        const checks = try allocator.alloc(pow_check_witness.Check, pow_count);
        errdefer allocator.free(checks);
        const word_storage = try allocator.alloc([]M31, frame_count);
        var initialized_words: usize = 0;
        errdefer {
            for (word_storage[0..initialized_words]) |words| allocator.free(words);
            allocator.free(word_storage);
        }

        var digest_state = [_]M31{M31.zero()} ** witness.RATE;
        var row_at: usize = 0;
        var frame_at: usize = 0;
        var pow_at: usize = 0;
        while (row_at < rows.len) : (frame_at += 1) {
            const first = rows[row_at];
            if (first.is_first != 1 or first.hash_id != frame_at)
                return error.InvalidFixtureLayout;
            var end = row_at;
            while (end < rows.len and rows[end].is_last == 0) : (end += 1) {}
            if (end >= rows.len) return error.InvalidFixtureLayout;
            const call_count = end - row_at + 1;
            const step = plan.steps[first.sequence];
            const draw = first.is_draw == 1;
            const stream_count = try testStreamWordCount(plan, step, draw);
            const words = try allocator.alloc(M31, stream_count);
            word_storage[frame_at] = words;
            initialized_words += 1;
            fillFrameWords(words, step, first.sequence, draw, seed, frame_at, digest_state);

            var previous = [_]M31{M31.zero()} ** witness.WIDTH;
            for (0..call_count) |frame_step| {
                const call_index = row_at + frame_step;
                const metadata = rows[call_index];
                var input = previous;
                for (0..witness.RATE) |lane| {
                    const stream_index = frame_step * witness.RATE + lane;
                    const chunk = if (stream_index < words.len)
                        words[stream_index]
                    else if (stream_index == words.len)
                        M31.one()
                    else
                        M31.zero();
                    input[lane] = input[lane].add(chunk);
                }
                var output: [witness.WIDTH]M31 = undefined;
                for (&output, 0..) |*word, lane| word.* = M31.fromU64(
                    @as(u64, seed) + 1 + 97 * call_index + 3 * lane,
                );
                calls[call_index] = .{
                    .id = .{
                        .call_id = metadata.call_id,
                        .hash_id = metadata.hash_id,
                        .step = metadata.hash_step,
                    },
                    .input = input,
                    .output = output,
                };
                previous = output;
            }
            frames[frame_at] = .{
                .hash_id = first.hash_id,
                .first_call_id = first.call_id,
                .call_count = @intCast(call_count),
                .purpose = if (draw) .draw else .mix,
                .words = words,
                .output = previous,
            };
            if (!draw) digest_state = previous[0..witness.RATE].*;
            if (rows[end].pow_final_mask == 1) {
                const bits = switch (step) {
                    .verify_and_absorb_interaction_pow => |item| item.bits,
                    .verify_and_absorb_pcs_pow => |item| item.bits,
                    else => return error.InvalidFixtureLayout,
                };
                checks[pow_at] = .{
                    .call_id = rows[end].call_id,
                    .nonce = @as(u64, seed) << 32 | pow_at,
                    .bits = bits,
                    .word = previous[0],
                };
                pow_at += 1;
            }
            row_at = end + 1;
        }
        if (frame_at != frames.len or pow_at != checks.len)
            return error.InvalidFixtureLayout;
        const trace = witness.TranscriptTrace{
            .poseidon_calls = calls,
            .hash_frames = frames,
            .pow_checks = checks,
        };
        try trace.validate();
        return .{
            .allocator = allocator,
            .trace = trace,
            .word_storage = word_storage,
        };
    }

    pub fn deinit(self: *OwnedTrace) void {
        for (self.word_storage) |words| self.allocator.free(words);
        self.allocator.free(self.word_storage);
        self.allocator.free(self.trace.pow_checks);
        self.allocator.free(self.trace.hash_frames);
        self.allocator.free(self.trace.poseidon_calls);
        self.* = undefined;
    }
};

pub fn fillFrameWords(
    words: []M31,
    step: schedule.VerifierStep,
    sequence: u32,
    draw: bool,
    seed: u32,
    frame: usize,
    digest_state: [witness.RATE]M31,
) void {
    for (words, 0..) |*word, index|
        word.* = M31.fromU64(@as(u64, seed) + 11 * frame + index + 1);
    @memcpy(words[0..witness.RATE], &digest_state);
    if (draw) {
        words[witness.RATE] = M31.zero();
        words[witness.RATE + 1] = M31.fromCanonical(pow_frame_witness.DRAW_TAG);
        return;
    }
    const encoded = step.encode();
    const header = [_]u32{
        0x5452,
        sequence,
        encoded.tag,
        encoded.arity,
        encoded.args[0],
        encoded.args[1],
        encoded.args[2],
        encoded.args[3],
    };
    for (header, 0..) |value, index|
        words[witness.RATE + index] = M31.fromCanonical(value);
}

pub fn testStreamWordCount(
    plan: *const schedule.Plan,
    step: schedule.VerifierStep,
    draw: bool,
) !usize {
    if (draw) return witness.RATE + 2;
    const payload: usize = switch (step) {
        .bind_protocol => 16,
        .bind_statement => 412,
        .bind_pcs_parameters => 16,
        .absorb_trace_commitment, .absorb_fri_commitment => 8,
        .absorb_public_claim => if (plan.schema == .vm) 8 else 0,
        .verify_and_absorb_interaction_pow, .verify_and_absorb_pcs_pow => 4,
        .absorb_claimed_sums => |item| try mulFour(item.count),
        .absorb_sampled_values => |item| try mulFour(item.count),
        .absorb_last_layer_coefficients => |item| try mulFour(item.count),
        .draw_relation_challenge,
        .draw_composition_randomness,
        .draw_oods_point,
        .draw_deep_randomness,
        .draw_fri_alpha,
        .draw_query_block,
        => 0,
        else => return error.InvalidFixtureLayout,
    };
    return 16 + payload;
}

pub fn mulFour(count: u32) !usize {
    return std.math.mul(usize, count, 4) catch error.InvalidFixtureLayout;
}

pub fn testShape() !@import("../fixed_profile.zig").ProofShapeV1 {
    const fixed_profile = @import("../fixed_profile.zig");
    const protocol = @import("../protocol.zig");
    const channel = @import("../poseidon2_channel.zig");
    const fri = try fixed_profile.FriSchedule.init(8, protocol.PCS_CONFIG.fri_config);
    return .{
        .air_program_id = channel.hashBytes("transcript-state-air", 0x5450),
        .preprocessing_id = channel.hashBytes("transcript-state-preprocessing", 0x5450),
        .table_layout_id = channel.hashBytes("transcript-state-layout", 0x5450),
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

pub fn stateEntriesAt(
    plan: *const interaction_mod.Plan,
    definition: *const component.Definition,
    main: *const witness.MainWitness,
    preprocessing: *const witness.Preprocessed,
    index: usize,
) ![component.RELATION_EVENT_COUNT]interaction_mod.Entry {
    return plan.entries(
        &definition.arena,
        component.SEMANTIC_DIGEST,
        definition.events,
        witness.logicalInputs(main.rows[index], preprocessing.rows[index], .segment_leaf),
    );
}

pub fn expectEntryCancellation(lhs: interaction_mod.Entry, rhs: anytype) !void {
    try std.testing.expect(lhs.numerator.add(rhs.numerator).isZero());
    try expectSameTuple(lhs, rhs);
}

pub fn expectSameTuple(lhs: anytype, rhs: anytype) !void {
    try std.testing.expectEqual(lhs.arity, rhs.arity);
    for (0..lhs.arity) |index|
        try std.testing.expect(lhs.values[index].eql(rhs.values[index]));
}

pub fn findCall(
    rows: []const binding_witness.PreprocessedRow,
    hash_id: u32,
    last: bool,
) ?usize {
    for (rows, 0..) |row, index| {
        if (row.hash_id == hash_id and
            (if (last) row.is_last == 1 else row.is_first == 1)) return index;
    }
    return null;
}

pub fn findDoubleProducer(rows: []const witness.PreprocessedRow) ?usize {
    for (rows, 0..) |row, index| {
        if (row.state_produce_multiplicity == 2 and index + 2 < rows.len)
            return index;
    }
    return null;
}

pub fn findDrawTag(rows: []const witness.PreprocessedRow, tag: u32) ?usize {
    for (rows, 0..) |row, index| {
        if (row.draw_output_mask == 1 and row.tag == tag) return index;
    }
    return null;
}

pub fn findNonInitialActive(rows: []const witness.PreprocessedRow) ?usize {
    for (rows, 0..) |row, index| if (row.initial_mask == 0) return index;
    return null;
}

pub fn assertPreprocessedWriter(
    executor: *const witness.Executor,
    preprocessing: *const witness.Preprocessed,
) !void {
    const size = @as(usize, 1) << @intCast(preprocessing.log_size);
    const count = witness.PREPROCESSED_COLUMN_COUNT;
    const storage = try std.testing.allocator.alloc(M31, count * size);
    defer std.testing.allocator.free(storage);
    var columns: [count][]M31 = undefined;
    splitColumns(count, size, storage, &columns);
    try executor.generatePreprocessedInto(preprocessing, &columns);
    for (columns) |column| for (column[preprocessing.rows.len..]) |padding|
        try std.testing.expect(padding.isZero());
    const sentinel = M31.fromCanonical(12345);
    @memset(storage, sentinel);
    var malformed = columns;
    malformed[0] = malformed[0][0 .. size - 1];
    try std.testing.expectError(
        error.InvalidTraceShape,
        executor.generatePreprocessedInto(preprocessing, &malformed),
    );
    for (storage) |value| try std.testing.expect(value.eql(sentinel));
    var aliased = columns;
    aliased[1] = aliased[0];
    try std.testing.expectError(
        error.AliasedDestination,
        executor.generatePreprocessedInto(preprocessing, &aliased),
    );
    for (storage) |value| try std.testing.expect(value.eql(sentinel));
}

pub fn assertMainWriter(
    executor: *const witness.Executor,
    main: *const witness.MainWitness,
    preprocessing: *const witness.Preprocessed,
) !void {
    const size = @as(usize, 1) << @intCast(preprocessing.log_size);
    const count = witness.MAIN_COLUMN_COUNT;
    const storage = try std.testing.allocator.alloc(M31, count * size);
    defer std.testing.allocator.free(storage);
    var columns: [count][]M31 = undefined;
    splitColumns(count, size, storage, &columns);
    try executor.generateMainInto(main, preprocessing, &columns);
    for (columns) |column| for (column[main.rows.len..]) |padding|
        try std.testing.expect(padding.isZero());
    const sentinel = M31.fromCanonical(12345);
    @memset(storage, sentinel);
    var malformed = columns;
    malformed[0] = malformed[0][0 .. size - 1];
    try std.testing.expectError(
        error.InvalidTraceShape,
        executor.generateMainInto(main, preprocessing, &malformed),
    );
    for (storage) |value| try std.testing.expect(value.eql(sentinel));
    var aliased = columns;
    aliased[1] = aliased[0];
    try std.testing.expectError(
        error.AliasedDestination,
        executor.generateMainInto(main, preprocessing, &aliased),
    );
    for (storage) |value| try std.testing.expect(value.eql(sentinel));
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
    calls: *const binding_witness.Preprocessed,
) !void {
    var preprocessing = try witness.Preprocessed.init(allocator, calls);
    defer preprocessing.deinit();
}

pub fn mainFailureCase(
    allocator: std.mem.Allocator,
    preprocessing: *const witness.Preprocessed,
    source_value: witness.Source,
) !void {
    var main = try witness.MainWitness.init(allocator, preprocessing, source_value);
    defer main.deinit();
}

pub fn interactionFailureCase(
    allocator: std.mem.Allocator,
    definition: *const component.Definition,
    plan: *const interaction_mod.Plan,
    rows: []const interaction_mod.Row,
    log_size: u32,
    relations: *const universal.UniversalRelations,
) !void {
    var interaction = try plan.generateInteraction(
        allocator,
        &definition.arena,
        component.SEMANTIC_DIGEST,
        definition.events,
        rows,
        log_size,
        relations,
    );
    defer interaction.deinit(allocator);
}
