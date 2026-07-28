const std = @import("std");
const common = @import("stwo_cuda_backend").runtime.stages.common;
const telemetry = @import("stwo_cuda_backend").runtime.telemetry;
const subject = @import("controller.zig");
const schedule_mod = @import("schedule.zig");
const fixture = @import("test_fixture.zig");

const CallKind = enum {
    mix,
    draw_secure,
    grind_pow,
    absorb_pow,
    draw_queries,
};

const Call = struct {
    kind: CallKind,
    stage: telemetry.Stage,
    step: u32,
    words: usize,
};

const FakeSession = struct {
    active_stage: telemetry.Stage = .trace_commit,
    calls: [64]Call = undefined,
    call_count: usize = 0,
    initial_chain: u64 = 0,

    fn append(
        self: *@This(),
        kind: CallKind,
        stage: telemetry.Stage,
        step: u32,
        word_count: usize,
    ) !void {
        if (stage != self.active_stage)
            return error.StageOrderViolation;
        self.calls[self.call_count] = .{
            .kind = kind,
            .stage = stage,
            .step = step,
            .words = word_count,
        };
        self.call_count += 1;
    }
};

const FakeTranscript = struct {
    pub fn initialize(
        session: *FakeSession,
        stage: telemetry.Stage,
        _: common.Words,
        seed: ?common.Words,
        seed_snapshot: ?common.Words,
        initial_chain: u64,
    ) !void {
        if (stage != session.active_stage or
            seed != null or seed_snapshot != null)
        {
            return error.InvalidInitialization;
        }
        session.initial_chain = initial_chain;
    }

    pub fn mixWords(
        session: *FakeSession,
        stage: telemetry.Stage,
        _: common.Words,
        boundary: anytype,
        source: common.Words,
        validate_m31: bool,
        snapshot: common.Words,
    ) !void {
        const expected_validation =
            boundary.expected_step == 13 or
            boundary.expected_step == 18 or
            boundary.expected_step == 36;
        if (!same(source, snapshot) or
            validate_m31 != expected_validation)
        {
            return error.DetachedInputSnapshot;
        }
        try session.append(
            .mix,
            stage,
            boundary.expected_step,
            source.len,
        );
    }

    pub fn drawSecure(
        session: *FakeSession,
        stage: telemetry.Stage,
        _: common.Words,
        boundary: anytype,
        felt_count: u32,
        rejection_rounds: u32,
        output: common.SecureFields,
        snapshot: common.SecureFields,
    ) !void {
        if (rejection_rounds != schedule_mod.max_rejection_rounds or
            !same(output, snapshot))
        {
            return error.InvalidChallengeDraw;
        }
        try session.append(
            .draw_secure,
            stage,
            boundary.expected_step,
            felt_count * 4,
        );
    }

    pub fn absorbPowAtStage(
        session: *FakeSession,
        stage: telemetry.Stage,
        _: common.Words,
        boundary: anytype,
        nonce_words: common.Words,
        _: u32,
        snapshot: common.Words,
    ) !void {
        if (!same(nonce_words, snapshot))
            return error.DetachedInputSnapshot;
        try session.append(
            .absorb_pow,
            stage,
            boundary.expected_step,
            nonce_words.len,
        );
    }

    pub fn drawQueries(
        session: *FakeSession,
        _: common.Words,
        boundary: anytype,
        _: u32,
        output: common.Words,
        snapshot: common.Words,
    ) !void {
        if (!same(output, snapshot))
            return error.DetachedOutputSnapshot;
        try session.append(
            .draw_queries,
            .decommit,
            boundary.expected_step,
            output.len,
        );
    }
};

const FakeFri = struct {
    pub fn grindPowAtStage(
        session: *FakeSession,
        stage: telemetry.Stage,
        _: common.Words,
        _: u32,
        search_end: u64,
        _: common.Words,
        _: common.Nonce,
        _: common.Words,
        nonce_words: common.Words,
    ) !void {
        if (search_end != subject.pow_search_end)
            return error.InvalidPowRange;
        try session.append(
            .grind_pow,
            stage,
            std.math.maxInt(u32),
            nonce_words.len,
        );
    }
};

test "controller executes all 39 SN2 operations without host challenges" {
    const allocator = std.testing.allocator;
    const protocol = try fixture.protocol();
    var program = try fixture.program(allocator, protocol);
    defer program.deinit(allocator);
    const schedule = try schedule_mod.Schedule.init(program, protocol);
    const view = try subject.View.bind(words(0x1000, 64));
    var cursor = subject.Cursor{};
    var session = FakeSession{};
    try subject.initialize(
        FakeTranscript,
        &session,
        schedule,
        &cursor,
        view,
    );
    try executeRemaining(
        &session,
        schedule,
        &cursor,
        view,
    );

    try std.testing.expect(cursor.complete(schedule));
    try std.testing.expectEqual(
        schedule.initialChain(),
        session.initial_chain,
    );
    // Every transcript operation dispatches once; each PoW also grinds once.
    try std.testing.expectEqual(@as(usize, 41), session.call_count);
    var transcript_calls: usize = 0;
    var pow_grinds: usize = 0;
    var expected_step: u32 = 0;
    for (session.calls[0..session.call_count]) |call| {
        if (call.kind == .grind_pow) {
            pow_grinds += 1;
            continue;
        }
        try std.testing.expectEqual(expected_step, call.step);
        expected_step += 1;
        transcript_calls += 1;
    }
    try std.testing.expectEqual(@as(usize, 2), pow_grinds);
    try std.testing.expectEqual(@as(usize, 39), transcript_calls);
    try std.testing.expectEqual(@as(u32, 39), expected_step);
}

test "controller rejects ordinal stage and payload drift before dispatch" {
    const allocator = std.testing.allocator;
    const protocol = try fixture.protocol();
    var program = try fixture.program(allocator, protocol);
    defer program.deinit(allocator);
    const schedule = try schedule_mod.Schedule.init(program, protocol);
    const view = try subject.View.bind(words(0x1000, 64));
    var cursor = subject.Cursor{};
    var session = FakeSession{};
    try subject.initialize(
        FakeTranscript,
        &session,
        schedule,
        &cursor,
        view,
    );

    try std.testing.expectError(
        error.InvalidTranscriptOperation,
        subject.mixInput(
            FakeTranscript,
            &session,
            .trace_commit,
            schedule,
            &cursor,
            view,
            2,
            words(0x2000, 4),
        ),
    );
    try std.testing.expectError(
        error.InvalidTranscriptStage,
        subject.mixInput(
            FakeTranscript,
            &session,
            .oods,
            schedule,
            &cursor,
            view,
            1,
            words(0x2000, 4),
        ),
    );
    try std.testing.expectError(
        error.InvalidTranscriptPayload,
        subject.mixInput(
            FakeTranscript,
            &session,
            .trace_commit,
            schedule,
            &cursor,
            view,
            1,
            words(0x2000, 3),
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), session.call_count);
    try std.testing.expectEqual(@as(u32, 0), cursor.next_step);
}

test "execution evidence requires complete authenticated AOT zero-fallback run" {
    const allocator = std.testing.allocator;
    const protocol = try fixture.protocol();
    var program = try fixture.program(allocator, protocol);
    defer program.deinit(allocator);
    const schedule = try schedule_mod.Schedule.init(program, protocol);
    const view = try subject.View.bind(words(0x1000, 64));
    var cursor = subject.Cursor{};
    var session = FakeSession{};
    try subject.initialize(
        FakeTranscript,
        &session,
        schedule,
        &cursor,
        view,
    );
    try executeRemaining(
        &session,
        schedule,
        &cursor,
        view,
    );
    const authority = subject.AotAuthority{
        .manifest_identity = [_]u8{0x41} ** 32,
        .binary_identity = [_]u8{0x42} ** 32,
    };
    const measurement = subject.Measurement{
        .measured = true,
        .observed_manifest_identity = authority.manifest_identity,
        .observed_binary_identity = authority.binary_identity,
        .runtime_compile_attempts = 0,
        .cpu_fallback_attempts = 0,
    };
    const evidence = try subject.Evidence.seal(
        schedule,
        cursor,
        authority,
        measurement,
    );
    try evidence.validate(schedule);

    var compile_observed = measurement;
    compile_observed.runtime_compile_attempts = 1;
    try std.testing.expectError(
        error.InvalidTranscriptExecutionEvidence,
        subject.Evidence.seal(
            schedule,
            cursor,
            authority,
            compile_observed,
        ),
    );
    var fallback_observed = measurement;
    fallback_observed.cpu_fallback_attempts = 1;
    try std.testing.expectError(
        error.InvalidTranscriptExecutionEvidence,
        subject.Evidence.seal(
            schedule,
            cursor,
            authority,
            fallback_observed,
        ),
    );
    var wrong_binary = measurement;
    wrong_binary.observed_binary_identity[0] ^= 1;
    try std.testing.expectError(
        error.InvalidTranscriptExecutionEvidence,
        subject.Evidence.seal(
            schedule,
            cursor,
            authority,
            wrong_binary,
        ),
    );
    var forged = evidence;
    forged.completed_operations -= 1;
    try std.testing.expectError(
        error.InvalidTranscriptExecutionEvidence,
        forged.validate(schedule),
    );
}

test "transcript view uses a bounded resident sub-layout" {
    const view = try subject.View.bind(words(0x1000, 64));
    try std.testing.expectEqual(@as(usize, 0x1000), view.state.address);
    try std.testing.expectEqual(
        @as(usize, 0x1040),
        view.boundary_snapshot.address,
    );
    try std.testing.expectError(
        error.InvalidTranscriptStorage,
        subject.View.bind(words(0x1000, 31)),
    );
}

fn executeRemaining(
    session: *FakeSession,
    schedule: schedule_mod.Schedule,
    cursor: *subject.Cursor,
    view: subject.View,
) !void {
    while (cursor.next_step < schedule.operation_count) {
        const step = cursor.next_step;
        const stage = try schedule.stage(step);
        session.active_stage = stage;
        switch (try schedule.operation(step)) {
            .mix_bootstrap,
            .mix_interaction_claims,
            .mix_interaction_root,
            .mix_composition_root,
            .mix_sampled_values,
            .mix_fri_root,
            .mix_last_layer,
            => try subject.mixInput(
                FakeTranscript,
                session,
                stage,
                schedule,
                cursor,
                view,
                (try schedule.inputOrdinal(step)).?,
                words(0x2000, inputWords(schedule, step)),
            ),
            .draw_relation_elements,
            .draw_composition_alpha,
            .draw_oods_point,
            .draw_quotient_alpha,
            .draw_fri_alpha,
            => try subject.drawSecure(
                FakeTranscript,
                session,
                stage,
                schedule,
                cursor,
                view,
                (try schedule.outputOrdinal(step)).?,
                secure(
                    0x3000,
                    (try schedule.secureFeltCount(step)).?,
                ),
            ),
            .absorb_interaction_pow, .absorb_query_pow => try subject.executePow(
                FakeFri,
                FakeTranscript,
                session,
                stage,
                schedule,
                cursor,
                view,
                .{
                    .prefix_digest = words(0x4000, 8),
                    .best_nonce = nonce(0x5000),
                    .completed_blocks = words(0x6000, 1),
                    .transcript_nonce = words(0x7000, 2),
                },
            ),
            .draw_queries => try subject.drawQueries(
                FakeTranscript,
                session,
                schedule,
                cursor,
                view,
                5,
                words(0x8000, schedule.protocol.query_count),
            ),
        }
    }
}

fn inputWords(
    schedule: schedule_mod.Schedule,
    step: u32,
) usize {
    const ordinal = (schedule.inputOrdinal(step) catch unreachable).?;
    return switch (ordinal) {
        1 => 4,
        2 => 8,
        3, 15, 16, 20, 23, 24 => 8,
        10, 13 => 4,
        11 => 84,
        12 => 60,
        14 => 56,
        22 => schedule.protocol.interaction_sum_count * 4,
        25 => schedule.protocol.sampled_value_words,
        30 => schedule.protocol.final_line_coefficient_count * 4,
        else => if (ordinal >= 65_536) 8 else unreachable,
    };
}

fn words(address: usize, len: usize) common.Words {
    return .{
        .address = address,
        .len = len,
        .owner = 1,
        .generation = 1,
    };
}

fn secure(address: usize, len: usize) common.SecureFields {
    return .{
        .address = address,
        .len = len,
        .owner = 1,
        .generation = 1,
    };
}

fn nonce(address: usize) common.Nonce {
    return .{
        .address = address,
        .len = 1,
        .owner = 1,
        .generation = 1,
    };
}

fn same(left: anytype, right: @TypeOf(left)) bool {
    return left.address == right.address and
        left.len == right.len and
        left.owner == right.owner and
        left.generation == right.generation;
}
