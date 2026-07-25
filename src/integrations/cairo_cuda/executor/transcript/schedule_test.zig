const std = @import("std");
const telemetry = @import(
    "../../../../backends/cuda/runtime/telemetry.zig",
);
const subject = @import("schedule.zig");
const fixture = @import("test_fixture.zig");

test "SN2 transcript schedule preserves the exact Metal authority order" {
    const allocator = std.testing.allocator;
    const protocol = try fixture.protocol();
    var program = try fixture.program(allocator, protocol);
    defer program.deinit(allocator);
    const schedule = try subject.Schedule.init(program, protocol);

    try std.testing.expectEqual(@as(u32, 39), schedule.operation_count);
    try std.testing.expectEqual(
        @as(u32, 11),
        subject.bootstrap_mix_ordinals.len,
    );
    for (subject.bootstrap_mix_ordinals, 0..) |ordinal, step| {
        try std.testing.expectEqual(
            subject.Operation{ .mix_bootstrap = ordinal },
            try schedule.operation(@intCast(step)),
        );
        try std.testing.expectEqual(
            telemetry.Stage.trace_commit,
            try schedule.stage(@intCast(step)),
        );
        try std.testing.expectEqual(
            ordinal,
            (try schedule.inputOrdinal(@intCast(step))).?,
        );
    }
    try std.testing.expectEqual(
        subject.Operation.absorb_interaction_pow,
        try schedule.operation(11),
    );
    try std.testing.expectEqual(
        subject.Operation.draw_relation_elements,
        try schedule.operation(12),
    );
    try std.testing.expectEqual(
        subject.Operation.mix_interaction_claims,
        try schedule.operation(13),
    );
    try std.testing.expectEqual(
        subject.Operation.mix_interaction_root,
        try schedule.operation(14),
    );
    try std.testing.expectEqual(
        subject.Operation.draw_composition_alpha,
        try schedule.operation(15),
    );
    try std.testing.expectEqual(
        subject.Operation.mix_composition_root,
        try schedule.operation(16),
    );
    try std.testing.expectEqual(
        subject.Operation.draw_oods_point,
        try schedule.operation(17),
    );
    try std.testing.expectEqual(
        subject.Operation.mix_sampled_values,
        try schedule.operation(18),
    );
    try std.testing.expectEqual(
        subject.Operation.draw_quotient_alpha,
        try schedule.operation(19),
    );
    for (0..protocol.fri_tree_count) |round| {
        const mix_step: u32 = @intCast(20 + round * 2);
        try std.testing.expectEqual(
            subject.Operation{
                .mix_fri_root = @intCast(round),
            },
            try schedule.operation(mix_step),
        );
        try std.testing.expectEqual(
            subject.Operation{
                .draw_fri_alpha = @intCast(round),
            },
            try schedule.operation(mix_step + 1),
        );
        try std.testing.expectEqual(
            subject.friInputOrdinal(@intCast(round)),
            (try schedule.inputOrdinal(mix_step)).?,
        );
        try std.testing.expectEqual(
            subject.friInputOrdinal(@intCast(round)) + 1,
            (try schedule.outputOrdinal(mix_step + 1)).?,
        );
    }
    try std.testing.expectEqual(
        subject.Operation.mix_last_layer,
        try schedule.operation(36),
    );
    try std.testing.expectEqual(
        subject.Operation.absorb_query_pow,
        try schedule.operation(37),
    );
    try std.testing.expectEqual(
        subject.Operation.draw_queries,
        try schedule.operation(38),
    );
    try std.testing.expectError(
        error.InvalidTranscriptStep,
        schedule.operation(39),
    );
}

test "SN2 transcript payload geometry is exact and runtime-sized only once" {
    const allocator = std.testing.allocator;
    const protocol = try fixture.protocol();
    var program = try fixture.program(allocator, protocol);
    defer program.deinit(allocator);
    const schedule = try subject.Schedule.init(program, protocol);

    const bootstrap_words = [_]usize{
        4,
        8,
        8,
        4,
        84,
        60,
        4,
        56,
        8,
        8,
        8,
    };
    for (bootstrap_words, 0..) |words, step| {
        try schedule.validateInputWords(@intCast(step), words);
    }
    try schedule.validateInputWords(13, 58 * 4);
    try schedule.validateInputWords(18, 24_440);
    for (0..protocol.fri_tree_count) |round| {
        try schedule.validateInputWords(
            @intCast(20 + round * 2),
            8,
        );
    }
    try schedule.validateInputWords(36, 4);
    try schedule.validateInputWords(37, 2);
    try schedule.validateOutputWords(12, 8);
    try schedule.validateOutputWords(15, 4);
    try schedule.validateOutputWords(38, 70);

    try std.testing.expectError(
        error.InvalidTranscriptPayload,
        schedule.validateInputWords(4, 83),
    );
    try std.testing.expectError(
        error.InvalidTranscriptPayload,
        schedule.validateInputWords(7, 55),
    );
    try std.testing.expectError(
        error.InvalidTranscriptPayload,
        schedule.validateInputWords(18, 24_436),
    );
    try std.testing.expectError(
        error.InvalidTranscriptPayload,
        schedule.validateOutputWords(38, 69),
    );
}

test "transcript identity binds semantic proof executable and protocol" {
    const allocator = std.testing.allocator;
    const protocol = try fixture.protocol();
    var program = try fixture.program(allocator, protocol);
    defer program.deinit(allocator);
    const baseline = try subject.Schedule.init(program, protocol);
    try std.testing.expect(!std.mem.allEqual(
        u8,
        &baseline.schedule_identity,
        0,
    ));

    program.program_digest[0] ^= 1;
    const executable_mutation = try subject.Schedule.init(
        program,
        protocol,
    );
    try std.testing.expect(!std.mem.eql(
        u8,
        &baseline.schedule_identity,
        &executable_mutation.schedule_identity,
    ));
    program.program_digest[0] ^= 1;

    program.semantic_digest[0] ^= 1;
    const semantic_mutation = try subject.Schedule.init(
        program,
        protocol,
    );
    try std.testing.expect(!std.mem.eql(
        u8,
        &baseline.schedule_identity,
        &semantic_mutation.schedule_identity,
    ));
    program.semantic_digest[0] ^= 1;

    var wrong_protocol = protocol;
    wrong_protocol.channel_salt += 1;
    try std.testing.expectError(
        error.InvalidCairoTranscriptAuthority,
        subject.Schedule.init(program, wrong_protocol),
    );
}

test "coarse ProofProgram barrier drift fails before scheduling" {
    const allocator = std.testing.allocator;
    const protocol = try fixture.protocol();
    var program = try fixture.program(allocator, protocol);
    defer program.deinit(allocator);

    program.transcript[6].value_count -= 1;
    try std.testing.expectError(
        error.InvalidCairoTranscriptBarriers,
        subject.Schedule.init(program, protocol),
    );
    program.transcript[6].value_count += 1;

    program.transcript[30].kind = .challenge;
    try std.testing.expectError(
        error.InvalidCairoTranscriptBarriers,
        subject.Schedule.init(program, protocol),
    );
}

test "boundary chain is deterministic and step-specific" {
    const allocator = std.testing.allocator;
    const protocol = try fixture.protocol();
    var program = try fixture.program(allocator, protocol);
    defer program.deinit(allocator);
    const schedule = try subject.Schedule.init(program, protocol);

    const first = try schedule.boundary(0);
    const second = try schedule.boundary(1);
    try std.testing.expectEqual(
        schedule.initialChain(),
        first.expected_chain,
    );
    try std.testing.expectEqual(
        first.next_chain,
        second.expected_chain,
    );
    try std.testing.expect(first.expected_chain != first.next_chain);
}
