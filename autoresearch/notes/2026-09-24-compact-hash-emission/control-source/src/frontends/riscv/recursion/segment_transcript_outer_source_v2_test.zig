//! Focused parity, geometry and fail-atomic gates for V2 transcript rows 0--9.

const std = @import("std");
const stwo_core = @import("stwo_core");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const PcsConfig = stwo_core.pcs.PcsConfig;
const opcode_interaction = @import("../air/lookups/opcode_interaction.zig");
const public_data_v2 = @import("../air/public_data_v2.zig");
const support = @import("../air/public_data_v2_test_support.zig");
const relation_challenges = @import("../air/relation_challenges.zig");
const statement_v1 = @import("../air/statement.zig");
const statement_v2 = @import("../air/statement_v2.zig");
const fixed_profile = @import("fixed_profile.zig");
const channel = @import("poseidon2_channel.zig");
const schedule = @import("air/verifier_schedule.zig");
const subject = @import("segment_transcript_outer_source_v2.zig");
const transcript = @import("transcript_program_v2.zig");

const config = PcsConfig{
    .pow_bits = 0,
    .fri_config = .{
        .log_blowup_factor = 1,
        .log_last_layer_degree_bound = 0,
        .n_queries = 3,
        .fold_step = 1,
    },
};

const component_descs = [_]statement_v1.FamilyComponentDesc{.{
    .family = .base_alu_imm,
    .log_size = 4,
    .n_rows = 2,
    .n_columns = 10,
}};

const infra_descs = [_]statement_v1.InfraComponentDesc{.{
    .kind = .program,
    .log_size = 4,
    .n_rows = 2,
    .n_columns = 2,
}};

const test_support = @import("segment_transcript_outer_source_v2_test_support.zig");
const Fixture = test_support.Fixture;
const OwnedDestinations = test_support.OwnedDestinations;
const testPlan = test_support.testPlan;
const expectCanonicalEventOrder = test_support.expectCanonicalEventOrder;
const qm31 = test_support.qm31;

test "V2 source writes exact typed rows events and provider range" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();

    const evidence = try fixture.execution.evidence(&fixture.program);
    const prepared = try subject.preflight(
        &fixture.program,
        &fixture.execution,
        &evidence,
        &fixture.plan,
        config,
        &fixture.data,
        &component_descs,
        &infra_descs,
    );
    try std.testing.expect(!prepared.productionReady());
    try prepared.manifest.validate();
    const authority_words = prepared.authority.canonicalWords();
    for (authority_words[0..channel.RATE], fixture.program.identity) |
        actual,
        expected,
    | try std.testing.expectEqual(expected, actual.toU32());

    var published: subject.PreparedV2 = undefined;
    try subject.prepareInto(
        &published,
        &fixture.program,
        &fixture.execution,
        &evidence,
        &fixture.plan,
        config,
        &fixture.data,
        &component_descs,
        &infra_descs,
    );
    try std.testing.expectEqualDeep(prepared, published);

    var owned = try OwnedDestinations.init(std.testing.allocator, prepared.counts());
    defer owned.deinit();
    try subject.writeInto(
        &prepared,
        owned.view(),
        &fixture.program,
        &fixture.execution,
        &evidence,
        &fixture.plan,
        config,
        &fixture.data,
        &component_descs,
        &infra_descs,
    );

    try std.testing.expectEqual(
        fixture.execution.poseidon_calls.len,
        owned.poseidon_requests.len,
    );
    for (owned.poseidon_requests, fixture.execution.poseidon_calls) |actual, expected| {
        try std.testing.expect(actual.io);
        try std.testing.expect(!actual.wide);
        try std.testing.expect(actual.narrow_output == null);
        for (actual.input, expected.input) |raw, word|
            try std.testing.expectEqual(word.toU32(), raw);
    }
    for (owned.relation_events) |event| try event.validate();
    try expectCanonicalEventOrder(owned.relation_events);

    const range = try subject.PoseidonRequestRangeV2.init(&prepared, 17);
    try range.validateAgainst(&prepared);
    try std.testing.expectEqual(@as(u32, 17), range.first);
    try std.testing.expectEqual(
        @as(u32, @intCast(17 + owned.poseidon_requests.len)),
        range.end,
    );
}

test "V2 digest-state keys advance only on mixes and count every reuse" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();

    const evidence = try fixture.execution.evidence(&fixture.program);
    const prepared = try subject.preflight(
        &fixture.program,
        &fixture.execution,
        &evidence,
        &fixture.plan,
        config,
        &fixture.data,
        &component_descs,
        &infra_descs,
    );
    var owned = try OwnedDestinations.init(std.testing.allocator, prepared.counts());
    defer owned.deinit();
    try subject.writeInto(
        &prepared,
        owned.view(),
        &fixture.program,
        &fixture.execution,
        &evidence,
        &fixture.plan,
        config,
        &fixture.data,
        &component_descs,
        &infra_descs,
    );

    var mix_ordinal: u32 = 0;
    var remaining_consumers: u32 = 0;
    var current_digest = [_]M31{M31.zero()} ** channel.RATE;
    var previous_was_draw = false;
    var saw_consecutive_draws = false;
    for (owned.transcript_state, fixture.execution.hash_frames, 0..) |
        row,
        frame,
        frame_index,
    | {
        const pp = row.preprocessing;
        const is_mix = frame.purpose == .mix;
        if (is_mix) {
            try std.testing.expectEqual(mix_ordinal, pp.input_state_key);
            try std.testing.expectEqual(@as(u32, @intFromBool(mix_ordinal == 0)), pp.initial_mask);
            try std.testing.expectEqual(@as(u32, @intFromBool(mix_ordinal != 0)), pp.state_consume_mask);
            if (mix_ordinal == 0) {
                try std.testing.expectEqualDeep(
                    [_]M31{M31.zero()} ** channel.RATE,
                    row.main.inputs,
                );
            } else {
                try std.testing.expect(remaining_consumers > 0);
                remaining_consumers -= 1;
                try std.testing.expectEqualDeep(current_digest, row.main.inputs);
            }

            mix_ordinal += 1;
            var expected_consumers: u32 = 0;
            for (fixture.execution.hash_frames[frame_index + 1 ..]) |future| {
                expected_consumers += 1;
                if (future.purpose == .mix) break;
            }
            try std.testing.expectEqual(mix_ordinal, pp.output_state_key);
            try std.testing.expectEqual(expected_consumers, pp.state_produce_multiplicity);
            current_digest = row.main.outputs;
            remaining_consumers = expected_consumers;
        } else {
            saw_consecutive_draws = saw_consecutive_draws or previous_was_draw;
            try std.testing.expect(mix_ordinal > 0);
            try std.testing.expect(remaining_consumers > 0);
            try std.testing.expectEqual(mix_ordinal, pp.input_state_key);
            try std.testing.expectEqual(mix_ordinal, pp.output_state_key);
            try std.testing.expectEqual(@as(u32, 1), pp.state_consume_mask);
            try std.testing.expectEqual(@as(u32, 0), pp.state_produce_multiplicity);
            try std.testing.expectEqualDeep(current_digest, row.main.inputs);
            remaining_consumers -= 1;
        }
        previous_was_draw = !is_mix;
    }
    try std.testing.expect(saw_consecutive_draws);
    try std.testing.expectEqual(@as(u32, 0), remaining_consumers);
}

test "V2 control and transcript rows share the exact verifier-owned schedule" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();

    const evidence = try fixture.execution.evidence(&fixture.program);
    const prepared = try subject.preflight(
        &fixture.program,
        &fixture.execution,
        &evidence,
        &fixture.plan,
        config,
        &fixture.data,
        &component_descs,
        &infra_descs,
    );
    try std.testing.expectEqual(fixture.plan.steps.len, prepared.counts().control);
    var owned = try OwnedDestinations.init(std.testing.allocator, prepared.counts());
    defer owned.deinit();
    try subject.writeInto(
        &prepared,
        owned.view(),
        &fixture.program,
        &fixture.execution,
        &evidence,
        &fixture.plan,
        config,
        &fixture.data,
        &component_descs,
        &infra_descs,
    );

    for (owned.control, fixture.plan.steps, 0..) |row, step, sequence| {
        const encoded = step.encode();
        try std.testing.expectEqual(subject.VERIFIER_ID, row.verifier_id);
        try std.testing.expectEqual(@as(u32, @intCast(sequence)), row.sequence);
        try std.testing.expectEqual(encoded.tag, row.tag);
        try std.testing.expectEqualDeep(encoded.args, row.args);
        try std.testing.expectEqual(
            @as(u32, @intFromBool(step.terminal())),
            row.terminal_mask,
        );
    }

    const represented = try std.testing.allocator.alloc(bool, fixture.plan.steps.len);
    defer std.testing.allocator.free(represented);
    @memset(represented, false);
    var operation_first_count: usize = 0;
    var pow_at: usize = 0;
    var relation_at: usize = 0;
    var randomness_at: usize = 0;
    for (fixture.program.instructions, fixture.execution.operations, 0..) |
        instruction,
        operation,
        instruction_index,
    | {
        const sequence: usize = @intCast(instruction.verifier_sequence);
        const encoded = fixture.plan.steps[sequence].encode();
        const first_instruction = instruction_index == 0 or
            fixture.program.instructions[instruction_index - 1].verifier_sequence !=
                instruction.verifier_sequence;
        if (first_instruction) {
            try std.testing.expect(!represented[sequence]);
            represented[sequence] = true;
        }

        const frame_start: usize = @intCast(operation.first_hash_id);
        const frame_end = frame_start + operation.hash_count;
        for (frame_start..frame_end, 0..) |frame_index, local_frame| {
            const state = owned.transcript_state[frame_index].preprocessing;
            try std.testing.expectEqual(instruction.verifier_sequence, state.sequence);
            try std.testing.expectEqual(encoded.tag, state.tag);
            try std.testing.expectEqualDeep(encoded.args, state.args);

            const frame = fixture.execution.hash_frames[frame_index];
            const call_start: usize = @intCast(frame.first_call_id);
            const call_end = call_start + frame.call_count;
            for (call_start..call_end) |call_index| {
                const binding = owned.transcript_binding[call_index].preprocessing;
                try std.testing.expectEqual(instruction.verifier_sequence, binding.sequence);
                try std.testing.expectEqual(encoded.tag, binding.tag);
                try std.testing.expectEqualDeep(encoded.args, binding.args);
                const expected_first: u32 = @intFromBool(
                    first_instruction and local_frame == 0 and binding.hash_step == 0,
                );
                try std.testing.expectEqual(expected_first, binding.is_operation_first);
                operation_first_count += binding.is_operation_first;
            }
        }

        switch (instruction.kind) {
            .interaction_pow, .pcs_pow => {
                try std.testing.expectEqual(
                    instruction.verifier_sequence,
                    owned.pow_frame[pow_at].instruction_index,
                );
                pow_at += 1;
            },
            .relation_draw => {
                const row = owned.relation_challenge[relation_at].preprocessing;
                try std.testing.expectEqual(instruction.verifier_sequence, row.sequence);
                try std.testing.expectEqual(encoded.tag, row.tag);
                try std.testing.expectEqualDeep(encoded.args, row.args);
                relation_at += 1;
            },
            .composition_draw,
            .oods_draw,
            .deep_draw,
            .fri_alpha_draw,
            .query_draw,
            => {
                const row = owned.verifier_randomness[randomness_at].preprocessing;
                try std.testing.expectEqual(instruction.verifier_sequence, row.sequence);
                try std.testing.expectEqual(encoded.tag, row.tag);
                try std.testing.expectEqualDeep(encoded.args, row.args);
                randomness_at += 1;
            },
            else => {},
        }
    }

    var represented_count: usize = 0;
    for (represented) |present| represented_count += @intFromBool(present);
    try std.testing.expectEqual(represented_count, operation_first_count);
    try std.testing.expectEqual(owned.pow_frame.len, pow_at);
    try std.testing.expectEqual(owned.relation_challenge.len, relation_at);
    try std.testing.expectEqual(owned.verifier_randomness.len, randomness_at);
}

test "V2 raw query custody preserves complete transcript words atomically" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();

    const evidence = try fixture.execution.evidence(&fixture.program);
    const prepared = try subject.preflight(
        &fixture.program,
        &fixture.execution,
        &evidence,
        &fixture.plan,
        config,
        &fixture.data,
        &component_descs,
        &infra_descs,
    );

    var query_words: [config.fri_config.n_queries]M31 = undefined;
    try prepared.writeRawQueryWords(
        &query_words,
        &fixture.program,
        &fixture.execution,
        &fixture.plan,
    );
    var expected: [config.fri_config.n_queries]M31 = undefined;
    var at: usize = 0;
    for (fixture.program.instructions, fixture.execution.operations) |
        instruction,
        operation,
    | {
        if (instruction.kind != .query_draw) continue;
        const draw = operation.draw.?;
        const width: usize = @intCast(instruction.args[2]);
        @memcpy(expected[at..][0..width], draw[0..width]);
        at += width;
    }
    try std.testing.expectEqual(expected.len, at);
    try std.testing.expectEqualSlices(M31, &expected, &query_words);

    var short = [_]M31{M31.fromCanonical(0x5a5a)} **
        (config.fri_config.n_queries - 1);
    const short_before = short;
    try std.testing.expectError(
        error.DestinationLengthMismatch,
        prepared.writeRawQueryWords(
            &short,
            &fixture.program,
            &fixture.execution,
            &fixture.plan,
        ),
    );
    try std.testing.expectEqualSlices(M31, &short_before, &short);

    const alias = fixture.execution.word_storage[0..query_words.len];
    var alias_before: [query_words.len]M31 = undefined;
    @memcpy(&alias_before, alias);
    try std.testing.expectError(
        error.AliasedDestination,
        prepared.writeRawQueryWords(
            alias,
            &fixture.program,
            &fixture.execution,
            &fixture.plan,
        ),
    );
    try std.testing.expectEqualSlices(M31, &alias_before, alias);
}

test "V2 source rejects evidence mutation before destination writes" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    var evidence = try fixture.execution.evidence(&fixture.program);
    const prepared = try subject.preflight(
        &fixture.program,
        &fixture.execution,
        &evidence,
        &fixture.plan,
        config,
        &fixture.data,
        &component_descs,
        &infra_descs,
    );
    var owned = try OwnedDestinations.init(std.testing.allocator, prepared.counts());
    defer owned.deinit();
    owned.fillSentinel();
    const before = owned.digest();

    evidence.final_digest[0] ^= 1;
    try std.testing.expectError(
        error.AuthorityMismatch,
        subject.writeInto(
            &prepared,
            owned.view(),
            &fixture.program,
            &fixture.execution,
            &evidence,
            &fixture.plan,
            config,
            &fixture.data,
            &component_descs,
            &infra_descs,
        ),
    );
    try std.testing.expectEqual(before, owned.digest());
}

test "V2 source rejects omitted destination and alias before any write" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const evidence = try fixture.execution.evidence(&fixture.program);
    const prepared = try subject.preflight(
        &fixture.program,
        &fixture.execution,
        &evidence,
        &fixture.plan,
        config,
        &fixture.data,
        &component_descs,
        &infra_descs,
    );
    var owned = try OwnedDestinations.init(std.testing.allocator, prepared.counts());
    defer owned.deinit();
    owned.fillSentinel();
    const before = owned.digest();

    var short = owned.view();
    short.control = short.control[0 .. short.control.len - 1];
    try std.testing.expectError(
        error.DestinationLengthMismatch,
        subject.writeInto(
            &prepared,
            short,
            &fixture.program,
            &fixture.execution,
            &evidence,
            &fixture.plan,
            config,
            &fixture.data,
            &component_descs,
            &infra_descs,
        ),
    );
    try std.testing.expectEqual(before, owned.digest());

    var aliased = owned.view();
    const aliased_binding: [*]subject.TranscriptBindingRowV2 =
        @ptrCast(@alignCast(aliased.transcript_air.ptr));
    aliased.transcript_binding = aliased_binding[0..aliased.transcript_binding.len];
    try std.testing.expectError(
        error.AliasedDestination,
        subject.writeInto(
            &prepared,
            aliased,
            &fixture.program,
            &fixture.execution,
            &evidence,
            &fixture.plan,
            config,
            &fixture.data,
            &component_descs,
            &infra_descs,
        ),
    );
    try std.testing.expectEqual(before, owned.digest());
}

test "V2 source rejects reordered program and duplicated operation atomically" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const evidence = try fixture.execution.evidence(&fixture.program);
    const prepared = try subject.preflight(
        &fixture.program,
        &fixture.execution,
        &evidence,
        &fixture.plan,
        config,
        &fixture.data,
        &component_descs,
        &infra_descs,
    );
    var owned = try OwnedDestinations.init(std.testing.allocator, prepared.counts());
    defer owned.deinit();
    owned.fillSentinel();
    const before = owned.digest();

    std.mem.swap(
        transcript.Instruction,
        &fixture.program.instructions[0],
        &fixture.program.instructions[1],
    );
    const reordered_result = subject.writeInto(
        &prepared,
        owned.view(),
        &fixture.program,
        &fixture.execution,
        &evidence,
        &fixture.plan,
        config,
        &fixture.data,
        &component_descs,
        &infra_descs,
    );
    std.mem.swap(
        transcript.Instruction,
        &fixture.program.instructions[0],
        &fixture.program.instructions[1],
    );
    try std.testing.expectError(error.AuthorityMismatch, reordered_result);
    try std.testing.expectEqual(before, owned.digest());

    const saved_operation = fixture.execution.operations[1];
    fixture.execution.operations[1] = fixture.execution.operations[0];
    const duplicated_result = subject.writeInto(
        &prepared,
        owned.view(),
        &fixture.program,
        &fixture.execution,
        &evidence,
        &fixture.plan,
        config,
        &fixture.data,
        &component_descs,
        &infra_descs,
    );
    fixture.execution.operations[1] = saved_operation;
    try std.testing.expectError(error.AuthorityMismatch, duplicated_result);
    try std.testing.expectEqual(before, owned.digest());
}

test "V2 source rejects manifest event and provider-range drift" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const evidence = try fixture.execution.evidence(&fixture.program);
    const prepared = try subject.preflight(
        &fixture.program,
        &fixture.execution,
        &evidence,
        &fixture.plan,
        config,
        &fixture.data,
        &component_descs,
        &infra_descs,
    );
    var owned = try OwnedDestinations.init(std.testing.allocator, prepared.counts());
    defer owned.deinit();
    try subject.writeInto(
        &prepared,
        owned.view(),
        &fixture.program,
        &fixture.execution,
        &evidence,
        &fixture.plan,
        config,
        &fixture.data,
        &component_descs,
        &infra_descs,
    );

    var bad_manifest = prepared.manifest;
    bad_manifest.format_version = 1;
    try std.testing.expectError(error.UnsupportedVersion, bad_manifest.validate());
    bad_manifest = prepared.manifest;
    bad_manifest.logical_rows[0] += 1;
    try std.testing.expectError(error.InvalidManifest, bad_manifest.validate());

    const event = owned.relation_events[0];
    var bad_event = event;
    bad_event.arity -= 1;
    try std.testing.expectError(error.InvalidRelationEvent, bad_event.validate());
    bad_event = event;
    bad_event.tuple[bad_event.arity] = M31.fromCanonical(1);
    try std.testing.expectError(error.InvalidRelationEvent, bad_event.validate());
    bad_event = event;
    bad_event.roster_row = subject.ROW_COUNT;
    try std.testing.expectError(error.InvalidRelationEvent, bad_event.validate());

    const canonical_range = try subject.PoseidonRequestRangeV2.init(&prepared, 17);
    var bad_range = canonical_range;
    bad_range.count += 1;
    try std.testing.expectError(
        error.PoseidonRangeMismatch,
        bad_range.validateAgainst(&prepared),
    );
    bad_range = canonical_range;
    bad_range.end += 1;
    try std.testing.expectError(
        error.PoseidonRangeMismatch,
        bad_range.validateAgainst(&prepared),
    );
    bad_range = canonical_range;
    bad_range.format_version = 1;
    try std.testing.expectError(
        error.PoseidonRangeMismatch,
        bad_range.validateAgainst(&prepared),
    );
}

test "V2 source is version separated and allocation-free on hot writes" {
    try std.testing.expect(subject.FORMAT_VERSION != 1);
    try std.testing.expect(!subject.FROZEN_V1_ROW_COMPATIBLE);
    try std.testing.expect(!subject.PRODUCTION_ACTIVATION);
    try std.testing.expectEqual(@as(usize, 0), subject.HOT_HEAP_ALLOCATIONS);
}
