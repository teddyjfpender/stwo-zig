//! Focused parity and rejection gates for the V2 transcript program.

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
const segment_v2 = @import("segment_statement_v2.zig");
const scheduled = @import("scheduled_channel_v2.zig");
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

test "V2 raw program exactly matches the ordinary generic channel" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();

    var ordinary = channel.Channel{};
    try drive(channel.MerkleChannel, &ordinary, &fixture);

    var guarded = try scheduled.Channel.init(
        &fixture.program,
        &fixture.plan,
        config,
        &fixture.data,
        &component_descs,
        &infra_descs,
    );
    try drive(scheduled.MerkleChannel, &guarded, &fixture);
    try guarded.complete();

    try fixture.execution.validateAgainst(&fixture.program);
    try fixture.execution.replayNative(&fixture.program);
    const evidence = try fixture.execution.evidence(&fixture.program);
    try evidence.validateAgainst(&fixture.execution, &fixture.program);
    try std.testing.expectEqual(ordinary.digestWords(), guarded.digestWords());
    try std.testing.expectEqual(ordinary.digestWords(), fixture.execution.final_digest);
    try std.testing.expectEqual(ordinary.n_draws, fixture.execution.final_draw_count);
    try std.testing.expect(fixture.execution.poseidonCalls().len > fixture.execution.hash_frames.len);

    // The first four native frames are PCS, statement header, wire identity,
    // and the complete variable canonical wire, with no V1 framing headers.
    try std.testing.expectEqual(
        @as(usize, channel.RATE + 4),
        fixture.execution.hash_frames[0].words.len,
    );
    try std.testing.expectEqual(
        @as(usize, channel.RATE + 8),
        fixture.execution.hash_frames[1].words.len,
    );
    try std.testing.expectEqual(
        @as(usize, channel.RATE + 2 * channel.RATE),
        fixture.execution.hash_frames[2].words.len,
    );
    const wire_frame = fixture.execution.hash_frames[3];
    try std.testing.expectEqual(
        channel.RATE + fixture.words.len,
        wire_frame.words.len,
    );
    for (wire_frame.words[channel.RATE..], fixture.words) |actual, expected|
        try std.testing.expect(actual.eql(expected));
}

test "V2 scheduled bootstrap rejects order version length and wire mutation" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();

    var out_of_order = try fixture.guardedChannel();
    const zero_digest = out_of_order.digestWords();
    out_of_order.mixU32s(&.{
        public_data_v2.STATEMENT_TRANSCRIPT_DOMAIN,
        public_data_v2.STATEMENT_TRANSCRIPT_VERSION,
        public_data_v2.STATEMENT_TRANSCRIPT_SCHEMA_VERSION,
        @intCast(fixture.words.len),
    });
    try std.testing.expectError(error.TranscriptFault, out_of_order.complete());
    try std.testing.expectEqual(zero_digest, out_of_order.digestWords());

    var bad_version = try fixture.guardedChannel();
    config.mixInto(&bad_version);
    const after_pcs = bad_version.digestWords();
    bad_version.mixU32s(&.{
        public_data_v2.STATEMENT_TRANSCRIPT_DOMAIN,
        public_data_v2.STATEMENT_TRANSCRIPT_VERSION + 1,
        public_data_v2.STATEMENT_TRANSCRIPT_SCHEMA_VERSION,
        @intCast(fixture.words.len),
    });
    try std.testing.expectError(error.TranscriptFault, bad_version.complete());
    try std.testing.expectEqual(after_pcs, bad_version.digestWords());

    var bad_length = try fixture.guardedChannel();
    config.mixInto(&bad_length);
    bad_length.mixU32s(&.{
        public_data_v2.STATEMENT_TRANSCRIPT_DOMAIN,
        public_data_v2.STATEMENT_TRANSCRIPT_VERSION,
        public_data_v2.STATEMENT_TRANSCRIPT_SCHEMA_VERSION,
        @intCast(fixture.words.len + 1),
    });
    try std.testing.expectError(error.TranscriptFault, bad_length.complete());

    const mutation_index = segment_v2.fixed_layout.position_id;
    const saved = fixture.words[mutation_index];
    fixture.words[mutation_index] = M31.fromCanonical(saved.toU32() ^ 1);
    try std.testing.expectError(error.DigestMismatch, fixture.data.validate());
    fixture.words[mutation_index] = saved;
    try fixture.data.validate();

    fixture.program.format_version += 1;
    try std.testing.expectError(
        error.UnsupportedVersion,
        fixture.program.validateAgainst(
            &fixture.plan,
            config,
            &fixture.data,
            &component_descs,
            &infra_descs,
        ),
    );
}

test "V2 execution evidence and trace mutations fail closed" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();

    fixture.execution.identity[0] ^= 1;
    try std.testing.expectError(
        error.AuthorityMismatch,
        fixture.execution.validateAgainst(&fixture.program),
    );
    fixture.execution.identity[0] ^= 1;
    try fixture.execution.validateAgainst(&fixture.program);

    const saved = fixture.execution.poseidon_calls[0].input[0];
    fixture.execution.poseidon_calls[0].input[0] = saved.add(M31.one());
    try std.testing.expectError(
        error.InvalidTranscriptTrace,
        fixture.execution.validateAgainst(&fixture.program),
    );
    fixture.execution.poseidon_calls[0].input[0] = saved;
    try fixture.execution.validateAgainst(&fixture.program);
}

const Fixture = struct {
    allocator: std.mem.Allocator,
    words: []M31,
    data: public_data_v2.PublicDataV2,
    plan: schedule.Plan,
    program: transcript.Program,
    trace_commitments: [4]channel.Digest,
    claimed_sums: [transcript.COMPONENT_CLAIM_COUNT]QM31,
    sampled_values: [3]QM31,
    fri_commitments: [4]channel.Digest,
    last_layer_coefficients: [1]QM31,
    execution: transcript.Execution,

    fn init(allocator: std.mem.Allocator) !Fixture {
        const source_fixture = try support.Fixture.init();
        const source = source_fixture.leftSource();
        const words = try support.encode(allocator, &source);
        errdefer allocator.free(words);
        const data = try public_data_v2.PublicDataV2.authenticate(words);
        var plan = try testPlan(allocator);
        errdefer plan.deinit();
        var program = try transcript.Program.init(
            allocator,
            &plan,
            config,
            &data,
            &component_descs,
            &infra_descs,
        );
        errdefer program.deinit();
        const trace_commitments = [_]channel.Digest{
            support.id("v2-tree-0"),
            support.id("v2-tree-1"),
            support.id("v2-tree-2"),
            support.id("v2-tree-3"),
        };
        var claimed_sums: [transcript.COMPONENT_CLAIM_COUNT]QM31 = undefined;
        for (&claimed_sums, 0..) |*value, index| value.* = qm31(index + 10);
        var sampled_values: [3]QM31 = undefined;
        for (&sampled_values, 0..) |*value, index| value.* = qm31(index + 100);
        const fri_commitments = [_]channel.Digest{
            support.id("v2-fri-0"),
            support.id("v2-fri-1"),
            support.id("v2-fri-2"),
            support.id("v2-fri-3"),
        };
        const last_layer_coefficients = [_]QM31{qm31(200)};
        const inputs = transcript.Inputs{
            .trace_commitments = &trace_commitments,
            .interaction_pow = 0,
            .claimed_sums = &claimed_sums,
            .sampled_values = &sampled_values,
            .fri_commitments = &fri_commitments,
            .last_layer_coefficients = &last_layer_coefficients,
            .pcs_pow = 0,
        };
        const execution = try transcript.execute(allocator, &program, &data, inputs);
        return .{
            .allocator = allocator,
            .words = words,
            .data = data,
            .plan = plan,
            .program = program,
            .trace_commitments = trace_commitments,
            .claimed_sums = claimed_sums,
            .sampled_values = sampled_values,
            .fri_commitments = fri_commitments,
            .last_layer_coefficients = last_layer_coefficients,
            .execution = execution,
        };
    }

    fn deinit(self: *Fixture) void {
        self.execution.deinit();
        self.program.deinit();
        self.plan.deinit();
        self.allocator.free(self.words);
        self.* = undefined;
    }

    fn inputView(self: *const Fixture) transcript.Inputs {
        return .{
            .trace_commitments = &self.trace_commitments,
            .interaction_pow = 0,
            .claimed_sums = &self.claimed_sums,
            .sampled_values = &self.sampled_values,
            .fri_commitments = &self.fri_commitments,
            .last_layer_coefficients = &self.last_layer_coefficients,
            .pcs_pow = 0,
        };
    }

    fn guardedChannel(self: *const Fixture) !scheduled.Channel {
        return scheduled.Channel.init(
            &self.program,
            &self.plan,
            config,
            &self.data,
            &component_descs,
            &infra_descs,
        );
    }
};

fn testPlan(allocator: std.mem.Allocator) !schedule.Plan {
    return schedule.Plan.initShape(
        allocator,
        try schedule.ProgramSpec.init(
            .vm,
            relation_challenges.RELATION_COUNT,
            1,
            2,
            relation_challenges.RELATION_COUNT,
        ),
        .{
            .protocol_id = support.id("v2-transcript-protocol"),
            .shape_id = support.id("v2-transcript-shape"),
            .interaction_pow_bits = 0,
            .pcs_pow_bits = config.pow_bits,
            .query_count = @intCast(config.fri_config.n_queries),
            .table_count = 4,
            .claimed_sum_count = transcript.COMPONENT_CLAIM_COUNT,
            .sampled_value_count = 3,
            .tree_heights = .{ 5, 5, 5, 5 },
            .fri = try fixed_profile.FriSchedule.init(4, config.fri_config),
        },
    );
}

fn drive(
    comptime MerkleChannel: type,
    transcript_channel: anytype,
    fixture: *const Fixture,
) !void {
    config.mixInto(transcript_channel);
    try statement_v2.mixIntoNativeTranscript(&fixture.data, transcript_channel);
    MerkleChannel.mixRoot(transcript_channel, fixture.trace_commitments[0]);
    MerkleChannel.mixRoot(transcript_channel, fixture.trace_commitments[1]);

    var core: statement_v1.RiscVStatement = undefined;
    core.n_components = component_descs.len;
    core.component_descs[0..component_descs.len].* = component_descs;
    core.n_infra = infra_descs.len;
    core.infra_descs[0..infra_descs.len].* = infra_descs;
    const main_claim = core.canonicalMainClaim();
    main_claim.mixInto(transcript_channel);
    core.mixShardManifest(transcript_channel);

    try std.testing.expect(transcript_channel.verifyPowNonce(0, 0));
    transcript_channel.mixU64(0);
    const relations = try relation_challenges.Relations.draw(
        std.testing.allocator,
        transcript_channel,
    );
    _ = relations;
    for (fixture.claimed_sums) |value| transcript_channel.mixFelts(&.{value});
    const log_count = interactionLogCount();
    transcript_channel.mixU64(log_count);
    inline for (component_descs) |descriptor| {
        for (0..opcode_interaction.nColumns(descriptor.family)) |_|
            transcript_channel.mixU64(descriptor.log_size);
    }
    inline for (infra_descs) |descriptor| {
        for (0..statement_v1.nInteractionColsForInfra(descriptor.kind)) |_|
            transcript_channel.mixU64(descriptor.log_size);
    }
    MerkleChannel.mixRoot(transcript_channel, fixture.trace_commitments[2]);
    _ = transcript_channel.drawSecureFelt();
    MerkleChannel.mixRoot(transcript_channel, fixture.trace_commitments[3]);
    _ = transcript_channel.drawSecureFelt();
    transcript_channel.mixFelts(&fixture.sampled_values);
    _ = transcript_channel.drawSecureFelt();
    for (fixture.fri_commitments) |root| {
        MerkleChannel.mixRoot(transcript_channel, root);
        _ = transcript_channel.drawSecureFelt();
    }
    transcript_channel.mixFelts(&fixture.last_layer_coefficients);
    try std.testing.expect(transcript_channel.verifyPowNonce(0, 0));
    transcript_channel.mixU64(0);
    _ = transcript_channel.drawU32s();
}

fn interactionLogCount() u64 {
    var result: u64 = 0;
    inline for (component_descs) |descriptor|
        result += opcode_interaction.nColumns(descriptor.family);
    inline for (infra_descs) |descriptor|
        result += statement_v1.nInteractionColsForInfra(descriptor.kind);
    return result;
}

fn qm31(seed: usize) QM31 {
    return QM31.fromU32Unchecked(
        @intCast(seed),
        @intCast(seed + 1),
        @intCast(seed + 2),
        @intCast(seed + 3),
    );
}
