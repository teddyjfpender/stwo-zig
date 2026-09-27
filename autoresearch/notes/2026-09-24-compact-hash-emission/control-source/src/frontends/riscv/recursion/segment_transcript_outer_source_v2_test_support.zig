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

// Shared fixtures and mutation helpers for this conformance suite.

pub const Fixture = struct {
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

    pub fn init(allocator: std.mem.Allocator) !Fixture {
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
            support.id("v2-source-tree-0"),
            support.id("v2-source-tree-1"),
            support.id("v2-source-tree-2"),
            support.id("v2-source-tree-3"),
        };
        var claimed_sums: [transcript.COMPONENT_CLAIM_COUNT]QM31 = undefined;
        for (&claimed_sums, 0..) |*value, index| value.* = qm31(index + 10);
        var sampled_values: [3]QM31 = undefined;
        for (&sampled_values, 0..) |*value, index| value.* = qm31(index + 100);
        const fri_commitments = [_]channel.Digest{
            support.id("v2-source-fri-0"),
            support.id("v2-source-fri-1"),
            support.id("v2-source-fri-2"),
            support.id("v2-source-fri-3"),
        };
        const last_layer_coefficients = [_]QM31{qm31(200)};
        const execution = try transcript.execute(allocator, &program, &data, .{
            .trace_commitments = &trace_commitments,
            .interaction_pow = 0,
            .claimed_sums = &claimed_sums,
            .sampled_values = &sampled_values,
            .fri_commitments = &fri_commitments,
            .last_layer_coefficients = &last_layer_coefficients,
            .pcs_pow = 0,
        });
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

    pub fn deinit(self: *Fixture) void {
        self.execution.deinit();
        self.program.deinit();
        self.plan.deinit();
        self.allocator.free(self.words);
        self.* = undefined;
    }
};

pub const OwnedDestinations = struct {
    allocator: std.mem.Allocator,
    control: []subject.ControlRowV2,
    transcript_air: []subject.TranscriptAirRowV2,
    transcript_binding: []subject.TranscriptBindingRowV2,
    transcript_state: []subject.TranscriptStateRowV2,
    transcript_word: []subject.TranscriptWordRowV2,
    transcript_payload: []subject.TranscriptPayloadRowV2,
    pow_check: []subject.PowCheckRowV2,
    pow_frame: []subject.PowFrameRowV2,
    relation_challenge: []subject.RelationChallengeRowV2,
    verifier_randomness: []subject.VerifierRandomnessRowV2,
    relation_events: []subject.RelationEventV2,
    poseidon_requests: []subject.ProviderCall,

    pub fn init(allocator: std.mem.Allocator, counts: subject.CountsV2) !OwnedDestinations {
        const control = try allocator.alloc(subject.ControlRowV2, counts.control);
        errdefer allocator.free(control);
        const transcript_air = try allocator.alloc(subject.TranscriptAirRowV2, counts.transcript_air);
        errdefer allocator.free(transcript_air);
        const transcript_binding = try allocator.alloc(subject.TranscriptBindingRowV2, counts.transcript_binding);
        errdefer allocator.free(transcript_binding);
        const transcript_state = try allocator.alloc(subject.TranscriptStateRowV2, counts.transcript_state);
        errdefer allocator.free(transcript_state);
        const transcript_word = try allocator.alloc(subject.TranscriptWordRowV2, counts.transcript_word);
        errdefer allocator.free(transcript_word);
        const transcript_payload = try allocator.alloc(subject.TranscriptPayloadRowV2, counts.transcript_payload);
        errdefer allocator.free(transcript_payload);
        const pow_check = try allocator.alloc(subject.PowCheckRowV2, counts.pow_check);
        errdefer allocator.free(pow_check);
        const pow_frame = try allocator.alloc(subject.PowFrameRowV2, counts.pow_frame);
        errdefer allocator.free(pow_frame);
        const relation_challenge = try allocator.alloc(subject.RelationChallengeRowV2, counts.relation_challenge);
        errdefer allocator.free(relation_challenge);
        const verifier_randomness = try allocator.alloc(subject.VerifierRandomnessRowV2, counts.verifier_randomness);
        errdefer allocator.free(verifier_randomness);
        const relation_events = try allocator.alloc(subject.RelationEventV2, counts.relation_events);
        errdefer allocator.free(relation_events);
        const poseidon_requests = try allocator.alloc(subject.ProviderCall, counts.poseidon_requests);
        errdefer allocator.free(poseidon_requests);
        return .{
            .allocator = allocator,
            .control = control,
            .transcript_air = transcript_air,
            .transcript_binding = transcript_binding,
            .transcript_state = transcript_state,
            .transcript_word = transcript_word,
            .transcript_payload = transcript_payload,
            .pow_check = pow_check,
            .pow_frame = pow_frame,
            .relation_challenge = relation_challenge,
            .verifier_randomness = verifier_randomness,
            .relation_events = relation_events,
            .poseidon_requests = poseidon_requests,
        };
    }

    pub fn deinit(self: *OwnedDestinations) void {
        self.allocator.free(self.poseidon_requests);
        self.allocator.free(self.relation_events);
        self.allocator.free(self.verifier_randomness);
        self.allocator.free(self.relation_challenge);
        self.allocator.free(self.pow_frame);
        self.allocator.free(self.pow_check);
        self.allocator.free(self.transcript_payload);
        self.allocator.free(self.transcript_word);
        self.allocator.free(self.transcript_state);
        self.allocator.free(self.transcript_binding);
        self.allocator.free(self.transcript_air);
        self.allocator.free(self.control);
        self.* = undefined;
    }

    pub fn view(self: *OwnedDestinations) subject.DestinationsV2 {
        return .{
            .control = self.control,
            .transcript_air = self.transcript_air,
            .transcript_binding = self.transcript_binding,
            .transcript_state = self.transcript_state,
            .transcript_word = self.transcript_word,
            .transcript_payload = self.transcript_payload,
            .pow_check = self.pow_check,
            .pow_frame = self.pow_frame,
            .relation_challenge = self.relation_challenge,
            .verifier_randomness = self.verifier_randomness,
            .relation_events = self.relation_events,
            .poseidon_requests = self.poseidon_requests,
        };
    }

    pub fn fillSentinel(self: *OwnedDestinations) void {
        inline for (std.meta.fields(OwnedDestinations)) |field| {
            if (field.type == std.mem.Allocator) continue;
            @memset(std.mem.sliceAsBytes(@field(self, field.name)), 0xa5);
        }
    }

    pub fn digest(self: *const OwnedDestinations) [32]u8 {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        inline for (std.meta.fields(OwnedDestinations)) |field| {
            if (field.type == std.mem.Allocator) continue;
            hash.update(std.mem.sliceAsBytes(@field(self, field.name)));
        }
        return hash.finalResult();
    }
};

pub fn testPlan(allocator: std.mem.Allocator) !schedule.Plan {
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
            .protocol_id = support.id("v2-source-protocol"),
            .shape_id = support.id("v2-source-shape"),
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

pub fn expectCanonicalEventOrder(events: []const subject.RelationEventV2) !void {
    for (events[1..], events[0 .. events.len - 1]) |current, previous| {
        try std.testing.expect(current.roster_row >= previous.roster_row);
        if (current.roster_row == previous.roster_row) {
            try std.testing.expect(current.logical_row >= previous.logical_row);
            if (current.logical_row == previous.logical_row)
                try std.testing.expect(current.event_ordinal > previous.event_ordinal);
        }
    }
}

pub fn qm31(seed: usize) QM31 {
    return QM31.fromU32Unchecked(
        @intCast(seed),
        @intCast(seed + 1),
        @intCast(seed + 2),
        @intCast(seed + 3),
    );
}
