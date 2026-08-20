//! Verifier-owned, proof-independent recursion control schedule.
//!
//! This is the Zig authority for the 28 fixed Stark-V verifier step tags at
//! pinned commit `59172a201bd01f2f4b699bc2f7d4442d8ee81597`. A plan is derived
//! only from an admitted fixed proof shape and AIR-owned program counts. Proof
//! bytes never choose a phase, repetition count, query path, or closure row.

const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const fixed_profile = @import("../fixed_profile.zig");
const protocol = @import("../protocol.zig");
const channel = @import("../poseidon2_channel.zig");

pub const FORMAT_VERSION: u16 = 1;
pub const QUERY_WORDS_PER_DRAW: usize = 8;
pub const MAX_PROGRAM_PHASE_COUNT: u32 = 1_000_000;
pub const PLAN_DIGEST_DOMAIN: u32 = 0x5653_4348; // "VSCH"
/// Public LogUp denominators that do not depend on the fixed public-I/O
/// capacities: two state boundaries, three root slots, 64 register-memory
/// boundaries, and one mandatory self-loop program-access boundary.
pub const VM_PUBLIC_LOGUP_FIXED_TERM_COUNT: u32 = 70;

/// Exact `CanonicalWords for PcsParameters` encoding at the pinned Stark-V
/// revision.  Transcript execution and row-5 payload preprocessing consume
/// this one authority; neither is allowed to restate the protocol words.
pub const PCS_PARAMETER_WORDS = [16]u32{
    20,
    21,
    protocol.INTERACTION_POW_BITS,
    22,
    protocol.PCS_POW_BITS,
    23,
    protocol.FRI_LOG_BLOWUP_FACTOR,
    24,
    protocol.FRI_QUERY_COUNT,
    25,
    protocol.FRI_LOG_LAST_LAYER_DEGREE_BOUND,
    26,
    protocol.FRI_FOLD_STEP,
    27,
    0,
    0,
};

/// Exact Stark-V program cardinalities at the source revision named above.
/// These counts affect step sequence numbers and therefore are protocol data,
/// not convenient defaults for a witness generator.
pub const VM_PROGRAM_SPEC_V1 = ProgramSpec{
    .schema = .vm,
    .relation_challenge_count = 12,
    .public_logup_term_count = VM_PUBLIC_LOGUP_FIXED_TERM_COUNT,
    .air_instruction_count = 101,
    .relation_closure_count = 12,
};
pub const RECURSION_PROGRAM_SPEC_V1 = ProgramSpec{
    .schema = .recursion,
    .relation_challenge_count = 47,
    .public_logup_term_count = 0,
    .air_instruction_count = 17,
    .relation_closure_count = 47,
};

pub const Schema = enum(u16) {
    vm = 1,
    recursion = 2,
};

pub const CommitmentRound = enum(u32) {
    preprocessed = 1,
    main = 2,
    interaction = 3,
    composition = 4,
};

pub const ProgramSpec = struct {
    schema: Schema,
    relation_challenge_count: u32,
    public_logup_term_count: u32,
    air_instruction_count: u32,
    relation_closure_count: u32,

    pub fn init(
        schema: Schema,
        relation_challenge_count: u32,
        public_logup_term_count: u32,
        air_instruction_count: u32,
        relation_closure_count: u32,
    ) Error!ProgramSpec {
        for ([_]u32{
            relation_challenge_count,
            air_instruction_count,
            relation_closure_count,
        }) |count| {
            if (count == 0) return error.ZeroProgramCount;
            if (count > MAX_PROGRAM_PHASE_COUNT)
                return error.ProgramCountOutOfRange;
        }
        if (schema == .vm and public_logup_term_count == 0)
            return error.ZeroProgramCount;
        if (public_logup_term_count > MAX_PROGRAM_PHASE_COUNT)
            return error.ProgramCountOutOfRange;
        return .{
            .schema = schema,
            .relation_challenge_count = relation_challenge_count,
            .public_logup_term_count = public_logup_term_count,
            .air_instruction_count = air_instruction_count,
            .relation_closure_count = relation_closure_count,
        };
    }
};

/// Derives the exact VM verifier program for one fixed public-claim shape.
/// Every admitted input/output slot has a selected public LogUp denominator,
/// including padded slots; proof bytes never choose this cardinality.
pub fn vmProgramSpec(
    max_input_words: u32,
    max_output_words: u32,
) Error!ProgramSpec {
    const with_inputs = std.math.add(
        u32,
        VM_PUBLIC_LOGUP_FIXED_TERM_COUNT,
        max_input_words,
    ) catch return error.ArithmeticOverflow;
    const term_count = std.math.add(
        u32,
        with_inputs,
        max_output_words,
    ) catch return error.ArithmeticOverflow;
    return ProgramSpec.init(
        .vm,
        VM_PROGRAM_SPEC_V1.relation_challenge_count,
        term_count,
        VM_PROGRAM_SPEC_V1.air_instruction_count,
        VM_PROGRAM_SPEC_V1.relation_closure_count,
    );
}

pub const VerifierStep = union(enum) {
    bind_protocol,
    bind_statement,
    bind_pcs_parameters,
    absorb_trace_commitment: struct {
        round: CommitmentRound,
        tree: u32,
        height: u32,
    },
    absorb_public_claim,
    verify_and_absorb_interaction_pow: struct { bits: u32 },
    draw_relation_challenge: struct { challenge: u32 },
    absorb_claimed_sums: struct { count: u32 },
    draw_composition_randomness,
    draw_oods_point,
    accumulate_public_logup_term: struct { term: u32 },
    assert_global_logup_zero,
    evaluate_air_instruction: struct { instruction: u32 },
    assert_composition: struct { sampled_value_count: u32 },
    absorb_sampled_values: struct { count: u32 },
    draw_deep_randomness,
    absorb_fri_commitment: struct { layer: u32 },
    draw_fri_alpha: struct { layer: u32 },
    absorb_last_layer_coefficients: struct { count: u32 },
    verify_and_absorb_pcs_pow: struct { bits: u32 },
    draw_query_block: struct {
        block: u32,
        first_query: u32,
        query_count: u32,
    },
    verify_trace_merkle_path: struct {
        tree: u32,
        query: u32,
        depth: u32,
    },
    evaluate_deep_quotient: struct {
        query: u32,
        queried_values_per_query: u32,
    },
    verify_fri_merkle_path: struct {
        layer: u32,
        query: u32,
        depth: u32,
        width: u32,
    },
    fold_fri: struct {
        layer: u32,
        query: u32,
        width: u32,
    },
    verify_last_layer: struct { query: u32 },
    close_relation: struct { relation_index: u32 },
    complete,

    pub fn encode(self: VerifierStep) EncodedStep {
        return switch (self) {
            .bind_protocol => encoded(1, .{}),
            .bind_statement => encoded(2, .{}),
            .bind_pcs_parameters => encoded(3, .{}),
            .absorb_trace_commitment => |step| encoded(4, .{
                @intFromEnum(step.round), step.tree, step.height,
            }),
            .absorb_public_claim => encoded(5, .{}),
            .verify_and_absorb_interaction_pow => |step| encoded(6, .{step.bits}),
            .draw_relation_challenge => |step| encoded(7, .{step.challenge}),
            .absorb_claimed_sums => |step| encoded(8, .{step.count}),
            .draw_composition_randomness => encoded(9, .{}),
            .draw_oods_point => encoded(10, .{}),
            .accumulate_public_logup_term => |step| encoded(11, .{step.term}),
            .assert_global_logup_zero => encoded(12, .{}),
            .evaluate_air_instruction => |step| encoded(13, .{step.instruction}),
            .assert_composition => |step| encoded(14, .{step.sampled_value_count}),
            .absorb_sampled_values => |step| encoded(15, .{step.count}),
            .draw_deep_randomness => encoded(16, .{}),
            .absorb_fri_commitment => |step| encoded(17, .{step.layer}),
            .draw_fri_alpha => |step| encoded(18, .{step.layer}),
            .absorb_last_layer_coefficients => |step| encoded(19, .{step.count}),
            .verify_and_absorb_pcs_pow => |step| encoded(20, .{step.bits}),
            .draw_query_block => |step| encoded(21, .{
                step.block, step.first_query, step.query_count,
            }),
            .verify_trace_merkle_path => |step| encoded(22, .{
                step.tree, step.query, step.depth,
            }),
            .evaluate_deep_quotient => |step| encoded(23, .{
                step.query, step.queried_values_per_query,
            }),
            .verify_fri_merkle_path => |step| encoded(24, .{
                step.layer, step.query, step.depth, step.width,
            }),
            .fold_fri => |step| encoded(25, .{
                step.layer, step.query, step.width,
            }),
            .verify_last_layer => |step| encoded(26, .{step.query}),
            .close_relation => |step| encoded(27, .{step.relation_index}),
            .complete => encoded(28, .{}),
        };
    }

    pub fn terminal(self: VerifierStep) bool {
        return switch (self) {
            .close_relation, .complete => true,
            else => false,
        };
    }
};

pub const EncodedStep = struct {
    tag: u32,
    args: [4]u32,
    arity: u8,
};

pub const Error = fixed_profile.Error || std.mem.Allocator.Error || error{
    ArithmeticOverflow,
    IndexOutOfRange,
    InvalidQueryGeometry,
    InvalidScheduleShape,
    NonCanonicalIdentity,
    ProgramCountOutOfRange,
    ScheduleDigestMismatch,
    ZeroProgramCount,
};

/// Minimal proof-independent geometry consumed by the verifier step machine.
///
/// `ProofShapeV1` remains the only admitted production-wire profile. This
/// narrower form exists so an explicitly versioned candidate profile can be
/// measured without weakening or silently reinterpreting frozen V1. Both
/// identities are verifier-owned and are included in the plan seal.
pub const ScheduleShape = struct {
    protocol_id: channel.Digest,
    shape_id: channel.Digest,
    interaction_pow_bits: u32,
    pcs_pow_bits: u32,
    query_count: u32,
    table_count: u32,
    claimed_sum_count: u32,
    sampled_value_count: u32,
    tree_heights: [fixed_profile.TREE_COUNT]u32,
    fri: fixed_profile.FriSchedule,

    pub fn fromV1(shape: fixed_profile.ProofShapeV1) Error!ScheduleShape {
        try shape.validate();
        const result = ScheduleShape{
            .protocol_id = protocol.protocolId(),
            .shape_id = try shape.id(),
            .interaction_pow_bits = protocol.INTERACTION_POW_BITS,
            .pcs_pow_bits = protocol.PCS_POW_BITS,
            .query_count = @intCast(protocol.FRI_QUERY_COUNT),
            .table_count = shape.table_count,
            .claimed_sum_count = shape.claimed_sum_count,
            .sampled_value_count = shape.sampled_value_count,
            .tree_heights = shape.tree_heights,
            .fri = shape.fri,
        };
        try result.validate();
        return result;
    }

    pub fn validate(self: ScheduleShape) Error!void {
        try validateIdentity(self.protocol_id);
        try validateIdentity(self.shape_id);
        if (self.interaction_pow_bits >= m31.Modulus or
            self.pcs_pow_bits >= m31.Modulus or
            self.query_count == 0 or self.query_count >= m31.Modulus or
            self.table_count == 0 or self.table_count >= m31.Modulus or
            self.claimed_sum_count == 0 or self.claimed_sum_count >= m31.Modulus or
            self.sampled_value_count == 0 or self.sampled_value_count >= m31.Modulus or
            self.fri.count == 0 or self.fri.count > self.fri.rounds.len or
            self.fri.last_layer_coefficient_count == 0 or
            self.fri.last_layer_coefficient_count >= m31.Modulus)
        {
            return error.InvalidScheduleShape;
        }
        for (self.tree_heights) |height| if (height == 0 or
            height > fixed_profile.MAX_DOMAIN_LOG) return error.InvalidScheduleShape;
        for (self.fri.active()) |round| {
            if (round.fold_width < 2 or !std.math.isPowerOfTwo(round.fold_width) or
                round.authentication_path_depth > fixed_profile.MAX_DOMAIN_LOG)
            {
                return error.InvalidScheduleShape;
            }
        }
        _ = std.math.mul(u64, self.table_count, self.query_count) catch
            return error.ArithmeticOverflow;
    }
};

pub const ControlTraceError = error{
    ExtraStep,
    MissingStep,
    UnexpectedStep,
};

pub const Plan = struct {
    allocator: std.mem.Allocator,
    schema: Schema,
    spec: ProgramSpec,
    protocol_id: channel.Digest,
    shape_id: channel.Digest,
    authority_digest: channel.Digest,
    steps: []VerifierStep,

    pub fn init(
        allocator: std.mem.Allocator,
        spec: ProgramSpec,
        shape: fixed_profile.ProofShapeV1,
    ) Error!Plan {
        return initShape(allocator, spec, try ScheduleShape.fromV1(shape));
    }

    /// Builds a plan for a separately authenticated candidate profile. This
    /// API cannot make that profile production V1; callers must bind distinct
    /// protocol and shape identities and carry their own admission policy.
    pub fn initShape(
        allocator: std.mem.Allocator,
        spec: ProgramSpec,
        shape: ScheduleShape,
    ) Error!Plan {
        try shape.validate();
        _ = try ProgramSpec.init(
            spec.schema,
            spec.relation_challenge_count,
            spec.public_logup_term_count,
            spec.air_instruction_count,
            spec.relation_closure_count,
        );
        var steps: std.ArrayList(VerifierStep) = .empty;
        errdefer steps.deinit(allocator);

        try steps.appendSlice(allocator, &.{
            .bind_protocol,
            .bind_statement,
            .bind_pcs_parameters,
            commitmentStep(shape, .preprocessed, 0),
            commitmentStep(shape, .main, 1),
            .absorb_public_claim,
            .{ .verify_and_absorb_interaction_pow = .{
                .bits = shape.interaction_pow_bits,
            } },
        });
        for (0..spec.relation_challenge_count) |challenge| {
            try steps.append(allocator, .{ .draw_relation_challenge = .{
                .challenge = @intCast(challenge),
            } });
        }
        for (0..spec.public_logup_term_count) |term| {
            try steps.append(allocator, .{ .accumulate_public_logup_term = .{
                .term = @intCast(term),
            } });
        }
        try steps.appendSlice(allocator, &.{
            .assert_global_logup_zero,
            .{ .absorb_claimed_sums = .{ .count = shape.claimed_sum_count } },
            commitmentStep(shape, .interaction, 2),
            .draw_composition_randomness,
            commitmentStep(shape, .composition, 3),
            .draw_oods_point,
        });
        for (0..spec.air_instruction_count) |instruction| {
            try steps.append(allocator, .{ .evaluate_air_instruction = .{
                .instruction = @intCast(instruction),
            } });
        }
        try steps.appendSlice(allocator, &.{
            .{ .assert_composition = .{
                .sampled_value_count = shape.sampled_value_count,
            } },
            .{ .absorb_sampled_values = .{ .count = shape.sampled_value_count } },
            .draw_deep_randomness,
        });
        for (shape.fri.active(), 0..) |_, layer| {
            const layer_u32 = try indexU32(layer);
            try steps.appendSlice(allocator, &.{
                .{ .absorb_fri_commitment = .{ .layer = layer_u32 } },
                .{ .draw_fri_alpha = .{ .layer = layer_u32 } },
            });
        }
        try steps.appendSlice(allocator, &.{
            .{ .absorb_last_layer_coefficients = .{
                .count = shape.fri.last_layer_coefficient_count,
            } },
            .{ .verify_and_absorb_pcs_pow = .{ .bits = shape.pcs_pow_bits } },
        });
        const query_count: usize = @intCast(shape.query_count);
        try appendQueryDraws(allocator, &steps, query_count);
        try appendTraceOpenings(allocator, &steps, shape, query_count);

        const queried_values = std.math.mul(
            u64,
            shape.table_count,
            shape.query_count,
        ) catch return error.ArithmeticOverflow;
        if (queried_values % shape.query_count != 0)
            return error.InvalidQueryGeometry;
        const per_query = queried_values / shape.query_count;
        if (per_query > std.math.maxInt(u32)) return error.IndexOutOfRange;
        for (0..query_count) |query| {
            try steps.append(allocator, .{ .evaluate_deep_quotient = .{
                .query = try indexU32(query),
                .queried_values_per_query = @intCast(per_query),
            } });
        }
        try appendFriChecks(allocator, &steps, shape, query_count);
        for (0..query_count) |query| {
            try steps.append(allocator, .{ .verify_last_layer = .{
                .query = try indexU32(query),
            } });
        }
        for (0..spec.relation_closure_count) |relation_index| {
            try steps.append(allocator, .{ .close_relation = .{
                .relation_index = @intCast(relation_index),
            } });
        }
        try steps.append(allocator, .complete);

        const owned = try steps.toOwnedSlice(allocator);
        errdefer allocator.free(owned);
        const authority_digest = try computeDigest(
            allocator,
            spec,
            shape.protocol_id,
            shape.shape_id,
            owned,
        );
        return .{
            .allocator = allocator,
            .schema = spec.schema,
            .spec = spec,
            .protocol_id = shape.protocol_id,
            .shape_id = shape.shape_id,
            .authority_digest = authority_digest,
            .steps = owned,
        };
    }

    pub fn deinit(self: *Plan) void {
        self.allocator.free(self.steps);
        self.* = undefined;
    }

    pub fn validate(self: *const Plan) Error!void {
        const actual = try computeDigest(
            self.allocator,
            self.spec,
            self.protocol_id,
            self.shape_id,
            self.steps,
        );
        if (!std.meta.eql(actual, self.authority_digest))
            return error.ScheduleDigestMismatch;
    }

    pub fn verifyControlTrace(
        self: *const Plan,
        actual: []const VerifierStep,
    ) ControlTraceError!void {
        for (self.steps, 0..) |expected, sequence| {
            if (sequence >= actual.len) return error.MissingStep;
            if (!std.meta.eql(expected, actual[sequence]))
                return error.UnexpectedStep;
        }
        if (actual.len != self.steps.len) return error.ExtraStep;
    }
};

fn encoded(comptime tag: u32, args: anytype) EncodedStep {
    comptime if (args.len > 4) @compileError("verifier steps encode at most four arguments");
    var result = EncodedStep{
        .tag = tag,
        .args = .{ 0, 0, 0, 0 },
        .arity = args.len,
    };
    inline for (args, 0..) |arg, index| result.args[index] = arg;
    return result;
}

fn commitmentStep(
    shape: ScheduleShape,
    round: CommitmentRound,
    tree: usize,
) VerifierStep {
    return .{ .absorb_trace_commitment = .{
        .round = round,
        .tree = @intCast(tree),
        .height = shape.tree_heights[tree],
    } };
}

fn appendQueryDraws(
    allocator: std.mem.Allocator,
    steps: *std.ArrayList(VerifierStep),
    query_count: usize,
) Error!void {
    var first_query: usize = 0;
    var block: usize = 0;
    while (first_query < query_count) {
        const width = @min(query_count - first_query, QUERY_WORDS_PER_DRAW);
        try steps.append(allocator, .{ .draw_query_block = .{
            .block = try indexU32(block),
            .first_query = try indexU32(first_query),
            .query_count = try indexU32(width),
        } });
        first_query += width;
        block += 1;
    }
}

fn appendTraceOpenings(
    allocator: std.mem.Allocator,
    steps: *std.ArrayList(VerifierStep),
    shape: ScheduleShape,
    query_count: usize,
) Error!void {
    for (0..fixed_profile.TREE_COUNT) |tree| {
        for (0..query_count) |query| {
            try steps.append(allocator, .{ .verify_trace_merkle_path = .{
                .tree = try indexU32(tree),
                .query = try indexU32(query),
                .depth = shape.tree_heights[tree],
            } });
        }
    }
}

fn appendFriChecks(
    allocator: std.mem.Allocator,
    steps: *std.ArrayList(VerifierStep),
    shape: ScheduleShape,
    query_count: usize,
) Error!void {
    for (shape.fri.active(), 0..) |round, layer| {
        const layer_u32 = try indexU32(layer);
        for (0..query_count) |query| {
            const query_u32 = try indexU32(query);
            try steps.appendSlice(allocator, &.{
                .{ .verify_fri_merkle_path = .{
                    .layer = layer_u32,
                    .query = query_u32,
                    .depth = round.authentication_path_depth,
                    .width = round.fold_width,
                } },
                .{ .fold_fri = .{
                    .layer = layer_u32,
                    .query = query_u32,
                    .width = round.fold_width,
                } },
            });
        }
    }
}

fn computeDigest(
    allocator: std.mem.Allocator,
    spec: ProgramSpec,
    protocol_id: channel.Digest,
    shape_id: channel.Digest,
    steps: []const VerifierStep,
) Error!channel.Digest {
    var words: std.ArrayList(u32) = .empty;
    defer words.deinit(allocator);
    try words.ensureTotalCapacity(
        allocator,
        8 + 2 * channel.RATE + steps.len * 6,
    );
    try words.appendSlice(allocator, &.{
        FORMAT_VERSION,
        @intFromEnum(spec.schema),
        spec.relation_challenge_count,
        spec.public_logup_term_count,
        spec.air_instruction_count,
        spec.relation_closure_count,
        @intCast(steps.len),
    });
    try words.appendSlice(allocator, &protocol_id);
    try words.appendSlice(allocator, &shape_id);
    for (steps) |step| {
        const item = step.encode();
        try words.append(allocator, item.tag);
        try words.append(allocator, item.arity);
        try words.appendSlice(allocator, item.args[0..item.arity]);
    }
    return channel.hashCanonicalU32s(words.items, PLAN_DIGEST_DOMAIN);
}

fn validateIdentity(value: channel.Digest) Error!void {
    var aggregate: u32 = 0;
    for (value) |word| {
        if (word >= m31.Modulus) return error.NonCanonicalIdentity;
        aggregate |= word;
    }
    if (aggregate == 0) return error.NonCanonicalIdentity;
}

fn indexU32(value: usize) Error!u32 {
    return std.math.cast(u32, value) orelse error.IndexOutOfRange;
}

test "R-012 verifier schedule pins all 28 exact step encodings" {
    const cases = [_]struct { step: VerifierStep, tag: u32, args: [4]u32, arity: u8 }{
        .{ .step = .bind_protocol, .tag = 1, .args = .{ 0, 0, 0, 0 }, .arity = 0 },
        .{ .step = .bind_statement, .tag = 2, .args = .{ 0, 0, 0, 0 }, .arity = 0 },
        .{ .step = .bind_pcs_parameters, .tag = 3, .args = .{ 0, 0, 0, 0 }, .arity = 0 },
        .{ .step = .{ .absorb_trace_commitment = .{ .round = .main, .tree = 1, .height = 8 } }, .tag = 4, .args = .{ 2, 1, 8, 0 }, .arity = 3 },
        .{ .step = .absorb_public_claim, .tag = 5, .args = .{ 0, 0, 0, 0 }, .arity = 0 },
        .{ .step = .{ .verify_and_absorb_interaction_pow = .{ .bits = 9 } }, .tag = 6, .args = .{ 9, 0, 0, 0 }, .arity = 1 },
        .{ .step = .{ .draw_relation_challenge = .{ .challenge = 4 } }, .tag = 7, .args = .{ 4, 0, 0, 0 }, .arity = 1 },
        .{ .step = .{ .absorb_claimed_sums = .{ .count = 5 } }, .tag = 8, .args = .{ 5, 0, 0, 0 }, .arity = 1 },
        .{ .step = .draw_composition_randomness, .tag = 9, .args = .{ 0, 0, 0, 0 }, .arity = 0 },
        .{ .step = .draw_oods_point, .tag = 10, .args = .{ 0, 0, 0, 0 }, .arity = 0 },
        .{ .step = .{ .accumulate_public_logup_term = .{ .term = 3 } }, .tag = 11, .args = .{ 3, 0, 0, 0 }, .arity = 1 },
        .{ .step = .assert_global_logup_zero, .tag = 12, .args = .{ 0, 0, 0, 0 }, .arity = 0 },
        .{ .step = .{ .evaluate_air_instruction = .{ .instruction = 6 } }, .tag = 13, .args = .{ 6, 0, 0, 0 }, .arity = 1 },
        .{ .step = .{ .assert_composition = .{ .sampled_value_count = 7 } }, .tag = 14, .args = .{ 7, 0, 0, 0 }, .arity = 1 },
        .{ .step = .{ .absorb_sampled_values = .{ .count = 8 } }, .tag = 15, .args = .{ 8, 0, 0, 0 }, .arity = 1 },
        .{ .step = .draw_deep_randomness, .tag = 16, .args = .{ 0, 0, 0, 0 }, .arity = 0 },
        .{ .step = .{ .absorb_fri_commitment = .{ .layer = 1 } }, .tag = 17, .args = .{ 1, 0, 0, 0 }, .arity = 1 },
        .{ .step = .{ .draw_fri_alpha = .{ .layer = 2 } }, .tag = 18, .args = .{ 2, 0, 0, 0 }, .arity = 1 },
        .{ .step = .{ .absorb_last_layer_coefficients = .{ .count = 9 } }, .tag = 19, .args = .{ 9, 0, 0, 0 }, .arity = 1 },
        .{ .step = .{ .verify_and_absorb_pcs_pow = .{ .bits = 10 } }, .tag = 20, .args = .{ 10, 0, 0, 0 }, .arity = 1 },
        .{ .step = .{ .draw_query_block = .{ .block = 1, .first_query = 8, .query_count = 8 } }, .tag = 21, .args = .{ 1, 8, 8, 0 }, .arity = 3 },
        .{ .step = .{ .verify_trace_merkle_path = .{ .tree = 2, .query = 3, .depth = 4 } }, .tag = 22, .args = .{ 2, 3, 4, 0 }, .arity = 3 },
        .{ .step = .{ .evaluate_deep_quotient = .{ .query = 5, .queried_values_per_query = 6 } }, .tag = 23, .args = .{ 5, 6, 0, 0 }, .arity = 2 },
        .{ .step = .{ .verify_fri_merkle_path = .{ .layer = 1, .query = 2, .depth = 3, .width = 4 } }, .tag = 24, .args = .{ 1, 2, 3, 4 }, .arity = 4 },
        .{ .step = .{ .fold_fri = .{ .layer = 2, .query = 3, .width = 4 } }, .tag = 25, .args = .{ 2, 3, 4, 0 }, .arity = 3 },
        .{ .step = .{ .verify_last_layer = .{ .query = 7 } }, .tag = 26, .args = .{ 7, 0, 0, 0 }, .arity = 1 },
        .{ .step = .{ .close_relation = .{ .relation_index = 8 } }, .tag = 27, .args = .{ 8, 0, 0, 0 }, .arity = 1 },
        .{ .step = .complete, .tag = 28, .args = .{ 0, 0, 0, 0 }, .arity = 0 },
    };
    for (cases) |case| {
        const actual = case.step.encode();
        try std.testing.expectEqual(case.tag, actual.tag);
        try std.testing.expectEqual(case.args, actual.args);
        try std.testing.expectEqual(case.arity, actual.arity);
        for (actual.args[actual.arity..]) |padding|
            try std.testing.expectEqual(@as(u32, 0), padding);
    }
    try std.testing.expect(cases[26].step.terminal());
    try std.testing.expect(cases[27].step.terminal());
}

test "R-012 verifier plan derives full query FRI and closure schedule from authority" {
    const shape = try testShape();
    var plan = try Plan.init(std.testing.allocator, VM_PROGRAM_SPEC_V1, shape);
    defer plan.deinit();
    try plan.validate();
    try plan.verifyControlTrace(plan.steps);
    try std.testing.expect(std.meta.eql(plan.steps[0], VerifierStep.bind_protocol));
    try std.testing.expect(std.meta.eql(plan.steps[plan.steps.len - 1], VerifierStep.complete));

    var relation_draws: usize = 0;
    var query_draws: usize = 0;
    var trace_paths: usize = 0;
    var fri_paths: usize = 0;
    var fri_folds: usize = 0;
    var closures: usize = 0;
    for (plan.steps) |step| switch (step) {
        .draw_relation_challenge => relation_draws += 1,
        .draw_query_block => query_draws += 1,
        .verify_trace_merkle_path => trace_paths += 1,
        .verify_fri_merkle_path => fri_paths += 1,
        .fold_fri => fri_folds += 1,
        .close_relation => closures += 1,
        else => {},
    };
    try std.testing.expectEqual(@as(usize, 12), relation_draws);
    try std.testing.expectEqual(
        (protocol.FRI_QUERY_COUNT + QUERY_WORDS_PER_DRAW - 1) / QUERY_WORDS_PER_DRAW,
        query_draws,
    );
    try std.testing.expectEqual(fixed_profile.TREE_COUNT * protocol.FRI_QUERY_COUNT, trace_paths);
    try std.testing.expectEqual(shape.fri.count * protocol.FRI_QUERY_COUNT, fri_paths);
    try std.testing.expectEqual(fri_paths, fri_folds);
    try std.testing.expectEqual(@as(usize, 12), closures);
}

test "R-012 frozen verifier programs separate VM and universal relation domains" {
    try std.testing.expectEqual(@as(u32, 12), VM_PROGRAM_SPEC_V1.relation_challenge_count);
    try std.testing.expectEqual(@as(u32, 12), VM_PROGRAM_SPEC_V1.relation_closure_count);
    try std.testing.expectEqual(
        VM_PUBLIC_LOGUP_FIXED_TERM_COUNT,
        VM_PROGRAM_SPEC_V1.public_logup_term_count,
    );
    const shaped = try vmProgramSpec(7, 11);
    try std.testing.expectEqual(@as(u32, 88), shaped.public_logup_term_count);
    try std.testing.expectEqual(@as(u32, 47), RECURSION_PROGRAM_SPEC_V1.relation_challenge_count);
    try std.testing.expectEqual(@as(u32, 47), RECURSION_PROGRAM_SPEC_V1.relation_closure_count);
}

test "R-012 verifier plan detects schedule mutation omission and extension" {
    const shape = try testShape();
    const spec = try ProgramSpec.init(.recursion, 47, 0, 17, 47);
    var plan = try Plan.init(std.testing.allocator, spec, shape);
    defer plan.deinit();
    var changed = try std.testing.allocator.dupe(VerifierStep, plan.steps);
    defer std.testing.allocator.free(changed);
    changed[0] = .bind_statement;
    try std.testing.expectError(error.UnexpectedStep, plan.verifyControlTrace(changed));
    try std.testing.expectError(
        error.MissingStep,
        plan.verifyControlTrace(plan.steps[0 .. plan.steps.len - 1]),
    );
    var extended = try std.testing.allocator.alloc(VerifierStep, plan.steps.len + 1);
    defer std.testing.allocator.free(extended);
    @memcpy(extended[0..plan.steps.len], plan.steps);
    extended[plan.steps.len] = .complete;
    try std.testing.expectError(error.ExtraStep, plan.verifyControlTrace(extended));

    plan.steps[0] = .bind_statement;
    try std.testing.expectError(error.ScheduleDigestMismatch, plan.validate());
}

test "R-012 candidate schedule is domain-separated without changing frozen V1" {
    const fixed = try testShape();
    var frozen = try Plan.init(std.testing.allocator, VM_PROGRAM_SPEC_V1, fixed);
    defer frozen.deinit();
    var lifted = try Plan.initShape(
        std.testing.allocator,
        VM_PROGRAM_SPEC_V1,
        try ScheduleShape.fromV1(fixed),
    );
    defer lifted.deinit();
    try std.testing.expectEqual(frozen.authority_digest, lifted.authority_digest);

    var candidate_shape = try ScheduleShape.fromV1(fixed);
    candidate_shape.protocol_id = channel.hashBytes("candidate-protocol", 0x4350);
    candidate_shape.shape_id = channel.hashBytes("candidate-shape", 0x4353);
    candidate_shape.query_count = 97;
    var candidate = try Plan.initShape(
        std.testing.allocator,
        VM_PROGRAM_SPEC_V1,
        candidate_shape,
    );
    defer candidate.deinit();
    var query_draws: usize = 0;
    var trace_paths: usize = 0;
    var fri_folds: usize = 0;
    for (candidate.steps) |step| switch (step) {
        .draw_query_block => query_draws += 1,
        .verify_trace_merkle_path => trace_paths += 1,
        .fold_fri => fri_folds += 1,
        else => {},
    };
    try std.testing.expectEqual(@as(usize, 13), query_draws);
    try std.testing.expectEqual(fixed_profile.TREE_COUNT * 97, trace_paths);
    try std.testing.expectEqual(@as(usize, candidate_shape.fri.count) * 97, fri_folds);
    try std.testing.expect(!std.meta.eql(
        frozen.authority_digest,
        candidate.authority_digest,
    ));

    candidate.protocol_id[0] +%= 1;
    try std.testing.expectError(error.ScheduleDigestMismatch, candidate.validate());
}

test "R-012 verifier schedule releases every allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        planAllocationFailureCase,
        .{},
    );
}

fn planAllocationFailureCase(allocator: std.mem.Allocator) !void {
    var plan = try Plan.init(
        allocator,
        try ProgramSpec.init(.vm, 47, 5, 101, 47),
        try testShape(),
    );
    defer plan.deinit();
}

fn testShape() !fixed_profile.ProofShapeV1 {
    const fri = try fixed_profile.FriSchedule.init(24, protocol.PCS_CONFIG.fri_config);
    return .{
        .air_program_id = channel.hashBytes("air-program", 0x5450),
        .preprocessing_id = channel.hashBytes("preprocessing", 0x5450),
        .table_layout_id = channel.hashBytes("ordered-table-layout", 0x5450),
        .table_count = 2_000,
        .claimed_sum_count = 36,
        .sampled_value_count = 2_100,
        .preprocessed_column_count = 128,
        .tree_column_counts = .{ 128, 1_500, 364, 8 },
        .tree_heights = .{ 25, 25, 25, 25 },
        .column_log_degree = 24,
        .proof_wire_bytes = 3_500_000,
        .fri = fri,
    };
}
