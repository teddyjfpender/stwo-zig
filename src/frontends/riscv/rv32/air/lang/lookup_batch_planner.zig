//! Deterministic degree-aware partitioning of ordered LogUp events.
//!
//! V1 considers only the recurrence already implemented by the prover:
//! singleton and adjacent two-entry batches.  Event order never changes.  The
//! objective is deliberately lexicographic rather than a fabricated timing
//! scalar:
//!
//! 1. minimize the whole-proof quotient expansion after accounting for every
//!    constraint outside the batches being selected;
//! 2. minimize committed interaction columns (equivalently batch count);
//! 3. minimize the maximum interaction degree;
//! 4. prefer the earliest legal pair as the canonical final tie-break.
//!
//! The resulting digest binds the semantic program, policy, ordered input
//! degrees, and every selected batch.  Production activation still requires a
//! proof/transcript version and end-to-end performance evidence.

const std = @import("std");
const protocol_degree = @import("protocol_degree.zig");

pub const FORMAT_VERSION: u16 = 1;
pub const DIGEST_DOMAIN = "stwo-zig/typed-air/lookup-batch-plan/v1\x00";
pub const MAXIMUM_SUPPORTED_DEGREE: protocol_degree.Degree = 16;
pub const MAXIMUM_BATCH_SIZE: u8 = 2;
pub const INTERACTION_COORDINATES_PER_BATCH: u8 = 4;
pub const PAIR_CROSS_MULTIPLICATIONS: u8 = 3;
pub const Digest = [32]u8;

pub const Error = std.mem.Allocator.Error || error{
    CountOverflow,
    DegreeOverflow,
    InvalidBatch,
    InvalidDigest,
    InvalidEvent,
    InvalidPlan,
    InvalidPolicy,
    NoFeasiblePartition,
};

pub const PolicyV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    maximum_batch_size: u8 = MAXIMUM_BATCH_SIZE,
    interaction_coordinates_per_batch: u8 =
        INTERACTION_COORDINATES_PER_BATCH,
    maximum_interaction_degree: protocol_degree.Degree,

    pub fn validate(self: PolicyV1) Error!void {
        if (self.format_version != FORMAT_VERSION or
            self.maximum_batch_size != MAXIMUM_BATCH_SIZE or
            self.interaction_coordinates_per_batch !=
                INTERACTION_COORDINATES_PER_BATCH or
            self.maximum_interaction_degree == 0 or
            self.maximum_interaction_degree > MAXIMUM_SUPPORTED_DEGREE)
        {
            return error.InvalidPolicy;
        }
    }
};

/// Degree facts for one typed relation effect in declaration order.  The
/// semantic program digest binds schema, role, fields, liveness, and ordinal;
/// these explicit fields make the cost decision independently auditable.
pub const Event = struct {
    ordinal: u32,
    numerator_degree: protocol_degree.Degree,
    denominator_degree: protocol_degree.Degree,

    pub fn fraction(self: Event) protocol_degree.FractionDegree {
        return .{
            .numerator = self.numerator_degree,
            .denominator = self.denominator_degree,
        };
    }
};

pub const Batch = struct {
    first_event: u32,
    event_count: u8,
    terms: protocol_degree.InteractionTerms,
};

pub const Score = struct {
    quotient_expansion_bits: u8,
    batch_count: u32,
    interaction_columns: u32,
    maximum_interaction_degree: protocol_degree.Degree,
    paired_batch_count: u32,
    pair_cross_multiplications: u32,

    fn betterThan(self: Score, other: Score) bool {
        if (self.quotient_expansion_bits != other.quotient_expansion_bits)
            return self.quotient_expansion_bits < other.quotient_expansion_bits;
        if (self.interaction_columns != other.interaction_columns)
            return self.interaction_columns < other.interaction_columns;
        if (self.maximum_interaction_degree != other.maximum_interaction_degree)
            return self.maximum_interaction_degree < other.maximum_interaction_degree;
        // The first three coordinates normally determine this value. Retain
        // it as a stable defensive tie-break if later recurrence accounting
        // makes two equal-width partitions differ in arithmetic work.
        return self.pair_cross_multiplications < other.pair_cross_multiplications;
    }
};

pub const Plan = struct {
    allocator: std.mem.Allocator,
    program_digest: Digest,
    policy: PolicyV1,
    /// Maximum proof-wide degree outside this plan.  Supplying only the local
    /// component's direct degree is invalid cost modeling when another
    /// component already fixes a larger composition domain.
    ambient_constraint_degree: protocol_degree.Degree,
    event_count: u32,
    batches: []Batch,
    score: Score,
    plan_digest: Digest,

    pub fn deinit(self: *Plan) void {
        self.allocator.free(self.batches);
        self.* = undefined;
    }

    pub fn validate(self: *const Plan, events: []const Event) Error!void {
        try self.policy.validate();
        try validateProgramDigest(self.program_digest);
        try validateEvents(events);
        if (self.event_count != events.len or
            self.batches.len != self.score.batch_count)
        {
            return error.InvalidPlan;
        }

        var cursor: usize = 0;
        var maximum_interaction: protocol_degree.Degree = 0;
        var paired: u32 = 0;
        for (self.batches) |batch| {
            const end = std.math.add(
                usize,
                cursor,
                batch.event_count,
            ) catch return error.CountOverflow;
            if (batch.first_event != cursor or
                batch.event_count == 0 or
                batch.event_count > self.policy.maximum_batch_size or
                end > events.len)
            {
                return error.InvalidBatch;
            }
            const second = if (batch.event_count == 2)
                events[cursor + 1].fraction()
            else
                null;
            const expected = interactionTerms(
                events[cursor].fraction(),
                second,
            ) catch return error.DegreeOverflow;
            if (!std.meta.eql(batch.terms, expected) or
                expected.final > self.policy.maximum_interaction_degree)
            {
                return error.InvalidBatch;
            }
            maximum_interaction = @max(maximum_interaction, expected.final);
            if (batch.event_count == 2) paired += 1;
            cursor = end;
        }
        if (cursor != events.len) return error.InvalidPlan;

        const expected_score = try makeScore(
            self.ambient_constraint_degree,
            self.batches.len,
            paired,
            maximum_interaction,
            self.policy.interaction_coordinates_per_batch,
        );
        if (!std.meta.eql(self.score, expected_score)) return error.InvalidPlan;
        const expected_digest = identityDigest(self, events);
        if (!std.mem.eql(u8, &expected_digest, &self.plan_digest))
            return error.InvalidDigest;
    }
};

pub fn select(
    allocator: std.mem.Allocator,
    program_digest: Digest,
    ambient_constraint_degree: protocol_degree.Degree,
    events: []const Event,
    policy: PolicyV1,
) Error!Plan {
    try policy.validate();
    try validateProgramDigest(program_digest);
    try validateEvents(events);
    if (events.len > std.math.maxInt(u32)) return error.CountOverflow;

    if (events.len == 0) {
        const batches = try allocator.alloc(Batch, 0);
        errdefer allocator.free(batches);
        var result = Plan{
            .allocator = allocator,
            .program_digest = program_digest,
            .policy = policy,
            .ambient_constraint_degree = ambient_constraint_degree,
            .event_count = 0,
            .batches = batches,
            .score = try makeScore(
                ambient_constraint_degree,
                0,
                0,
                0,
                policy.interaction_coordinates_per_batch,
            ),
            .plan_digest = undefined,
        };
        result.plan_digest = identityDigest(&result, events);
        try result.validate(events);
        return result;
    }

    const count_slots = std.math.add(usize, events.len, 1) catch
        return error.CountOverflow;
    const counts = try allocator.alloc(u32, count_slots);
    defer allocator.free(counts);
    const choices = try allocator.alloc(u8, events.len);
    defer allocator.free(choices);

    var best_cap: ?protocol_degree.Degree = null;
    var best_score: Score = undefined;
    var cap: protocol_degree.Degree = 1;
    while (cap <= policy.maximum_interaction_degree) : (cap += 1) {
        if (!try solveForCap(events, cap, counts, choices)) continue;
        const score = try scoreChoices(
            events,
            choices,
            ambient_constraint_degree,
            policy.interaction_coordinates_per_batch,
        );
        if (best_cap == null or score.betterThan(best_score)) {
            best_cap = cap;
            best_score = score;
        }
    }
    const selected_cap = best_cap orelse return error.NoFeasiblePartition;
    if (!try solveForCap(events, selected_cap, counts, choices))
        return error.NoFeasiblePartition;

    const batches = try allocator.alloc(Batch, best_score.batch_count);
    errdefer allocator.free(batches);
    var event_index: usize = 0;
    var batch_index: usize = 0;
    while (event_index < events.len) : (batch_index += 1) {
        const width = choices[event_index];
        if (width == 0 or width > MAXIMUM_BATCH_SIZE)
            return error.InvalidPlan;
        const second = if (width == 2)
            events[event_index + 1].fraction()
        else
            null;
        batches[batch_index] = .{
            .first_event = @intCast(event_index),
            .event_count = width,
            .terms = interactionTerms(
                events[event_index].fraction(),
                second,
            ) catch return error.DegreeOverflow,
        };
        event_index += width;
    }
    std.debug.assert(batch_index == batches.len);

    var result = Plan{
        .allocator = allocator,
        .program_digest = program_digest,
        .policy = policy,
        .ambient_constraint_degree = ambient_constraint_degree,
        .event_count = @intCast(events.len),
        .batches = batches,
        .score = best_score,
        .plan_digest = undefined,
    };
    result.plan_digest = identityDigest(&result, events);
    try result.validate(events);
    return result;
}

fn solveForCap(
    events: []const Event,
    cap: protocol_degree.Degree,
    counts: []u32,
    choices: []u8,
) Error!bool {
    std.debug.assert(counts.len == events.len + 1);
    std.debug.assert(choices.len == events.len);
    const unreachable_count: u32 = std.math.maxInt(u32);
    @memset(counts, unreachable_count);
    @memset(choices, 0);
    counts[events.len] = 0;

    var index = events.len;
    while (index > 0) {
        index -= 1;
        var selected_count: u32 = unreachable_count;
        var selected_width: u8 = 0;

        const single = interactionTerms(events[index].fraction(), null) catch
            return error.DegreeOverflow;
        if (single.final <= cap and counts[index + 1] != unreachable_count) {
            selected_count = std.math.add(u32, counts[index + 1], 1) catch
                return error.CountOverflow;
            selected_width = 1;
        }

        if (index + 1 < events.len and counts[index + 2] != unreachable_count) {
            const pair = interactionTerms(
                events[index].fraction(),
                events[index + 1].fraction(),
            ) catch return error.DegreeOverflow;
            if (pair.final <= cap) {
                const pair_count = std.math.add(u32, counts[index + 2], 1) catch
                    return error.CountOverflow;
                if (pair_count <= selected_count) {
                    selected_count = pair_count;
                    selected_width = 2;
                }
            }
        }
        counts[index] = selected_count;
        choices[index] = selected_width;
    }
    return counts[0] != unreachable_count;
}

fn scoreChoices(
    events: []const Event,
    choices: []const u8,
    ambient_constraint_degree: protocol_degree.Degree,
    interaction_coordinates_per_batch: u8,
) Error!Score {
    var event_index: usize = 0;
    var batch_count: usize = 0;
    var paired: u32 = 0;
    var maximum_interaction: protocol_degree.Degree = 0;
    while (event_index < events.len) {
        const width = choices[event_index];
        if (width == 0 or width > MAXIMUM_BATCH_SIZE or
            event_index + width > events.len)
        {
            return error.InvalidPlan;
        }
        const second = if (width == 2)
            events[event_index + 1].fraction()
        else
            null;
        const terms = interactionTerms(
            events[event_index].fraction(),
            second,
        ) catch return error.DegreeOverflow;
        maximum_interaction = @max(maximum_interaction, terms.final);
        if (width == 2) paired += 1;
        event_index += width;
        batch_count += 1;
    }
    return makeScore(
        ambient_constraint_degree,
        batch_count,
        paired,
        maximum_interaction,
        interaction_coordinates_per_batch,
    );
}

fn makeScore(
    ambient_constraint_degree: protocol_degree.Degree,
    batch_count: usize,
    paired_batch_count: u32,
    maximum_interaction_degree: protocol_degree.Degree,
    interaction_coordinates_per_batch: u8,
) Error!Score {
    const batch_count_u32 = std.math.cast(u32, batch_count) orelse
        return error.CountOverflow;
    const interaction_columns = std.math.mul(
        u32,
        batch_count_u32,
        interaction_coordinates_per_batch,
    ) catch return error.CountOverflow;
    const pair_cross_multiplications = std.math.mul(
        u32,
        paired_batch_count,
        PAIR_CROSS_MULTIPLICATIONS,
    ) catch return error.CountOverflow;
    return .{
        .quotient_expansion_bits = protocol_degree.quotientExpansionBits(@max(
            ambient_constraint_degree,
            maximum_interaction_degree,
        )),
        .batch_count = batch_count_u32,
        .interaction_columns = interaction_columns,
        .maximum_interaction_degree = maximum_interaction_degree,
        .paired_batch_count = paired_batch_count,
        .pair_cross_multiplications = pair_cross_multiplications,
    };
}

fn interactionTerms(
    first: protocol_degree.FractionDegree,
    second: ?protocol_degree.FractionDegree,
) error{DegreeOverflow}!protocol_degree.InteractionTerms {
    return protocol_degree.interactionTerms(first, second) catch
        error.DegreeOverflow;
}

fn validateEvents(events: []const Event) Error!void {
    if (events.len > std.math.maxInt(u32)) return error.CountOverflow;
    for (events, 0..) |event, index| {
        if (event.ordinal != index or
            event.numerator_degree > MAXIMUM_SUPPORTED_DEGREE or
            event.denominator_degree > MAXIMUM_SUPPORTED_DEGREE)
        {
            return error.InvalidEvent;
        }
    }
}

fn validateProgramDigest(value: Digest) Error!void {
    if (std.mem.allEqual(u8, &value, 0)) return error.InvalidDigest;
}

fn identityDigest(plan: *const Plan, events: []const Event) Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(DIGEST_DOMAIN);
    hashInt(&hash, u16, plan.policy.format_version);
    hashInt(&hash, u8, plan.policy.maximum_batch_size);
    hashInt(&hash, u8, plan.policy.interaction_coordinates_per_batch);
    hashInt(&hash, u32, plan.policy.maximum_interaction_degree);
    hash.update(&plan.program_digest);
    hashInt(&hash, u32, plan.ambient_constraint_degree);
    hashInt(&hash, u32, plan.event_count);
    for (events) |event| {
        hashInt(&hash, u32, event.ordinal);
        hashInt(&hash, u32, event.numerator_degree);
        hashInt(&hash, u32, event.denominator_degree);
    }
    hashInt(&hash, u32, plan.score.quotient_expansion_bits);
    hashInt(&hash, u32, plan.score.batch_count);
    hashInt(&hash, u32, plan.score.interaction_columns);
    hashInt(&hash, u32, plan.score.maximum_interaction_degree);
    hashInt(&hash, u32, plan.score.paired_batch_count);
    hashInt(&hash, u32, plan.score.pair_cross_multiplications);
    for (plan.batches) |batch| {
        hashInt(&hash, u32, batch.first_event);
        hashInt(&hash, u8, batch.event_count);
        hashInt(&hash, u32, batch.terms.row_window);
        hashInt(&hash, u32, batch.terms.boundary_selector);
        hashInt(&hash, u32, batch.terms.boundary_claim);
        hashInt(&hash, u32, batch.terms.delta);
        hashInt(&hash, u32, batch.terms.denominator_product);
        hashInt(&hash, u32, batch.terms.combined_numerator);
        hashInt(&hash, u32, batch.terms.final);
    }
    return hash.finalResult();
}

fn hashInt(hash: anytype, comptime T: type, value: T) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    hash.update(&bytes);
}
