//! Typed order for the candidate S31NAT9F four-root, two-track Gate channel.
//!
//! Its methods check the proposed transcript event sequence when callers use
//! the wrapper as intended; Zig exposes mutable struct fields, so this is not
//! a selected verifier's encapsulation boundary. Statement digests and fold
//! heights must come from a sealed key and checked geometry, not proof bytes.
//! Each named challenge event accepts one exact eight-limb block. Lookup uses
//! both QM31 values; scalar challenges use the first four limbs and discard
//! the second four. More accepted blocks require a new protocol revision.
const std = @import("std");
const framed = @import("framed_bcs_v2.zig");
const uniform_queries = @import("../queries/uniform_v1.zig");

pub const max_fold_heights: usize = 64;
pub const Error = error{ InvalidFoldHeightRoster, UnexpectedStage } || framed.Error || uniform_queries.Error;

pub const Stage = enum {
    fixed_root,
    circuit_identity,
    public_values,
    main_root,
    interaction_pow,
    interaction_nonce,
    lookup_pair,
    interaction_claim,
    interaction_root,
    composition_gamma,
    composition_root,
    oods_seed,
    sampled_values,
    batch_lambda,
    fold_alpha,
    original_line_root,
    own_quotient_line_root,
    original_terminal_coefficients,
    own_quotient_terminal_coefficients,
    fri_pow,
    fri_nonce,
    queries,
    complete,
};

/// A fixed-size roster copy avoids aliasing the caller's input slice. The
/// fields remain publicly mutable in Zig. A selected verifier must own this
/// value privately and derive its roster and descriptors from its sealed key.
pub const PairedGateEventPlanV2 = struct {
    channel: framed.FramedBcsChannelV2,
    stage: Stage,
    fold_heights: [max_fold_heights]u32,
    fold_count: usize,
    fold_index: usize,

    const Self = @This();

    pub fn init(statement: framed.StatementBinding, heights: []const u32) Error!Self {
        if (heights.len == 0 or heights.len > max_fold_heights) return error.InvalidFoldHeightRoster;
        for (heights[1..], 1..) |height, i| {
            if (heights[i - 1] <= height) return error.InvalidFoldHeightRoster;
        }
        var self = Self{
            .channel = framed.FramedBcsChannelV2.init(statement),
            .stage = .fixed_root,
            .fold_heights = undefined,
            .fold_count = heights.len,
            .fold_index = 0,
        };
        @memcpy(self.fold_heights[0..heights.len], heights);
        return self;
    }

    pub fn currentFoldHeight(self: Self) Error!u32 {
        if (self.fold_index >= self.fold_count) return error.UnexpectedStage;
        return self.fold_heights[self.fold_index];
    }

    fn require(self: Self, expected: Stage) Error!void {
        if (self.stage != expected) return error.UnexpectedStage;
    }

    fn root(self: *Self, expected: Stage, next: Stage, value: framed.Digest32) Error!void {
        try self.require(expected);
        try self.channel.mixRoot(value);
        self.stage = next;
    }

    fn field(self: *Self, expected: Stage, next: Stage, limbs: []const u32) Error!void {
        try self.require(expected);
        try self.channel.mixField(limbs);
        self.stage = next;
    }

    fn challenge(self: *Self, expected: Stage, next: Stage) Error![8]u32 {
        try self.require(expected);
        try self.channel.beginChallengeDraw();
        const limbs = try self.channel.drawChallengeQM31Limbs();
        try self.channel.endChallengeDraw();
        self.stage = next;
        return limbs;
    }

    fn scalarChallenge(self: *Self, expected: Stage, next: Stage) Error![4]u32 {
        const pair = try self.challenge(expected, next);
        return pair[0..4].*;
    }

    pub fn mixFixedRoot(self: *Self, value: framed.Digest32) Error!void {
        return self.root(.fixed_root, .circuit_identity, value);
    }

    pub fn mixCircuitIdentity(self: *Self, value: framed.Digest32) Error!void {
        return self.root(.circuit_identity, .public_values, value);
    }

    pub fn mixPublicValues(self: *Self, limbs: []const u32) Error!void {
        return self.field(.public_values, .main_root, limbs);
    }

    pub fn mixMainRoot(self: *Self, value: framed.Digest32) Error!void {
        return self.root(.main_root, .interaction_pow, value);
    }

    pub fn beginInteractionPow(self: *Self, difficulty: u32) Error!framed.PowBarrier {
        try self.require(.interaction_pow);
        const barrier = try self.channel.beginPow(difficulty);
        self.stage = .interaction_nonce;
        return barrier;
    }

    pub fn acceptInteractionNonce(self: *Self, nonce: u64) Error!void {
        try self.require(.interaction_nonce);
        try self.channel.acceptPowNonce(nonce);
        self.stage = .lookup_pair;
    }

    pub fn drawLookupPair(self: *Self) Error![8]u32 {
        return self.challenge(.lookup_pair, .interaction_claim);
    }

    pub fn mixInteractionClaim(self: *Self, limbs: []const u32) Error!void {
        return self.field(.interaction_claim, .interaction_root, limbs);
    }

    pub fn mixInteractionRoot(self: *Self, value: framed.Digest32) Error!void {
        return self.root(.interaction_root, .composition_gamma, value);
    }

    pub fn drawCompositionGamma(self: *Self) Error![4]u32 {
        return self.scalarChallenge(.composition_gamma, .composition_root);
    }

    pub fn mixCompositionRoot(self: *Self, value: framed.Digest32) Error!void {
        return self.root(.composition_root, .oods_seed, value);
    }

    pub fn drawOodsSeed(self: *Self) Error![4]u32 {
        return self.scalarChallenge(.oods_seed, .sampled_values);
    }

    pub fn mixSampledValues(self: *Self, limbs: []const u32) Error!void {
        return self.field(.sampled_values, .batch_lambda, limbs);
    }

    pub fn drawBatchLambda(self: *Self) Error![4]u32 {
        return self.scalarChallenge(.batch_lambda, .fold_alpha);
    }

    pub fn drawFoldAlpha(self: *Self) Error![4]u32 {
        try self.require(.fold_alpha);
        const terminal = self.fold_index + 1 == self.fold_count;
        return self.scalarChallenge(.fold_alpha, if (terminal) .original_terminal_coefficients else .original_line_root);
    }

    pub fn mixOriginalLineRoot(self: *Self, value: framed.Digest32) Error!void {
        return self.root(.original_line_root, .own_quotient_line_root, value);
    }

    pub fn mixOwnQuotientLineRoot(self: *Self, value: framed.Digest32) Error!void {
        try self.require(.own_quotient_line_root);
        try self.channel.mixRoot(value);
        self.fold_index += 1;
        self.stage = .fold_alpha;
    }

    pub fn mixOriginalTerminalCoefficients(self: *Self, limbs: []const u32) Error!void {
        return self.field(.original_terminal_coefficients, .own_quotient_terminal_coefficients, limbs);
    }

    pub fn mixOwnQuotientTerminalCoefficients(self: *Self, limbs: []const u32) Error!void {
        try self.field(.own_quotient_terminal_coefficients, .fri_pow, limbs);
        self.fold_index = self.fold_count;
    }

    pub fn beginFriPow(self: *Self, difficulty: u32) Error!framed.PowBarrier {
        try self.require(.fri_pow);
        const barrier = try self.channel.beginPow(difficulty);
        self.stage = .fri_nonce;
        return barrier;
    }

    pub fn acceptFriNonce(self: *Self, nonce: u64) Error!void {
        try self.require(.fri_nonce);
        try self.channel.acceptPowNonce(nonce);
        self.stage = .queries;
    }

    pub fn beginQueries(self: *Self) Error!uniform_queries.FramedQueryWordChannelV1 {
        try self.require(.queries);
        const query_channel = try self.channel.beginQueries();
        self.stage = .complete;
        return query_channel;
    }
};

fn zeroStatement() framed.StatementBinding {
    const zero = [_]u8{0} ** 32;
    return .{
        .key_digest = zero,
        .circuit_digest = zero,
        .fri_config_digest = zero,
        .source_tree_descriptors = [_]framed.Digest32{zero} ** 4,
        .line_profile_digest = zero,
    };
}

fn patternRoot(event: u8) framed.Digest32 {
    return [_]u8{event} ** 32;
}

test "typed paired Gate plan rejects invalid roster and out-of-order events" {
    const statement = zeroStatement();
    try std.testing.expectError(error.InvalidFoldHeightRoster, PairedGateEventPlanV2.init(statement, &.{}));
    try std.testing.expectError(error.InvalidFoldHeightRoster, PairedGateEventPlanV2.init(statement, &.{ 17, 17 }));
    try std.testing.expectError(error.InvalidFoldHeightRoster, PairedGateEventPlanV2.init(statement, &.{ 16, 17 }));
    const too_many = [_]u32{1} ** (max_fold_heights + 1);
    try std.testing.expectError(error.InvalidFoldHeightRoster, PairedGateEventPlanV2.init(statement, &too_many));

    var plan = try PairedGateEventPlanV2.init(statement, &.{ 17, 16 });
    const first_digest = plan.channel.digest;
    const first_event = plan.channel.next_event;
    try std.testing.expectError(error.UnexpectedStage, plan.mixMainRoot(patternRoot(4)));
    try std.testing.expectError(error.UnexpectedStage, plan.beginInteractionPow(0));
    try std.testing.expectEqualSlices(u8, &first_digest, &plan.channel.digest);
    try std.testing.expectEqual(first_event, plan.channel.next_event);
    try std.testing.expectEqual(@as(u32, 17), try plan.currentFoldHeight());
}

test "typed paired Gate plan matches Python full event schedule" {
    var plan = try PairedGateEventPlanV2.init(zeroStatement(), &.{ 17, 16 });
    try plan.mixFixedRoot(patternRoot(1));
    try plan.mixCircuitIdentity(patternRoot(2));
    try plan.mixPublicValues(&.{ 0, 1, 2, 3 });
    try plan.mixMainRoot(patternRoot(4));
    const interaction_pow = try plan.beginInteractionPow(0);
    try std.testing.expectEqual(@as(u64, 5), interaction_pow.prefix_event);
    try std.testing.expectEqual(@as(u64, 6), interaction_pow.trial_event);
    try plan.acceptInteractionNonce(0);
    try std.testing.expectEqual(@as(u32, 1822750541), (try plan.drawLookupPair())[0]);
    try plan.mixInteractionClaim(&.{ 0, 1, 2, 3 });
    try plan.mixInteractionRoot(patternRoot(10));
    try std.testing.expectEqual(@as(u32, 640893609), (try plan.drawCompositionGamma())[0]);
    try plan.mixCompositionRoot(patternRoot(12));
    try std.testing.expectEqual(@as(u32, 1454020928), (try plan.drawOodsSeed())[0]);
    try plan.mixSampledValues(&.{ 0, 1, 2, 3 });
    try std.testing.expectEqual(@as(u32, 590385924), (try plan.drawBatchLambda())[0]);
    try std.testing.expectEqual(@as(u32, 17), try plan.currentFoldHeight());
    try std.testing.expectEqual(@as(u32, 1174171810), (try plan.drawFoldAlpha())[0]);
    try std.testing.expectError(error.UnexpectedStage, plan.drawFoldAlpha());
    try plan.mixOriginalLineRoot(patternRoot(17));
    try plan.mixOwnQuotientLineRoot(patternRoot(18));
    try std.testing.expectEqual(@as(u32, 16), try plan.currentFoldHeight());
    try std.testing.expectEqual(@as(u32, 452219042), (try plan.drawFoldAlpha())[0]);
    try plan.mixOriginalTerminalCoefficients(&.{ 0, 1, 2, 3 });
    try plan.mixOwnQuotientTerminalCoefficients(&.{ 0, 1, 2, 3 });
    const fri_pow = try plan.beginFriPow(0);
    try std.testing.expectEqual(@as(u64, 22), fri_pow.prefix_event);
    try std.testing.expectEqual(@as(u64, 23), fri_pow.trial_event);
    try plan.acceptFriNonce(0);
    var expected_bytes: [32]u8 = undefined;
    const expected = try std.fmt.hexToBytes(&expected_bytes, "84bbf452bd2097fe94c0310fe2030f5ff985fb52fa1d9dc8cbeedc2af9ed464f");
    try std.testing.expectEqualSlices(u8, expected, &plan.channel.digest);
    var query_channel = try plan.beginQueries();
    try std.testing.expectEqual(@as(u64, 25), query_channel.event);
    try std.testing.expectEqual(@as(u32, 1533884970), (try query_channel.drawRawU32sChecked())[0]);
    try std.testing.expectError(error.UnexpectedStage, plan.beginQueries());
}
