//! Verifier-owned fixed proof geometry for the recursion V1 profile.
//!
//! Ordinary STWO proofs use owned slices. A recursive verifier cannot trust
//! their lengths to select its schedule: dynamic proofs must first be adapted
//! into a fixed wire whose geometry is derived here from a trusted manifest.

const std = @import("std");
const protocol = @import("protocol.zig");
const channel = @import("poseidon2_channel.zig");

pub const TREE_COUNT: usize = protocol.COMMITMENT_TREE_COUNT;
pub const MAX_FRI_ROUNDS: usize = 16;
pub const MAX_DOMAIN_LOG: u32 = 30;
pub const PACKED_LEAF_LOG: u32 = 2;
pub const PROFILE_SHAPE_ID_DOMAIN: u32 = 0x5053_4850; // "PSHP"
const SHAPE_ID_WORD_CAPACITY: usize = 160;

pub const Error = error{
    ArithmeticOverflow,
    EmptyShape,
    InvalidDomainLog,
    InvalidFoldStep,
    InvalidFriSchedule,
    InvalidLastLayer,
    InvalidTableLayout,
    InvalidTreeHeight,
    InvalidWireSize,
    ShapeMismatch,
};

pub const FriRound = struct {
    evaluation_log: u32,
    fold_step: u32,
    fold_width: u32,
    packed_leaf_log: u32,
    merkle_tree_height: u32,
    authenticated_subtree_height: u32,
    authentication_path_depth: u32,
};

pub const FriSchedule = struct {
    count: u32,
    rounds: [MAX_FRI_ROUNDS]FriRound,
    terminal_evaluation_log: u32,
    last_layer_coefficient_count: u32,

    pub fn init(
        column_log_degree: u32,
        config: @TypeOf(protocol.PCS_CONFIG.fri_config),
    ) Error!FriSchedule {
        if (column_log_degree > MAX_DOMAIN_LOG or
            config.log_blowup_factor > MAX_DOMAIN_LOG or
            config.log_last_layer_degree_bound > column_log_degree)
        {
            return error.InvalidDomainLog;
        }
        if (config.fold_step == 0 or config.fold_step > 4)
            return error.InvalidFoldStep;
        if (column_log_degree == config.log_last_layer_degree_bound)
            return error.InvalidLastLayer;

        const terminal_evaluation_log = std.math.add(
            u32,
            config.log_last_layer_degree_bound,
            config.log_blowup_factor,
        ) catch return error.ArithmeticOverflow;
        if (terminal_evaluation_log > MAX_DOMAIN_LOG)
            return error.InvalidDomainLog;

        var result = FriSchedule{
            .count = 0,
            .rounds = [_]FriRound{std.mem.zeroes(FriRound)} ** MAX_FRI_ROUNDS,
            .terminal_evaluation_log = terminal_evaluation_log,
            .last_layer_coefficient_count = @as(u32, 1) <<
                @intCast(config.log_last_layer_degree_bound),
        };

        var degree_log = column_log_degree;
        while (degree_log > config.log_last_layer_degree_bound) {
            if (result.count == result.rounds.len)
                return error.InvalidFriSchedule;
            const remaining = degree_log - config.log_last_layer_degree_bound;
            const this_fold_step = @min(config.fold_step, remaining);
            const evaluation_log = std.math.add(
                u32,
                degree_log,
                config.log_blowup_factor,
            ) catch return error.ArithmeticOverflow;
            if (evaluation_log > MAX_DOMAIN_LOG)
                return error.InvalidDomainLog;
            const fold_width = @as(u32, 1) << @intCast(this_fold_step);
            const packed_leaf_log: u32 = if (this_fold_step > 1)
                PACKED_LEAF_LOG
            else
                0;
            if (packed_leaf_log > evaluation_log or
                packed_leaf_log > this_fold_step)
            {
                return error.InvalidFriSchedule;
            }
            const merkle_tree_height = evaluation_log - packed_leaf_log;
            const authenticated_subtree_height = this_fold_step - packed_leaf_log;
            const authentication_path_depth = merkle_tree_height -
                authenticated_subtree_height;

            result.rounds[result.count] = .{
                .evaluation_log = evaluation_log,
                .fold_step = this_fold_step,
                .fold_width = fold_width,
                .packed_leaf_log = packed_leaf_log,
                .merkle_tree_height = merkle_tree_height,
                .authenticated_subtree_height = authenticated_subtree_height,
                .authentication_path_depth = authentication_path_depth,
            };
            result.count += 1;
            degree_log -= this_fold_step;
        }
        if (degree_log + config.log_blowup_factor != terminal_evaluation_log)
            return error.InvalidFriSchedule;
        return result;
    }

    pub fn active(self: *const FriSchedule) []const FriRound {
        return self.rounds[0..self.count];
    }

    pub fn eql(left: FriSchedule, right: FriSchedule) bool {
        if (left.count != right.count or
            left.terminal_evaluation_log != right.terminal_evaluation_log or
            left.last_layer_coefficient_count != right.last_layer_coefficient_count)
        {
            return false;
        }
        for (left.active(), right.active()) |left_round, right_round| {
            if (!std.meta.eql(left_round, right_round)) return false;
        }
        return true;
    }
};

/// Authentication siblings above one complete FRI fold subset. Packed leaves
/// locally absorb four evaluations; the remaining subset subtree is also
/// reconstructed before consuming siblings from the proof.
pub fn friQueryPathDepth(tree_height: u32, fold_width: u32) Error!u32 {
    if (fold_width < 2 or !std.math.isPowerOfTwo(fold_width))
        return error.InvalidFoldStep;
    const fold_step = std.math.log2_int(u32, fold_width);
    if (fold_step > 4) return error.InvalidFoldStep;
    const packed_leaf_log: u32 = if (fold_step > 1) PACKED_LEAF_LOG else 0;
    if (fold_step < packed_leaf_log) return error.InvalidFoldStep;
    const authenticated_subtree_height = fold_step - packed_leaf_log;
    return std.math.sub(
        u32,
        tree_height,
        authenticated_subtree_height,
    ) catch error.InvalidTreeHeight;
}

/// Aggregate fixed-wire facts. Ordered table log sizes and preprocessing
/// identifiers are represented by semantic digests here; the eventual wire
/// generator owns their fixed arrays and must reproduce these counts.
pub const ProofShapeV1 = struct {
    air_program_id: channel.Digest,
    preprocessing_id: channel.Digest,
    table_layout_id: channel.Digest,
    table_count: u32,
    claimed_sum_count: u32,
    sampled_value_count: u32,
    preprocessed_column_count: u32,
    tree_column_counts: [TREE_COUNT]u32,
    tree_heights: [TREE_COUNT]u32,
    column_log_degree: u32,
    proof_wire_bytes: u64,
    fri: FriSchedule,

    pub fn validate(self: ProofShapeV1) Error!void {
        try validateDigest(self.air_program_id);
        try validateDigest(self.preprocessing_id);
        try validateDigest(self.table_layout_id);
        if (self.table_count == 0 or
            self.claimed_sum_count == 0 or
            self.sampled_value_count == 0 or
            self.preprocessed_column_count == 0)
        {
            return error.EmptyShape;
        }
        for (self.tree_column_counts) |count| {
            if (count == 0) return error.EmptyShape;
        }
        var described_table_count: u32 = 0;
        for (self.tree_column_counts) |count| {
            described_table_count = std.math.add(
                u32,
                described_table_count,
                count,
            ) catch return error.ArithmeticOverflow;
        }
        if (described_table_count != self.table_count or
            self.tree_column_counts[0] != self.preprocessed_column_count)
        {
            return error.InvalidTableLayout;
        }
        for (self.tree_heights) |height| {
            if (height == 0 or height > MAX_DOMAIN_LOG)
                return error.InvalidTreeHeight;
        }
        if (self.proof_wire_bytes == 0) return error.InvalidWireSize;

        const expected = try FriSchedule.init(
            self.column_log_degree,
            protocol.PCS_CONFIG.fri_config,
        );
        if (!self.fri.eql(expected)) return error.ShapeMismatch;
        const expected_fri_height = std.math.add(
            u32,
            self.column_log_degree,
            protocol.PCS_CONFIG.fri_config.log_blowup_factor,
        ) catch return error.ArithmeticOverflow;
        if (self.tree_heights[TREE_COUNT - 1] != expected_fri_height)
            return error.InvalidTreeHeight;
    }

    pub fn rawQueryCount(self: ProofShapeV1) u64 {
        _ = self;
        return protocol.FRI_QUERY_COUNT;
    }

    pub fn queriedValueCount(self: ProofShapeV1) Error!u64 {
        return std.math.mul(
            u64,
            self.table_count,
            self.rawQueryCount(),
        ) catch error.ArithmeticOverflow;
    }

    pub fn tracePathCount(self: ProofShapeV1) Error!u64 {
        _ = self;
        return std.math.mul(
            u64,
            TREE_COUNT,
            protocol.FRI_QUERY_COUNT,
        ) catch error.ArithmeticOverflow;
    }

    pub fn id(self: ProofShapeV1) Error!channel.Digest {
        try self.validate();
        var words: [SHAPE_ID_WORD_CAPACITY]u32 = undefined;
        var at: usize = 0;
        appendDigest(&words, &at, self.air_program_id);
        appendDigest(&words, &at, self.preprocessing_id);
        appendDigest(&words, &at, self.table_layout_id);
        append(&words, &at, self.table_count);
        append(&words, &at, self.claimed_sum_count);
        append(&words, &at, self.sampled_value_count);
        append(&words, &at, self.preprocessed_column_count);
        for (self.tree_column_counts) |count| append(&words, &at, count);
        for (self.tree_heights) |height| append(&words, &at, height);
        append(&words, &at, self.column_log_degree);
        appendU64(&words, &at, self.proof_wire_bytes);
        append(&words, &at, self.fri.count);
        append(&words, &at, self.fri.terminal_evaluation_log);
        append(&words, &at, self.fri.last_layer_coefficient_count);
        for (self.fri.active()) |round| {
            append(&words, &at, round.evaluation_log);
            append(&words, &at, round.fold_step);
            append(&words, &at, round.fold_width);
            append(&words, &at, round.packed_leaf_log);
            append(&words, &at, round.merkle_tree_height);
            append(&words, &at, round.authenticated_subtree_height);
            append(&words, &at, round.authentication_path_depth);
        }
        return channel.hashCanonicalU32s(words[0..at], PROFILE_SHAPE_ID_DOMAIN);
    }
};

fn validateDigest(digest: channel.Digest) Error!void {
    var aggregate: u32 = 0;
    for (digest) |word| {
        if (word >= 0x7fff_ffff) return error.ShapeMismatch;
        aggregate |= word;
    }
    if (aggregate == 0) return error.EmptyShape;
}

fn append(words: *[SHAPE_ID_WORD_CAPACITY]u32, at: *usize, value: u32) void {
    std.debug.assert(at.* < words.len);
    std.debug.assert(value < 0x7fff_ffff);
    words[at.*] = value;
    at.* += 1;
}

fn appendDigest(words: *[SHAPE_ID_WORD_CAPACITY]u32, at: *usize, digest: channel.Digest) void {
    for (digest) |word| append(words, at, word);
}

fn appendU64(words: *[SHAPE_ID_WORD_CAPACITY]u32, at: *usize, value: u64) void {
    append(words, at, @truncate(value & 0xffff));
    append(words, at, @truncate((value >> 16) & 0xffff));
    append(words, at, @truncate((value >> 32) & 0xffff));
    append(words, at, @truncate(value >> 48));
}

fn testDigest(label: []const u8) channel.Digest {
    return channel.hashBytes(label, 0x5450); // "TP"
}

fn testShape() ProofShapeV1 {
    const fri = FriSchedule.init(24, protocol.PCS_CONFIG.fri_config) catch unreachable;
    return .{
        .air_program_id = testDigest("air-program"),
        .preprocessing_id = testDigest("preprocessing"),
        .table_layout_id = testDigest("ordered-table-layout"),
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

test "recursion fixed profile: fold-four schedule is exact" {
    const schedule = try FriSchedule.init(24, protocol.PCS_CONFIG.fri_config);
    try std.testing.expectEqual(@as(u32, 6), schedule.count);
    try std.testing.expectEqual(@as(u32, 1), schedule.terminal_evaluation_log);
    try std.testing.expectEqual(@as(u32, 1), schedule.last_layer_coefficient_count);
    for (schedule.active(), 0..) |round, index| {
        try std.testing.expectEqual(@as(u32, 4), round.fold_step);
        try std.testing.expectEqual(@as(u32, 16), round.fold_width);
        try std.testing.expectEqual(@as(u32, 2), round.packed_leaf_log);
        try std.testing.expectEqual(round.evaluation_log - 4, round.authentication_path_depth);
        const expected_log: u32 = 25 - @as(u32, @intCast(index * 4));
        try std.testing.expectEqual(expected_log, round.evaluation_log);
    }
}

test "recursion fixed profile: partial final fold and paths are derived" {
    const schedule = try FriSchedule.init(22, protocol.PCS_CONFIG.fri_config);
    try std.testing.expectEqual(@as(u32, 6), schedule.count);
    const last = schedule.active()[schedule.count - 1];
    try std.testing.expectEqual(@as(u32, 3), last.evaluation_log);
    try std.testing.expectEqual(@as(u32, 2), last.fold_step);
    try std.testing.expectEqual(@as(u32, 4), last.fold_width);
    try std.testing.expectEqual(@as(u32, 2), last.packed_leaf_log);
    try std.testing.expectEqual(@as(u32, 1), last.merkle_tree_height);
    try std.testing.expectEqual(@as(u32, 0), last.authenticated_subtree_height);
    try std.testing.expectEqual(@as(u32, 1), last.authentication_path_depth);

    try std.testing.expectEqual(@as(u32, 21), try friQueryPathDepth(23, 16));
    try std.testing.expectEqual(@as(u32, 4), try friQueryPathDepth(5, 2));
}

test "recursion fixed profile: proof-selected geometry rejects" {
    var shape = testShape();
    try shape.validate();
    const canonical_id = try shape.id();
    try std.testing.expectEqual(@as(u64, 386_000), try shape.queriedValueCount());
    try std.testing.expectEqual(@as(u64, 772), try shape.tracePathCount());

    shape.fri.rounds[0].fold_width = 8;
    try std.testing.expectError(error.ShapeMismatch, shape.validate());
    shape = testShape();
    shape.tree_heights[3] -= 1;
    try std.testing.expectError(error.InvalidTreeHeight, shape.validate());
    shape = testShape();
    shape.proof_wire_bytes += 1;
    try std.testing.expect(!std.meta.eql(canonical_id, try shape.id()));
}

test "recursion fixed profile: invalid schedules fail closed" {
    var config = protocol.PCS_CONFIG.fri_config;
    config.fold_step = 0;
    try std.testing.expectError(error.InvalidFoldStep, FriSchedule.init(24, config));
    config = protocol.PCS_CONFIG.fri_config;
    config.log_last_layer_degree_bound = 24;
    try std.testing.expectError(error.InvalidLastLayer, FriSchedule.init(24, config));
    try std.testing.expectError(error.InvalidFoldStep, friQueryPathDepth(10, 3));
    try std.testing.expectError(error.InvalidTreeHeight, friQueryPathDepth(0, 2));
}
