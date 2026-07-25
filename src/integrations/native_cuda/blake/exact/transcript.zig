//! Pinned transcript and public-claim order for exact CUDA Blake.

const std = @import("std");
const geometry = @import("geometry.zig");

pub const Relation = enum(u8) {
    blake,
    round,
    xor_12,
    xor_9,
    xor_8,
    xor_7,
    xor_4,
};

pub const relation_draw_order = [_]Relation{
    .blake,
    .round,
    .xor_12,
    .xor_9,
    .xor_8,
    .xor_7,
    .xor_4,
};

pub const Claim = enum(u8) {
    scheduler,
    xor_12,
    xor_9,
    xor_8,
    xor_7,
    xor_4,
    round_split_3,
    round_split_1,
};

/// This differs deliberately from component execution order. It is the exact
/// `Statement1::mix_into` order in the pinned Rust oracle.
pub const statement1_mix_order = [_]Claim{
    .scheduler,
    .xor_12,
    .xor_9,
    .xor_8,
    .xor_7,
    .xor_4,
    .round_split_3,
    .round_split_1,
};

pub const Operation = union(enum) {
    mix_preprocessed_root,
    mix_statement0,
    mix_main_root,
    draw_relation_elements,
    mix_statement1_claims,
    mix_interaction_root,
    draw_composition_coefficient,
    mix_composition_root,
    draw_oods_point,
    mix_sampled_values,
    draw_quotient_coefficient,
    mix_fri_root: u32,
    draw_fri_alpha: u32,
    mix_last_layer,
    grind_and_mix_pow,
    draw_queries,
};

pub const fixed_prefix = [_]Operation{
    .mix_preprocessed_root,
    .mix_statement0,
    .mix_main_root,
    .draw_relation_elements,
    .mix_statement1_claims,
    .mix_interaction_root,
    .draw_composition_coefficient,
    .mix_composition_root,
    .draw_oods_point,
    .mix_sampled_values,
    .draw_quotient_coefficient,
};

pub const Schedule = struct {
    fri_tree_count: u32,

    pub fn init(value: geometry.Geometry) Schedule {
        return .{ .fri_tree_count = value.fri_tree_count };
    }

    pub fn operationCount(self: Schedule) u32 {
        return @intCast(
            fixed_prefix.len +
                2 * self.fri_tree_count +
                3,
        );
    }

    pub fn operation(self: Schedule, index: u32) !Operation {
        const i: usize = index;
        if (i < fixed_prefix.len) return fixed_prefix[i];
        const after_prefix = i - fixed_prefix.len;
        const fri_operations = 2 * @as(usize, self.fri_tree_count);
        if (after_prefix < fri_operations) {
            const tree_index: u32 = @intCast(after_prefix / 2);
            return if (after_prefix % 2 == 0)
                .{ .mix_fri_root = tree_index }
            else
                .{ .draw_fri_alpha = tree_index };
        }
        return switch (after_prefix - fri_operations) {
            0 => .mix_last_layer,
            1 => .grind_and_mix_pow,
            2 => .draw_queries,
            else => error.InvalidTranscriptStep,
        };
    }
};

test "exact transcript preserves Rust relation and claimed-sum order" {
    try std.testing.expectEqual(@as(usize, 7), relation_draw_order.len);
    try std.testing.expectEqual(@as(usize, 8), statement1_mix_order.len);
    try std.testing.expectEqual(Relation.blake, relation_draw_order[0]);
    try std.testing.expectEqual(Relation.round, relation_draw_order[1]);
    try std.testing.expectEqual(Claim.scheduler, statement1_mix_order[0]);
    try std.testing.expectEqual(Claim.xor_12, statement1_mix_order[1]);
    try std.testing.expectEqual(Claim.round_split_3, statement1_mix_order[6]);
}

test "exact transcript places FRI between quotient and proof of work" {
    const admitted = try geometry.admit(.{
        .statement = .{ .log_n_rows = 4 },
        .protocol = @import("stwo_core").pcs.PcsConfig.default(),
    });
    const schedule = Schedule.init(admitted);
    try std.testing.expectEqual(@as(u32, 46), schedule.operationCount());
    try std.testing.expectEqual(
        Operation.draw_quotient_coefficient,
        try schedule.operation(10),
    );
    try std.testing.expectEqual(
        Operation{ .mix_fri_root = 0 },
        try schedule.operation(11),
    );
    try std.testing.expectEqual(
        Operation{ .draw_fri_alpha = 0 },
        try schedule.operation(12),
    );
    try std.testing.expectEqual(
        Operation{ .mix_fri_root = 15 },
        try schedule.operation(41),
    );
    try std.testing.expectEqual(
        Operation{ .draw_fri_alpha = 15 },
        try schedule.operation(42),
    );
    try std.testing.expectEqual(
        Operation.mix_last_layer,
        try schedule.operation(43),
    );
    try std.testing.expectEqual(
        Operation.grind_and_mix_pow,
        try schedule.operation(44),
    );
    try std.testing.expectEqual(
        Operation.draw_queries,
        try schedule.operation(45),
    );
    try std.testing.expectError(
        error.InvalidTranscriptStep,
        schedule.operation(46),
    );
}
