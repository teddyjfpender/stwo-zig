//! Fail-closed Fiat-Shamir order for exact State Machine v2.

const std = @import("std");
const shared = @import("../common/transcript_schedule.zig");
const geometry_mod = @import("geometry.zig");

pub const Operation = shared.Operation;
pub const Boundary = shared.Boundary;

pub const Schedule = struct {
    seed_chain: u64,
    fri_tree_count: u32,
    operation_count: u32,

    pub fn init(geometry: geometry_mod.Geometry) !Schedule {
        var seed = shared.SeedBuilder.init(0x5354_4154_4556_3200);
        try seed.mix(geometry.statement.log_n_rows);
        try seed.mix(geometry.statement.initial_state[0].toU32());
        try seed.mix(geometry.statement.initial_state[1].toU32());
        try seed.mix(geometry.protocol.pow_bits);
        try seed.mix(geometry.protocol.fri_config.log_blowup_factor);
        try seed.mix(
            geometry.protocol.fri_config.log_last_layer_degree_bound,
        );
        try seed.mix(geometry.protocol.fri_config.n_queries);
        try seed.mix(geometry.protocol.fri_config.fold_step);
        try seed.mix(
            if (geometry.protocol.lifting_log_size) |value|
                @as(u64, value) + 1
            else
                0,
        );
        try seed.mix(geometry.fri_tree_count);
        const fri_count = std.math.cast(
            u32,
            geometry.fri_tree_count,
        ) orelse return error.GeometryOverflow;
        const operation_count = std.math.add(
            u32,
            15,
            std.math.mul(u32, fri_count, 2) catch
                return error.GeometryOverflow,
        ) catch return error.GeometryOverflow;
        return .{
            .seed_chain = seed.finish(),
            .fri_tree_count = fri_count,
            .operation_count = operation_count,
        };
    }

    pub fn initialChain(self: Schedule) u64 {
        return chainAt(self.seed_chain, 0);
    }

    pub fn operation(self: Schedule, step: u32) !Operation {
        if (step >= self.operation_count)
            return error.GeometryOverflow;
        return switch (step) {
            0 => .mix_pcs_config,
            1 => .mix_preprocessed_root,
            2 => .mix_statement,
            3 => .mix_main_root,
            4 => .draw_lookup_elements,
            5 => .mix_statement,
            6 => .mix_interaction_root,
            7 => .draw_composition_alpha,
            8 => .mix_composition_root,
            9 => .draw_oods_point,
            10 => .mix_sampled_values,
            11 => .draw_quotient_alpha,
            else => self.operationAfterQuotient(step),
        };
    }

    pub fn boundary(self: Schedule, step: u32) !Boundary {
        _ = try self.operation(step);
        return .{
            .expected_step = step,
            .expected_chain = chainAt(self.seed_chain, step),
            .next_chain = chainAt(self.seed_chain, step + 1),
        };
    }

    pub fn friTreeCount(self: Schedule) u32 {
        return self.fri_tree_count;
    }

    pub fn operationCount(self: Schedule) u32 {
        return self.operation_count;
    }

    fn operationAfterQuotient(
        self: Schedule,
        step: u32,
    ) Operation {
        const fri_offset = step - 12;
        const fri_operations = self.fri_tree_count * 2;
        if (fri_offset < fri_operations) {
            const tree_index = fri_offset / 2;
            return if (fri_offset % 2 == 0)
                .{ .mix_fri_root = tree_index }
            else
                .{ .draw_fri_alpha = tree_index };
        }
        return switch (fri_offset - fri_operations) {
            0 => .mix_last_layer,
            1 => .absorb_pow,
            2 => .draw_queries,
            else => unreachable,
        };
    }
};

fn chainAt(seed: u64, step: u32) u64 {
    return avalanche(
        seed ^ (@as(u64, step) *% 0x9e37_79b9_7f4a_7c15),
    );
}

fn avalanche(input: u64) u64 {
    var value = input;
    value ^= value >> 30;
    value *%= 0xbf58_476d_1ce4_e5b9;
    value ^= value >> 27;
    value *%= 0x94d0_49bb_1331_11eb;
    value ^= value >> 31;
    return value;
}

test "State v2 schedule binds both statements around lookup draw" {
    const pcs = @import("stwo_core").pcs;
    const M31 = @import("stwo_core").fields.m31.M31;
    const schedule = try Schedule.init(try geometry_mod.admit(
        .{
            .log_n_rows = 8,
            .initial_state = .{
                M31.fromU64(9),
                M31.fromU64(3),
            },
        },
        pcs.PcsConfig.default(),
    ));
    try std.testing.expectEqual(@as(u32, 31), schedule.operationCount());
    try std.testing.expectEqual(
        Operation.mix_statement,
        try schedule.operation(2),
    );
    try std.testing.expectEqual(
        Operation.draw_lookup_elements,
        try schedule.operation(4),
    );
    try std.testing.expectEqual(
        Operation.mix_statement,
        try schedule.operation(5),
    );
    try std.testing.expectEqual(
        Operation.mix_interaction_root,
        try schedule.operation(6),
    );
    try std.testing.expectEqual(
        Operation{ .mix_fri_root = 0 },
        try schedule.operation(12),
    );
}
