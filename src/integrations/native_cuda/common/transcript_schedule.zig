//! Workload-independent Fiat-Shamir operation topology.

const std = @import("std");

pub const Error = error{
    GeometryOverflow,
    UnsupportedProtocol,
};

pub const Operation = union(enum) {
    mix_pcs_config,
    mix_preprocessed_root,
    mix_main_root,
    mix_statement,
    draw_composition_alpha,
    mix_composition_root,
    draw_oods_point,
    mix_sampled_values,
    draw_quotient_alpha,
    mix_fri_root: u32,
    draw_fri_alpha: u32,
    mix_last_layer,
    absorb_pow,
    draw_queries,
};

pub const Boundary = struct {
    expected_step: u32,
    expected_chain: u64,
    next_chain: u64,
};

/// Builds the non-cryptographic ordering sentinel without learning statement
/// fields. Callers mix their admitted structural values in canonical order.
pub const SeedBuilder = struct {
    state: u64,

    pub fn init(domain: u64) SeedBuilder {
        return .{ .state = domain };
    }

    pub fn mix(self: *SeedBuilder, value: anytype) Error!void {
        const word = std.math.cast(u64, value) orelse
            return error.GeometryOverflow;
        self.state = (self.state ^ word) *% 0x100_0000_01b3;
    }

    pub fn finish(self: SeedBuilder) u64 {
        return avalanche(self.state);
    }
};

pub const Schedule = struct {
    seed_chain: u64,
    fri_tree_count: u32,
    operation_count: u32,

    pub fn init(seed_chain: u64, fri_tree_count: usize) Error!Schedule {
        const fri_count = std.math.cast(u32, fri_tree_count) orelse
            return error.GeometryOverflow;
        if (fri_count == 0) return error.UnsupportedProtocol;
        const operation_count = std.math.add(
            u32,
            12,
            std.math.mul(u32, fri_count, 2) catch
                return error.GeometryOverflow,
        ) catch return error.GeometryOverflow;
        return .{
            .seed_chain = seed_chain,
            .fri_tree_count = fri_count,
            .operation_count = operation_count,
        };
    }

    pub fn initialChain(self: Schedule) u64 {
        return chainAt(self.seed_chain, 0);
    }

    pub fn operation(self: Schedule, step: u32) Error!Operation {
        if (step >= self.operation_count) return error.GeometryOverflow;
        return switch (step) {
            0 => .mix_pcs_config,
            1 => .mix_preprocessed_root,
            2 => .mix_main_root,
            3 => .mix_statement,
            4 => .draw_composition_alpha,
            5 => .mix_composition_root,
            6 => .draw_oods_point,
            7 => .mix_sampled_values,
            8 => .draw_quotient_alpha,
            else => self.operationAfterQuotient(step),
        };
    }

    pub fn boundary(self: Schedule, step: u32) Error!Boundary {
        _ = try self.operation(step);
        return .{
            .expected_step = step,
            .expected_chain = chainAt(self.seed_chain, step),
            .next_chain = chainAt(self.seed_chain, step + 1),
        };
    }

    fn operationAfterQuotient(
        self: Schedule,
        step: u32,
    ) Operation {
        const fri_offset = step - 9;
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
    return avalanche(seed ^ (@as(u64, step) *% 0x9e37_79b9_7f4a_7c15));
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

test "operation order is independent from statement semantics" {
    const schedule = try Schedule.init(0x1234, 5);
    try std.testing.expectEqual(@as(u32, 22), schedule.operation_count);
    try std.testing.expectEqual(
        Operation.mix_preprocessed_root,
        try schedule.operation(1),
    );
    try std.testing.expectEqual(
        Operation{ .mix_fri_root = 0 },
        try schedule.operation(9),
    );
    try std.testing.expectEqual(
        Operation.draw_queries,
        try schedule.operation(21),
    );
}
