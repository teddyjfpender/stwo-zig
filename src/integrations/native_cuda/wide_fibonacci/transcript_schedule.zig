//! Exact Fiat-Shamir operation topology for one admitted proof.
//!
//! Chain values are ordering sentinels, not transcript inputs. The CUDA
//! transcript kernels still derive every challenge solely from canonical
//! Blake2s state.

const std = @import("std");
const request = @import("request.zig");

pub const Operation = union(enum) {
    mix_pcs_config,
    mix_empty_preprocessed_root,
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

pub const Schedule = struct {
    seed_chain: u64,
    fri_tree_count: u32,
    operation_count: u32,

    pub fn init(geometry: request.Geometry) request.Error!Schedule {
        const fri_tree_count = std.math.cast(
            u32,
            geometry.fri_tree_count,
        ) orelse return error.GeometryOverflow;
        const operation_count = std.math.add(
            u32,
            12,
            std.math.mul(u32, fri_tree_count, 2) catch
                return error.GeometryOverflow,
        ) catch return error.GeometryOverflow;
        return .{
            .seed_chain = geometryChain(geometry),
            .fri_tree_count = fri_tree_count,
            .operation_count = operation_count,
        };
    }

    pub fn initialChain(self: Schedule) u64 {
        return chainAt(self.seed_chain, 0);
    }

    pub fn operation(self: Schedule, step: u32) request.Error!Operation {
        if (step >= self.operation_count) return error.GeometryOverflow;
        return switch (step) {
            0 => .mix_pcs_config,
            1 => .mix_empty_preprocessed_root,
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

    pub fn boundary(
        self: Schedule,
        step: u32,
    ) request.Error!Boundary {
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

fn geometryChain(geometry: request.Geometry) u64 {
    var state: u64 = 0x5354_574f_4355_4441; // "STWOCUDA"
    state = mix(state, geometry.statement.log_n_rows);
    state = mix(state, geometry.statement.sequence_len);
    state = mix(state, geometry.protocol.pow_bits);
    state = mix(state, geometry.protocol.log_blowup_factor);
    state = mix(state, geometry.protocol.log_last_layer_degree_bound);
    state = mix(state, geometry.protocol.n_queries);
    state = mix(state, geometry.protocol.fold_step);
    state = mix(
        state,
        if (geometry.protocol.lifting_log_size) |value|
            @as(u64, value) + 1
        else
            0,
    );
    state = mix(state, geometry.fri_tree_count);
    return avalanche(state);
}

fn chainAt(seed: u64, step: u32) u64 {
    return avalanche(seed ^ (@as(u64, step) *% 0x9e37_79b9_7f4a_7c15));
}

fn mix(state: u64, value: anytype) u64 {
    const word = std.math.cast(u64, value) orelse unreachable;
    return (state ^ word) *% 0x100_0000_01b3;
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

test "schedule seals canonical operation order for every admitted FRI tree" {
    const geometry = try request.admit(testRequest(5));
    const schedule = try Schedule.init(geometry);
    try std.testing.expectEqual(@as(u32, 22), schedule.operation_count);
    try std.testing.expectEqual(
        Operation.mix_pcs_config,
        try schedule.operation(0),
    );
    try std.testing.expectEqual(
        Operation.draw_quotient_alpha,
        try schedule.operation(8),
    );
    try std.testing.expectEqual(
        Operation{ .mix_fri_root = 0 },
        try schedule.operation(9),
    );
    try std.testing.expectEqual(
        Operation{ .draw_fri_alpha = 4 },
        try schedule.operation(18),
    );
    try std.testing.expectEqual(
        Operation.mix_last_layer,
        try schedule.operation(19),
    );
    try std.testing.expectEqual(
        Operation.draw_queries,
        try schedule.operation(21),
    );
}

test "schedule boundaries are geometry-bound and contiguous" {
    const small = try Schedule.init(try request.admit(testRequest(3)));
    const large = try Schedule.init(try request.admit(testRequest(22)));
    try std.testing.expect(small.initialChain() != large.initialChain());
    try std.testing.expectEqual(@as(u32, 18), small.operation_count);
    try std.testing.expectEqual(@as(u32, 56), large.operation_count);

    var step: u32 = 0;
    var expected_chain = small.initialChain();
    while (step < small.operation_count) : (step += 1) {
        const boundary = try small.boundary(step);
        try std.testing.expectEqual(step, boundary.expected_step);
        try std.testing.expectEqual(expected_chain, boundary.expected_chain);
        expected_chain = boundary.next_chain;
    }
    try std.testing.expectError(
        error.GeometryOverflow,
        small.boundary(small.operation_count),
    );
}

fn testRequest(log_n_rows: u32) request.Request {
    return .{
        .statement = .{
            .log_n_rows = log_n_rows,
            .sequence_len = 100,
        },
        .protocol = .{
            .pow_bits = 10,
            .log_blowup_factor = 1,
            .log_last_layer_degree_bound = 0,
            .n_queries = 3,
            .fold_step = 1,
            .lifting_log_size = null,
        },
    };
}
