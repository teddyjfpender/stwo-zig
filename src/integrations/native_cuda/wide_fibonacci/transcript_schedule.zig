//! Wide-Fibonacci seed policy for the shared transcript schedule.

const shared = @import("../common/transcript_schedule.zig");
const request = @import("request.zig");

pub const Operation = shared.Operation;
pub const Boundary = shared.Boundary;

pub const Schedule = struct {
    structural: shared.Schedule,

    pub fn init(geometry: request.Geometry) !Schedule {
        var seed = shared.SeedBuilder.init(0x5354_574f_4355_4441);
        try seed.mix(geometry.statement.log_n_rows);
        try seed.mix(geometry.statement.sequence_len);
        try seed.mix(geometry.protocol.pow_bits);
        try seed.mix(geometry.protocol.log_blowup_factor);
        try seed.mix(geometry.protocol.log_last_layer_degree_bound);
        try seed.mix(geometry.protocol.n_queries);
        try seed.mix(geometry.protocol.fold_step);
        try seed.mix(
            if (geometry.protocol.lifting_log_size) |value|
                @as(u64, value) + 1
            else
                0,
        );
        try seed.mix(geometry.fri_tree_count);
        return .{
            .structural = try shared.Schedule.init(
                seed.finish(),
                geometry.fri_tree_count,
            ),
        };
    }

    pub fn initialChain(self: Schedule) u64 {
        return self.structural.initialChain();
    }

    pub fn operation(self: Schedule, step: u32) !Operation {
        return self.structural.operation(step);
    }

    pub fn boundary(self: Schedule, step: u32) !Boundary {
        return self.structural.boundary(step);
    }

    pub fn friTreeCount(self: Schedule) u32 {
        return self.structural.fri_tree_count;
    }

    pub fn operationCount(self: Schedule) u32 {
        return self.structural.operation_count;
    }
};

test "wide schedule preserves the canonical operation count" {
    const std = @import("std");
    const geometry = try request.admit(.{
        .statement = .{ .log_n_rows = 5, .sequence_len = 100 },
        .protocol = .{
            .pow_bits = 10,
            .log_blowup_factor = 1,
            .log_last_layer_degree_bound = 0,
            .n_queries = 3,
            .fold_step = 1,
            .lifting_log_size = null,
        },
    });
    const schedule = try Schedule.init(geometry);
    try std.testing.expectEqual(@as(u32, 22), schedule.operationCount());
    try std.testing.expectEqual(
        Operation.mix_preprocessed_root,
        try schedule.operation(1),
    );
}
