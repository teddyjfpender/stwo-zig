//! Plonk statement policy for the shared transcript schedule.

const shared = @import("../common/transcript_schedule.zig");
const geometry_mod = @import("geometry.zig");

pub const Operation = shared.Operation;
pub const Boundary = shared.Boundary;

pub const Schedule = struct {
    structural: shared.Schedule,

    pub fn init(geometry: geometry_mod.Geometry) !Schedule {
        var seed = shared.SeedBuilder.init(0x5354_574f_4355_4441);
        try seed.mix(geometry.statement.log_n_rows);
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

test "Plonk schedule binds the complete public statement" {
    const std = @import("std");
    const pcs = @import("stwo_core").pcs;
    const first = try Schedule.init(try geometry_mod.admit(
        .{ .log_n_rows = 8 },
        pcs.PcsConfig.default(),
    ));
    const second = try Schedule.init(try geometry_mod.admit(
        .{ .log_n_rows = 7 },
        pcs.PcsConfig.default(),
    ));
    try std.testing.expectEqual(@as(u32, 28), first.operationCount());
    try std.testing.expectEqual(
        Operation.mix_preprocessed_root,
        try first.operation(1),
    );
    try std.testing.expect(first.initialChain() != second.initialChain());
}
