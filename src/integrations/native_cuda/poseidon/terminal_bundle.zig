//! Exact terminal SWPC admission policy for Native Poseidon.

const std = @import("std");
const stark = @import(
    "../../../backends/cuda/runtime/proof_assembly/stark_bundle.zig",
);
const geometry_mod = @import("geometry.zig");

pub const Descriptor = struct {
    pub fn validateProtocol(protocol: stark.Protocol) stark.Error!void {
        const expected_decommit = std.math.add(
            u32,
            protocol.log_n_rows,
            3,
        ) catch return error.SizeOverflow;
        if (protocol.log_n_rows == 0 or
            protocol.log_n_rows > geometry_mod.max_log_n_rows or
            protocol.sequence_len != protocol.log_n_rows + 3 or
            protocol.pow_bits != 10 or
            protocol.log_blowup_factor != 1 or
            protocol.log_last_layer_degree_bound != 0 or
            protocol.n_queries != 3 or
            protocol.fold_step != 1 or
            protocol.lifting_log_size != null or
            protocol.commitment_root_count != 4 or
            protocol.fri_root_count != protocol.log_n_rows or
            protocol.decommit_tree_count != expected_decommit)
        {
            return error.InvalidProtocolCounts;
        }
    }

    pub fn sampledValueCount(
        _: stark.Protocol,
    ) stark.Error!usize {
        return geometry_mod.sampled_mask_points;
    }
};

test "Poseidon terminal policy binds instance and trace logs" {
    const protocol = stark.Protocol{
        .log_n_rows = 10,
        .sequence_len = 13,
        .pow_bits = 10,
        .log_blowup_factor = 1,
        .log_last_layer_degree_bound = 0,
        .n_queries = 3,
        .fold_step = 1,
        .lifting_log_size = null,
        .commitment_root_count = 4,
        .fri_root_count = 10,
        .decommit_tree_count = 13,
    };
    try Descriptor.validateProtocol(protocol);
    try std.testing.expectEqual(
        @as(usize, 1316),
        try Descriptor.sampledValueCount(protocol),
    );
}
