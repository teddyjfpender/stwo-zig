//! Exact terminal SWPC admission policy for Native XOR.

const std = @import("std");
const geometry_mod = @import("geometry.zig");
const stark = @import(
    "../../../backends/cuda/runtime/proof_assembly/stark_bundle.zig",
);

pub const Descriptor = struct {
    pub fn validateProtocol(protocol: stark.Protocol) stark.Error!void {
        const expected_decommit = std.math.add(
            u32,
            protocol.log_n_rows,
            4,
        ) catch return error.SizeOverflow;
        if (protocol.log_n_rows < geometry_mod.min_log_size or
            protocol.log_n_rows > 29 or
            protocol.sequence_len > protocol.log_n_rows or
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

    pub fn sampledValueCount(_: stark.Protocol) stark.Error!usize {
        return 27;
    }
};

test "XOR terminal policy admits step zero and exact tree counts" {
    const protocol = stark.Protocol{
        .log_n_rows = 14,
        .sequence_len = 3,
        .pow_bits = 10,
        .log_blowup_factor = 1,
        .log_last_layer_degree_bound = 0,
        .n_queries = 3,
        .fold_step = 1,
        .lifting_log_size = null,
        .commitment_root_count = 4,
        .fri_root_count = 14,
        .decommit_tree_count = 18,
    };
    try Descriptor.validateProtocol(protocol);
    try std.testing.expectEqual(
        @as(usize, 27),
        try Descriptor.sampledValueCount(protocol),
    );
}
