//! Storage geometry measured by the real segment2 AIR preflight. Both saved
//! child keys must independently match in run(); these numbers admit no proof.
test "Ethereum saved real wrapper siblings prove and verify after destruction" {
    try @import("ethereum_wrapper_saved_child_parent_v1_test.zig").run(.{
        .commitment_count = 4,
        .claimed_sum_count = 36,
        .sampled_value_count = 2453,
        .queried_value_count = 444865,
        .trace_path_count = 772,
        .fri_layer_count = 6,
        .query_count = 193,
        .maximum_fold_width = 16,
        .last_layer_coefficient_count = 1,
        .maximum_merkle_depth = 25,
    });
}
