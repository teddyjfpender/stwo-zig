//! Native SegmentV2 development PCS parameters. The outer development proof
//! has a separate q3 profile; its key must regenerate native Tree 0 with
//! these q1 parameters.
pub const PCS_CONFIG = @import("stwo_core").pcs.PcsConfig{
    .pow_bits = 0,
    .fri_config = .{
        .log_blowup_factor = 1,
        .log_last_layer_degree_bound = 0,
        .n_queries = 1,
        .fold_step = 2,
    },
};
