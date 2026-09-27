//! Fixed experimental outer PCS profile, independent of capture/preparation.
const stwo_core = @import("stwo_core");

pub const QUERY_COUNT: usize = 3;

pub const INTERACTION_POW_BITS: u32 = 0;

pub const PCS_POW_BITS: u32 = 0;

pub const LOG_BLOWUP_FACTOR: u32 = 1;

pub const LOG_LAST_LAYER_DEGREE_BOUND: u32 = 0;

pub const FOLD_STEP: u32 = 1;

pub const OUTER_FRI_CONFIG: stwo_core.fri.FriConfig = .{
    .log_blowup_factor = LOG_BLOWUP_FACTOR,
    .log_last_layer_degree_bound = LOG_LAST_LAYER_DEGREE_BOUND,
    .n_queries = QUERY_COUNT,
    .fold_step = FOLD_STEP,
};

pub const OUTER_PCS_CONFIG: stwo_core.pcs.PcsConfig = .{
    .pow_bits = PCS_POW_BITS,
    .fri_config = OUTER_FRI_CONFIG,
};
