//! Narrow CPU integration surface for the Stage101 degree-five Metal sweep.
//!
//! Keeping these modules outside the aggregate CPU integration root lets the
//! retained provider command compile without analyzing unrelated CPU products.

pub const ethereum_block_leaf_support =
    @import("ethereum_block_leaf_support.zig");
pub const ethereum_candidate_degree5_provider_batch_execution_v1 =
    @import("ethereum_candidate_degree5_provider_batch_execution_v1.zig");
pub const ethereum_candidate_degree5_provider_order_batch_v1 =
    @import("ethereum_candidate_degree5_provider_order_batch_v1.zig");
pub const ethereum_candidate_degree5_provider_prepared_batch_v1 =
    @import("ethereum_candidate_degree5_provider_prepared_batch_v1.zig");
pub const ethereum_incremental_full_leaf_replay_command_v4 =
    @import("ethereum_incremental_full_leaf_replay_command_v4.zig");
pub const ethereum_incremental_full_leaf_throughput_execution_v1 =
    @import("ethereum_incremental_full_leaf_throughput_execution_v1.zig");
pub const ethereum_precompile_artifact_io =
    @import("ethereum_precompile_artifact_io.zig");
