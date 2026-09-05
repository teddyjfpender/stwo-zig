//! Narrow CPU integration surface for the Stage101 Metal experiment.
//!
//! Keeping these two modules outside the aggregate CPU integration root lets
//! the Metal command compile without analyzing unrelated CPU products.

pub const ethereum_incremental_full_leaf_replay_command_v4 =
    @import("ethereum_incremental_full_leaf_replay_command_v4.zig");
pub const ethereum_incremental_full_leaf_throughput_execution_v1 =
    @import("ethereum_incremental_full_leaf_throughput_execution_v1.zig");
