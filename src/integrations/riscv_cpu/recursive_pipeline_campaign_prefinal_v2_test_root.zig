//! Isolated structural root for the non-circular campaign padding flow.

comptime {
    _ = @import("recursive_pipeline_campaign_padding_transaction_v2_test.zig");
    _ = @import("recursive_pipeline_campaign_prefinal_fold_lease_v2_test.zig");
    _ = @import("recursive_common_fold_campaign_prefinal_v2_test.zig");
    _ = @import("recursive_pipeline_worker_execution_policy_v2_test.zig");
    _ = @import("recursive_pipeline_level_scheduler_v2_test.zig");
    _ = @import("recursive_pipeline_worker_campaign_stage102_inventory_builder_v4_test.zig");
}
