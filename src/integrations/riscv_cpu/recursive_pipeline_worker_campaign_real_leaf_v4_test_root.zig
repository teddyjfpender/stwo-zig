//! Isolated structural root for the campaign Stage101 -> Stage102 worker family.

comptime {
    _ = @import("recursive_pipeline_worker_campaign_real_leaf_v4_test.zig");
    _ = @import("recursive_pipeline_worker_campaign_real_leaf_composite_v4_test.zig");
    _ = @import("recursive_pipeline_worker_campaign_stage102_lifecycle_v4_test.zig");
    _ = @import("recursive_pipeline_worker_campaign_stage102_final_lifecycle_v4_test.zig");
    _ = @import("recursive_pipeline_worker_campaign_final_session_bridge_v4_test.zig");
    _ = @import("recursive_pipeline_worker_campaign_role0_frontier_v4_test.zig");
    _ = @import("recursive_pipeline_campaign_final_driver_role0_frontier_v4_test.zig");
    _ = @import("recursive_pipeline_campaign_final_live_receipt_binder_v2_test.zig");
    _ = @import("recursive_pipeline_campaign_final_live_build_executor_v2_test.zig");
    _ = @import("recursive_pipeline_campaign_final_live_tree_executor_v2_test.zig");
    _ = @import("recursive_pipeline_campaign_final_live_runtime_epoch_v2_test.zig");
    _ = @import("recursive_pipeline_campaign_final_owned_live_runtime_v2_test.zig");
    _ = @import("recursive_pipeline_campaign_final_assembly_bound_runtime_v2_test.zig");
    _ = @import("recursive_pipeline_campaign_stage102_inventory_description_bridge_v4_test.zig");
    _ = @import("recursive_pipeline_campaign_genuine_three_leaf_final_remint_fixture_v2_test.zig");
    _ = @import("recursive_pipeline_campaign_genuine_stage101_authenticated_inputs_v4_test.zig");
}
