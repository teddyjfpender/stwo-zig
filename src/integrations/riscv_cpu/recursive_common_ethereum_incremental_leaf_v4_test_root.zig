//! Aggregate structural test root for the versioned real-leaf wrapper input.

comptime {
    _ = @import("recursive_common_ethereum_incremental_leaf_field_public_v4_test.zig");
    _ = @import("recursive_common_ethereum_incremental_leaf_field_public_v4_schema3_test.zig");
    _ = @import("recursive_common_ethereum_incremental_leaf_materializer_v4_test.zig");
    _ = @import("recursive_common_ethereum_incremental_leaf_public_semantics_v4_test.zig");
    _ = @import("recursive_common_ethereum_incremental_leaf_role_aware_io_v4_test.zig");
    _ = @import("recursive_common_ethereum_incremental_leaf_campaign_provider_geometry_v4_test.zig");
    _ = @import("recursive_common_ethereum_incremental_leaf_child_public_v4_test.zig");
    _ = @import("recursive_common_ethereum_incremental_leaf_complete_provider_geometry_v4_test.zig");
    _ = @import("recursive_common_ethereum_incremental_leaf_transcript_cohort_v4_test.zig");
    _ = @import("recursive_common_ethereum_incremental_leaf_universal_cohort_v4_test.zig");
}
