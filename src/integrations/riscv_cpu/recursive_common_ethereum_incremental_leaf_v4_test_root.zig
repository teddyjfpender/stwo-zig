//! Aggregate structural test root for the versioned real-leaf wrapper input.

comptime {
    _ = @import("recursive_common_ethereum_incremental_leaf_universal_proof_v4_core.zig");
    _ = @import("recursive_secure_transcript_program_v1.zig");
    _ = @import("recursive_common_ethereum_incremental_leaf_transcript_program_v4.zig");
    _ = @import("ethereum_wrapper_candidate_v1.zig");
    _ = @import("recursive_common_ethereum_incremental_leaf_cold_geometry_v4.zig");
    _ = @import("ethereum_symbolic_wire_boundary_v4_test.zig");
    _ = @import("recursive_common_ethereum_incremental_leaf_composition_capture_owner_v4.zig");
    _ = @import("recursive_common_ethereum_incremental_leaf_composition_capture_v4.zig");
    _ = @import("ethereum_wrapper_composition_proof_v1_test.zig");
    _ = @import("ethereum_failed_wrapper_replay_v1.zig");
    _ = @import("ethereum_tuple_ledger_reservation_v1.zig");
    _ = @import("ethereum_compact_tuple_ledger_v1.zig");
    _ = @import("ethereum_wrapper_resources_v1.zig");
    _ = @import("ethereum_typed_air_preflight_v4.zig");
    _ = @import("ethereum_typed_air_point_parity_v4.zig");
    _ = @import("recursive_common_ethereum_incremental_leaf_secure_cohort_v4.zig");
    _ = @import("recursive_common_ethereum_incremental_leaf_public_statement_boundary_v4.zig");
    _ = @import("recursive_common_ethereum_incremental_leaf_field_frame_plan_v4.zig");
    _ = @import("recursive_common_ethereum_incremental_leaf_native_identity_hash_v4.zig");
    _ = @import("recursive_common_ethereum_incremental_leaf_native_identity_routing_v4.zig");
    _ = @import("ethereum_incremental_field_transcript_v4.zig");
    _ = @import("ethereum_incremental_full_leaf_proof_v4_test.zig");
    _ = @import("recursive_common_ethereum_incremental_leaf_program_admission_v1.zig");
    _ = @import("recursive_common_ethereum_incremental_leaf_publication_hash_v4_test.zig");
    _ = @import("recursive_common_ethereum_incremental_leaf_statement_routing_v4_test.zig");
    _ = @import("recursive_common_ethereum_incremental_leaf_public_sums_v4_support.zig");
    _ = @import("recursive_common_ethereum_incremental_leaf_public_sums_v4_clock_test.zig");
    _ = @import("recursive_common_ethereum_incremental_leaf_global_binding_v1_test.zig");
    _ = @import("recursive_common_ethereum_incremental_leaf_field_public_v4_test.zig");
    _ = @import("recursive_common_ethereum_incremental_leaf_field_public_v4_schema3_test.zig");
    _ = @import("recursive_common_ethereum_incremental_leaf_materializer_v4_test.zig");
    _ = @import("recursive_common_ethereum_incremental_leaf_public_semantics_v4_test.zig");
    _ = @import("recursive_common_ethereum_incremental_leaf_role_aware_io_v4_test.zig");
    _ = @import("recursive_common_ethereum_incremental_leaf_campaign_provider_geometry_v4_test.zig");
    _ = @import("recursive_common_ethereum_incremental_leaf_child_public_v4_test.zig");
    _ = @import("recursive_common_ethereum_incremental_leaf_child_statement_v4_test.zig");
    _ = @import("recursive_common_ethereum_incremental_leaf_complete_provider_geometry_v4_test.zig");
    _ = @import("recursive_common_ethereum_incremental_leaf_transcript_cohort_v4_test.zig");
    _ = @import("recursive_common_ethereum_incremental_leaf_universal_cohort_v4_test.zig");
}

test "Ethereum cohort replay publication preserves absent and present initial claims" {
    try @import("ethereum_statement_root_cohort_replay.zig").exercisePublicationCodec();
}
