//! Focused verifier-circuit construction without native leaf or witness fixtures.
comptime {
    _ = @import("ethereum_fixed_program_admission_v1_test.zig");
    _ = @import("ethereum_fixed_program_completion_v1_test.zig");
    _ = @import("ethereum_fixed_program_native_v1_test.zig");
    _ = @import("ethereum_wrapper_detached_fold_namespace_v1_test.zig");
    _ = @import("recursive_common_fold_verifier_command_v2.zig");
    _ = @import("recursive_binary_outer_grouped_storage_test.zig");
    _ = @import("ethereum_wrapper_verifier_components_v1.zig");
    _ = @import("ethereum_wrapper_root_verifier_v1_test.zig");
    _ = @import("ethereum_wrapper_detached_transcript_v1.zig");
    _ = @import("ethereum_wrapper_child_shape_v1_test.zig");
    _ = @import("ethereum_wrapper_detached_fold_v1_test.zig");
    _ = @import("ethereum_native_tree0_admission_v1_test.zig");
    _ = @import("ethereum_native_verification_scope_v1.zig");
    _ = @import("ethereum_full_leaf_bundle_verifier_v1.zig");
}
