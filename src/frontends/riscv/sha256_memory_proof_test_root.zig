comptime {
    _ = @import("runner/guest_precompile/tests/ethereum_sha_profile_test.zig");
    _ = @import("prover/guest_precompile/ethereum_sha_relations.zig");
    _ = @import("air/guest_precompile/sha256_coefficient_bounds.zig");
    _ = @import("recursion/air/universal_component_owner.zig");
    _ = @import("air/guest_precompile/sha256_lookup_registration.zig");
    _ = @import("air/guest_precompile/sha256_component_profile.zig");
    _ = @import("air/guest_precompile/sha256_relations.zig");
    _ = @import("air/guest_precompile/sha256_memory_rows.zig");
    _ = @import("air/guest_precompile/sha256_preprocessed.zig");
    _ = @import("air/guest_precompile/tests/sha256_memory_proof_test.zig");
    _ = @import("air/guest_precompile/sha256_memory_proof_boundary.zig");
}
