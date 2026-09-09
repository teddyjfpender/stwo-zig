const std = @import("std");

test "fixed64 SHA-256 pair candidate declarations compile" {
    std.testing.refAllDecls(
        @import("air/guest_precompile/sha256_pair_candidate_v1.zig"),
    );
    std.testing.refAllDecls(
        @import("air/guest_precompile/sha256_pair_direct_candidate_v1.zig"),
    );
    std.testing.refAllDecls(
        @import("air/guest_precompile/sha256_pair_caller_candidate_v1.zig"),
    );
    std.testing.refAllDecls(
        @import("air/guest_precompile/sha256_pair_observer_projection_v1.zig"),
    );
}

comptime {
    _ = @import("air/guest_precompile/sha256_pair_candidate_v1_test.zig");
}
