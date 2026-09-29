//! Merkle tests import the engine through its named package boundary.
comptime {
    _ = @import("vcs_lifted/tests/commit_paths.zig");
    _ = @import("vcs_lifted/tests/protocol.zig");
    _ = @import("vcs_lifted/tests/lifted_height.zig");
    _ = @import("vcs_lifted/tests/lazy_and_batched.zig");
    _ = @import("vcs_lifted/tests/test_utils.zig");
    _ = @import("vcs_lifted/tests/bounded_blake2_tail.zig");
}
