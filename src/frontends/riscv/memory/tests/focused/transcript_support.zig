//! Explicit original transcript support cases at their canonical owner.
test {
    _ = @import("air/boundary.zig");
    _ = @import("air/incremental_boundary_interaction.zig");
    _ = @import("air/interaction.zig");
    _ = @import("air/merkle_node.zig");
    _ = @import("air/poseidon2.zig");
    _ = @import("air/poseidon2_air.zig");
    _ = @import("air/poseidon2_air_test.zig");
    _ = @import("air/sparse_merkle.zig");
    _ = @import("primitives/common/poseidon2.zig");
    _ = @import("primitives/recursion/blake3_identity_digest.zig");
    _ = @import("primitives/recursion/poseidon2_channel.zig");
}
