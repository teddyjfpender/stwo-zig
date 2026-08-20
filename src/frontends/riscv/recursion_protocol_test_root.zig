//! Focused native recursion-protocol foundation gate.

comptime {
    _ = @import("recursion/poseidon2_channel.zig");
    _ = @import("recursion/protocol.zig");
    _ = @import("recursion/fixed_profile.zig");
    _ = @import("recursion/fixed_wire.zig");
    _ = @import("recursion/fixed_wire_adapter.zig");
    _ = @import("recursion/leaf_profile.zig");
    _ = @import("recursion/fri_profile_frontier_test.zig");
    _ = @import("recursion/engine.zig");
    _ = @import("recursion/pair_node_test.zig");
    _ = @import("recursion/relation_summary_test.zig");
}
