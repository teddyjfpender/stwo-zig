//! Focused native recursion-protocol foundation gate.

comptime {
    _ = @import("air/component.zig");
    _ = @import("recursion/air/pcs_deep_circuit_test.zig");
    _ = @import("recursion/vm_public_semantics_circuit_test.zig");
    _ = @import("recursion/statement_semantics_circuit_test.zig");
    _ = @import("recursion/poseidon2_channel.zig");
    _ = @import("recursion/protocol.zig");
    _ = @import("recursion/vm_public_claim_test.zig");
    _ = @import("recursion/fixed_profile.zig");
    _ = @import("recursion/fixed_wire.zig");
    _ = @import("recursion/fixed_wire_adapter.zig");
    _ = @import("recursion/leaf_profile.zig");
    _ = @import("recursion/fri_profile_frontier_test.zig");
    _ = @import("recursion/engine.zig");
    _ = @import("recursion/pair_node_test.zig");
    _ = @import("recursion/relation_summary_test.zig");
}
