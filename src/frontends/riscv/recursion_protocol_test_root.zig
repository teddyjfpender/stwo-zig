//! Focused native recursion-protocol foundation gate.

comptime {
    _ = @import("air/component.zig");
    _ = @import("recursion/air/tests/pcs_deep_circuit_test.zig");
    _ = @import("recursion/tests/vm_public_semantics_circuit_test.zig");
    _ = @import("recursion/tests/statement_semantics_circuit_test.zig");
    _ = @import("recursion/poseidon2_channel.zig");
    _ = @import("recursion/protocol.zig");
    _ = @import("recursion/tests/vm_public_claim_test.zig");
    _ = @import("recursion/fixed_profile.zig");
    _ = @import("recursion/fixed_wire.zig");
    _ = @import("recursion/fixed_wire_adapter.zig");
    _ = @import("recursion/leaf_profile.zig");
    _ = @import("recursion/tests/fri_profile_frontier_test.zig");
    _ = @import("recursion/engine.zig");
    _ = @import("recursion/tests/pair_node_test.zig");
    _ = @import("recursion/tests/relation_summary_test.zig");
}
