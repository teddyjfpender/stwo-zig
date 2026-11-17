//! Owner-local focused collection; selected by the maintained catalog.

test {
    _ = @import("typed/tests/typed_poseidon2_degree_bounded_candidate_test.zig");
    _ = @import("typed/tests/typed_poseidon2_degree_bounded_component_test.zig");
    _ = @import("prover/provider_order_component.zig");
    _ = @import("air/poseidon2_air.zig");
    _ = @import("primitives/recursion/poseidon2_channel.zig");
}
