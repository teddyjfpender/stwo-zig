//! Focused typed-Poseidon materialization and quotient-frontier tests.
//!
//! This root deliberately avoids the full RISC-V test inventory so physical
//! layout experiments retain a short correctness loop.

test {
    _ = @import("air/lang/materialization_cost_test.zig");
    _ = @import("air/lang/typed_poseidon2_degree_bounded_candidate_test.zig");
    _ = @import("air/lang/typed_poseidon2_degree_bounded_component_test.zig");
    _ = @import("air/lang/typed_poseidon2_degree_bounded_backend_test.zig");
    _ = @import("air/lang/typed_poseidon2_degree_bounded_trace_test.zig");
    _ = @import("air/lang/typed_poseidon2_degree5_trace_test.zig");
    _ = @import("prover/memory_provider_shards/provider_order_component.zig");
    _ = @import("air/memory_commitment/poseidon2_air.zig");
    _ = @import("recursion/poseidon2_channel.zig");
}
