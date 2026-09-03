//! Focused nonproduction SWAP1..SWAP16 semantic and AIR candidate gate.

test {
    _ = @import("runner/guest_precompile/stack_swap_v1_test.zig");
    _ = @import("runner/guest_precompile/ethereum_stack_swap_candidate_test.zig");
}
