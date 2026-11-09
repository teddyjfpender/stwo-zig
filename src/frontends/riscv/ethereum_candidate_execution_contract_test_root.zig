//! Focused nonproduction combined-candidate capability/journal/product gate.

test {
    _ = @import("isa/ethereum_candidate_private_registry.zig");
    _ = @import("runner/guest_precompile/ethereum_candidate_execution_capability.zig");
    _ = @import("runner/guest_precompile/ethereum_candidate_execution_journal.zig");
    _ = @import("runner/guest_precompile/ethereum_candidate_observed_journal.zig");
}
