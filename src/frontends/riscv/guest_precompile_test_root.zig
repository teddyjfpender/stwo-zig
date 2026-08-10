//! Focused proof-side guest-precompile test root.

test {
    _ = @import("air/guest_precompile/interaction_chunk_test.zig");
    _ = @import("air/guest_precompile/interaction_test.zig");
    _ = @import("air/guest_precompile/main_trace_test.zig");
    _ = @import("air/guest_precompile/proof_admission_test.zig");
    _ = @import("air/guest_precompile/program_commitment_test.zig");
    _ = @import("air/guest_precompile/relation_test.zig");
}
