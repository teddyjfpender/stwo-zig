//! Focused proof-side guest-precompile test root.

test {
    _ = @import("air/guest_precompile/main_trace_test.zig");
    _ = @import("air/guest_precompile/relation_test.zig");
}
