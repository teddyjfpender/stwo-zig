//! Focused segment-statement V2 boundary/root test root.

test {
    _ = @import("access_clock.zig");
    _ = @import("recursion/tests/segment_statement_test.zig");
    _ = @import("recursion/tests/segment_statement_transcript_layout_test.zig");
    _ = @import("recursion/segment_statement_identity_preimage.zig");
    _ = @import("air/statement_authority_preimage.zig");
}
