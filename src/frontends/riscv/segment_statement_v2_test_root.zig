//! Focused segment-statement V2 boundary/root test root.

test {
    _ = @import("access_clock.zig");
    _ = @import("recursion/segment_statement_v2_test.zig");
    _ = @import("recursion/segment_statement_v2_transcript_layout_test.zig");
    _ = @import("recursion/segment_statement_v2_identity_preimage.zig");
    _ = @import("air/statement_v2_authority_preimage.zig");
}
