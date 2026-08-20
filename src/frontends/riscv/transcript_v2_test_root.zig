//! Focused compile/test root for the disjoint V2 generic transcript authority.

test {
    _ = @import("recursion/transcript_program_v2.zig");
    _ = @import("recursion/scheduled_channel_v2.zig");
    _ = @import("recursion/transcript_program_v2_test.zig");
}
