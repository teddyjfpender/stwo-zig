//! Focused compile/test root for the disjoint V2 generic transcript authority.

test {
    _ = @import("recursion/transcript_program_v2.zig");
    _ = @import("recursion/tests/transcript_program_v2_test.zig");
    const std = @import("std");
    const required = .{
        "recording channel preserves native transcript and rejects corrupt trace coordinates",
        "V2 raw program exactly matches the ordinary generic channel",
        "V2 scheduled bootstrap rejects order version length and wire mutation",
        "V2 execution evidence and trace mutations fail closed",
    };
    // Anonymous tests survive filtering; every retained named case is mandatory.
    inline for (required) |suffix| {
        var found = false;
        for (@import("builtin").test_functions) |entry| {
            if (std.mem.endsWith(u8, entry.name, suffix)) found = true;
        }
        try std.testing.expect(found);
    }
}
