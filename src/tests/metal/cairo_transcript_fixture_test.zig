const std = @import("std");
const transcript_fixture = @import("stwo_metal_backend").cairo.diagnostics.transcript_fixture;

test {
    std.testing.refAllDecls(transcript_fixture);
}
