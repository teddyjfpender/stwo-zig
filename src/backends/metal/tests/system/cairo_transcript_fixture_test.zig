const std = @import("std");
const transcript_fixture = @import("stwo_cairo_metal_integration").transcript_fixture;

test {
    std.testing.refAllDecls(transcript_fixture);
}
