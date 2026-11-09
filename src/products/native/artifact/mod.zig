//! Native example proof artifacts: the JSON artifact codec and its verifier.
pub const examples_artifact = @import("examples_artifact.zig");
pub const examples_artifact_verifier = @import("examples_artifact_verifier.zig");

test {
    _ = @import("tests/xor_codec_roundtrip.zig");
    @import("std").testing.refAllDecls(@This());
}
