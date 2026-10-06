pub fn main() !void {
    return @import("mvp_runtime.zig").verifierMain(@embedFile("s31_verification_key"));
}
