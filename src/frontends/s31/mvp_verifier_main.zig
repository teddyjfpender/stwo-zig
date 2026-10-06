pub fn main() !void {
    return @import("mvp_runtime.zig").verifierMain(@embedFile("s31_verification_key"), @embedFile("s31_recursive_key"), @embedFile("s31_recursive_next_key"), @embedFile("s31_fold_key"));
}
