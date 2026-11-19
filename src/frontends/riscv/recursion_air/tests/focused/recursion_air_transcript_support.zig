//! Explicit original transcript support cases at their canonical owner.
test {
    _ = @import("../../protocol/recursion/fixed_profile.zig");
    _ = @import("../../protocol/recursion/protocol.zig");
    _ = @import("../../composition/verifier_schedule.zig");
}
