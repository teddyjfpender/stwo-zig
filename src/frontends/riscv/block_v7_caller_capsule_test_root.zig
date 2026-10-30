const std = @import("std");
test "v7 trusted compiler capsule entrypoints instantiate" {
    std.mem.doNotOptimizeAway(&@import("recursion/block_v7_caller_joint_compiler_capsule_v1.zig").Capsule.derive);
    std.mem.doNotOptimizeAway(&@import("recursion/block_v7_caller_joint_compiler_capsule_v1.zig").Capsule.prepareComposition);
    std.mem.doNotOptimizeAway(&@import("recursion/block_v7_caller_joint_preparation_v1.zig").prepareFromCapsule);
    std.mem.doNotOptimizeAway(&@import("recursion/block_v7_caller_joint_fixed_roster_v1.zig").Owned.deriveFromCapsule);
}
test {
    _ = @import("recursion/block_v7_caller_capsule_test_v1.zig");
}
