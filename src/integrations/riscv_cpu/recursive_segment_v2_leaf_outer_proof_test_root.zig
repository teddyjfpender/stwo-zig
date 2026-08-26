const std = @import("std");
const subject = @import("recursive_segment_v2_leaf_outer.zig");
const proof_test = @import("recursive_segment_v2_leaf_outer_proof_test.zig");

test "recursive segment V2 Poseidon proof gate declarations compile" {
    std.testing.refAllDeclsRecursive(subject);
    std.testing.refAllDeclsRecursive(proof_test);
}
