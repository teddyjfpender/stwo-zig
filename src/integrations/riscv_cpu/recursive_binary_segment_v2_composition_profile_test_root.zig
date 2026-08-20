const std = @import("std");
const subject = @import("recursive_binary_composition_authority.zig");
const focused = @import("recursive_binary_segment_v2_composition_profile_test.zig");

test "SegmentV2 composition V3 bridge declarations compile" {
    std.testing.refAllDeclsRecursive(subject.SegmentV2RecorderBridgeV3);
    std.testing.refAllDeclsRecursive(focused);
}
