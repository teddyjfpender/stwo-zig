const std = @import("std");

test "SegmentV2 publication-input provider focused inventory compiles" {
    std.testing.refAllDeclsRecursive(
        @import("recursion/segment_publication_input_provider_authority_v2_test.zig"),
    );
}
