const std = @import("std");
const subject = @import("recursive_segment_v2_outer_cohort.zig");
const outer_engine = @import("recursive_segment_v2_outer_engine.zig");
const tuple_diagnostic = @import("recursive_segment_v2_tuple_closure_diagnostic.zig");

test "SegmentV2 concrete cohort satisfies the complete outer-engine contract" {
    std.testing.refAllDeclsRecursive(subject.Cohort);
    const Kernel = outer_engine.EngineKernel(subject.Cohort);
    std.testing.refAllDeclsRecursive(Kernel);
    std.testing.refAllDeclsRecursive(tuple_diagnostic);
}
