//! Canonical SegmentV2 verifier adapters without native proof or witness owners.
comptime {
    _ = @import("recursive_segment_v2_detached_parent_producer.zig");
    _ = @import("recursive_segment_v2_detached_parent_prepare.zig");
    _ = @import("recursive_segment_v2_detached_parent_cohort.zig");
    _ = @import("recursive_segment_v2_detached_routing_test.zig");
    // Zig collects tests only from the test root's module. These focused
    // builds own the source files here; production runners use the integration
    // module exports and never also import the files into their root module.
    _ = @import("recursive_segment_v2_verifier_components.zig");
    _ = @import("recursive_segment_v2_public_inputs.zig");
    _ = @import("recursive_segment_v2_detached_transcript.zig");
    _ = @import("recursive_segment_v2_detached_command.zig");
    _ = @import("recursive_segment_v2_detached_child_transcript.zig");
    _ = @import("recursive_segment_v2_detached_boundary.zig");
    _ = @import("recursive_segment_v2_detached_parent_statement.zig");
}
