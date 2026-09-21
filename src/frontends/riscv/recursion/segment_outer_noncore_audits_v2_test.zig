const shard_0 = @import("segment_outer_noncore_audits_v2_test_owned_boundary_traces.zig");
const shard_1 = @import("segment_outer_noncore_audits_v2_test_fixture.zig");
const shard_2 = @import("segment_outer_noncore_audits_v2_test_suite_3.zig");

test "non-core custody suite imports every shard" {
    _ = shard_0;
    _ = shard_1;
    _ = shard_2;
}
