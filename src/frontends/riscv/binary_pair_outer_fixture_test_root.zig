const std = @import("std");
const support = @import("testing/binary_pair_outer_fixture.zig");

test "binary pair outer shared fixture API compiles" {
    std.testing.refAllDeclsRecursive(support);
}

test "binary pair outer shared fixture owns one authority for both cohorts" {
    var fixture = try support.Fixture.init(std.testing.allocator);
    defer fixture.deinit();

    const nonfri = try fixture.nonFriInputs();
    const fri = fixture.friSource();
    try std.testing.expect(nonfri.transcript_prepared == fri.pair);
    try std.testing.expect(std.meta.eql(
        nonfri.root_pin.expected_aggregator_vk_id,
        fri.root_pin.expected_aggregator_vk_id,
    ));
    try fri.requireFullBundleAuthority();
}
