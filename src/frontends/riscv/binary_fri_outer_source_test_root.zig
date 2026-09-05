const std = @import("std");
const source = @import("recursion/binary_fri_outer_source.zig");
const bundle = @import("recursion/binary_fri_outer_bundle.zig");
const fixture = @import("recursion/binary_pair_test_fixture.zig");
const segment_core = @import("recursion/segment_core_outer_components_v2.zig");
const SegmentCoreBundle = segment_core.Bundle(fixture.DIMENSIONS);

comptime {
    _ = @import("recursion/binary_composition_rows_heterogeneous_v2_test.zig");
    _ = @import("recursion/binary_fri_outer_source_test.zig");
    _ = @import("air/memory_commitment/poseidon2_air.zig");
}

test "R-015 binary FRI neutral bundle public surface compiles" {
    std.testing.refAllDeclsRecursive(bundle);
    std.testing.refAllDeclsRecursive(segment_core);
    std.testing.refAllDeclsRecursive(SegmentCoreBundle);
}

test "R-015 binary FRI trusted composition profile is sealed" {
    const protocol_id = [_]u32{1} ** 8;
    const circuit_id = [_]u8{2} ** 32;
    const graph_id = [_]u8{3} ** 32;
    var profile = try source.TrustedCompositionProfileV1.seal(
        protocol_id,
        71,
        circuit_id,
        graph_id,
    );
    try profile.validate();
    profile.graph_identity[0] ^= 1;
    try std.testing.expectError(error.InvalidCompositionProfile, profile.validate());
}
