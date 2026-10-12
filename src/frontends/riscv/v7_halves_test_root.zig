const std = @import("std");
const payload = @import("recursion/air/transcript_payload_direct_v7.zig");
const payload_v6 = @import("recursion/air/transcript_payload_direct_v6.zig");
const schedule = @import("recursion/segment_leaf_wrapper_row5_halves_v7.zig");
const bridge = @import("recursion/air/transcript_program_v2_field_bridge_v6.zig");
const witness = @import("recursion/segment_leaf_wrapper_wire_half_witness_v7.zig");
const range_provider = @import("recursion/segment_leaf_wrapper_range_provider_v7.zig");

test {
    std.testing.refAllDeclsRecursive(payload);
    _ = payload_v6;
    std.testing.refAllDeclsRecursive(schedule);
    std.testing.refAllDeclsRecursive(bridge);
    std.testing.refAllDeclsRecursive(witness);
    std.testing.refAllDeclsRecursive(range_provider);
}
