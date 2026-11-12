//! Canonical nominal types and callable signatures consumed across owners.
const std = @import("std");
const api = @import("../mod.zig");

test "C3 canonical API identity: unstable regression callable signatures" {
    try std.testing.expect(@TypeOf(api.regressions.keccak_tuples.run) == @TypeOf(@import("../cases/air/guest_precompile/tests/keccakf_lookup_tuple_test.zig").run));
    try std.testing.expect(@TypeOf(api.regressions.segment_wire.expectNativeView) == @TypeOf(@import("../cases/recursion/tests/segment_statement_transcript_layout_test.zig").expectNativeView));
}
