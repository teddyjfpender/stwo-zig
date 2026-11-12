//! Canonical typed domain interfaces; test hooks are explicitly unstable.

pub const regressions = struct {
    pub const keccak_tuples = struct {
        pub const run = @import("cases/air/guest_precompile/tests/keccakf_lookup_tuple_test.zig").run;
    };
    pub const segment_wire = struct {
        pub const expectNativeView = @import("cases/recursion/tests/segment_statement_transcript_layout_test.zig").expectNativeView;
    };
};
pub const testing = struct {
    pub const inventory_source = @embedFile("tests/root.zig");
};

test {
    _ = @import("tests/root.zig");
}
