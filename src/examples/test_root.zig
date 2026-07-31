//! Package-owned Native example AIR and reusable-session test root.

const std = @import("std");
const examples = @import("mod.zig");

test {
    std.testing.refAllDecls(examples);
    _ = @import("blake/session_test.zig");
    _ = @import("plonk/session_test.zig");
    _ = @import("poseidon/session_test.zig");
    _ = @import("state_machine/session_test.zig");
    _ = @import("wide_fibonacci/session_test.zig");
    _ = @import("xor/session_test.zig");
}
