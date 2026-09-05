const std = @import("std");

test "LOAD_STORE private fixed-authority declarations compile" {
    std.testing.refAllDecls(@import("air/lang/fixed_load_store.zig"));
    std.testing.refAllDecls(@import("air/lang/typed_load_store_authority.zig"));
    std.testing.refAllDecls(@import("runner/load_store_retirement.zig"));
}

comptime {
    _ = @import("air/lang/typed_load_store_selector_alias_candidate_v1_test.zig");
    _ = @import("air/lang/typed_load_store_authority_test.zig");
    _ = @import("runner/load_store_retirement_test.zig");
}
