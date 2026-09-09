//! Focused root for the engine-generic Stage101 D5 provider route body.
//!
//! It carries the unit gates plus a `refAllDecls` of the module itself, so a
//! declaration only the Metal command would otherwise instantiate is analysed
//! here in seconds rather than in a nine-minute Metal product build.

const std = @import("std");

const route_mod = @import("ethereum_incremental_omitted_leaf_route_v1.zig");

comptime {
    _ = @import("ethereum_incremental_omitted_leaf_route_v1_test.zig");
}

test "Stage101 D5 route declarations compile" {
    std.testing.refAllDecls(route_mod);
    std.testing.refAllDecls(route_mod.ReceiptV1);
    std.testing.refAllDecls(route_mod.ProviderRouteBudgetV1);
    std.testing.refAllDecls(route_mod.TimingV1);
    std.testing.refAllDecls(route_mod.RetainedSourcePinsV1);
}
