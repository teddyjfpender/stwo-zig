//! Product-neutral RV64 block pipeline: capture, plan, native CPU proving and
//! fresh reception of one guest execution. Product lines plug in through the
//! comptime hooks contract in `hooks.zig`; nothing here names a product.
const std = @import("std");
const hooks = @import("hooks.zig");

/// The pipeline bound to one product's hooks. The hooks type must be the
/// module the product build injected as `rv64_pipeline_hooks` (see the
/// package build's `instantiate`), so each product owns one pipeline instance.
pub fn Pipeline(comptime H: type) type {
    comptime assertHooks(H);
    if (H != @import("rv64_pipeline_hooks")) @compileError("Pipeline hooks must be the module injected as rv64_pipeline_hooks");
    return struct {
        pub const Hooks = H;
        pub const label: []const u8 = H.label;
        /// Request JSON schema and the pinned ELF/input/expected-output request.
        pub const request = @import("request.zig");
        /// Independently loaded pristine expected image owner.
        pub const image = @import("word16_execution/expected_image.zig");
        pub const plan = @import("block/plan.zig");
        pub const keys = @import("block/keys.zig");
        pub const receiver = @import("block/gkr_receiver.zig");
        pub const terminal = @import("block/terminal.zig");
        pub const resources = @import("block/gkr_resources.zig");
        /// Native CPU production and fresh reception command line (no
        /// recursion): `describe-candidate`, `plan-candidate`,
        /// `produce-candidate`, `verify-candidate`, `verify-prefix-candidate`.
        pub const main = @import("block/gkr_main.zig").main;
    };
}

/// Contract of the product hooks module (doc namespace; see `hooks.zig`).
pub const ProductHooks = struct {
    pub const required_decls = hooks.required_decls;
    pub const symbol_fields = hooks.symbol_fields;
    pub const TERMINAL_OUTPUT_BYTES = hooks.TERMINAL_OUTPUT_BYTES;
    pub const violation = hooks.violation;
};
/// RFC-3 extension point; products declare an empty set until it is decided.
pub const ServiceFamily = hooks.ServiceFamily;
pub const assertHooks = hooks.assertHooks;

test "api signature: hooks contract rejects incomplete hooks and admits the reference hooks" {
    const Incomplete = struct {
        pub const label = "incomplete";
    };
    try std.testing.expectEqualStrings("missing hook `Symbols`", comptime hooks.violation(Incomplete).?);
    try std.testing.expect(comptime hooks.violation(@import("rv64_pipeline_hooks")) == null);
    _ = Pipeline(@import("rv64_pipeline_hooks"));
}

test "api invariant: guest abi view forwards the injected hooks unchanged" {
    const H = @import("rv64_pipeline_hooks");
    const abi = @import("guest_abi.zig");
    try std.testing.expectEqual(@as(usize, H.MAX_INPUT_BYTES + 4), abi.INPUT_CAPACITY_MAX);
    try std.testing.expectEqual(@as(usize, 43), abi.OUTPUT_BYTES);
    try std.testing.expect(abi.Symbols == H.Symbols);
}

test {
    _ = @import("block/gkr_main.zig");
    _ = @import("block/plan_scope_test.zig");
    _ = @import("block/terminal_test.zig");
    _ = @import("block/receiver_test.zig");
    _ = @import("block/gkr_receiver_test.zig");
    _ = @import("tests/hooks_test.zig");
}
