//! Explicit native protocol choice. Canonical V7 keeps its exact prior layout
//! identity; the opt-in degree-bounded roster has its own versioned digest.
const std = @import("std");
const Canonical = @import("block_v7_native_relation_layout_v1.zig");
const Bounded = @import("block_v7_degree_bounded_relation_layout_v1.zig");
const Shape = @import("../air/statement.zig").Blake3ExecutionStatement;
const Source = @import("block_v5_native_projection_fused_source_v1.zig");
pub const Mode = enum(u32) { canonical_v1 = 0, degree_bounded_q2_v1 = 1 };
pub const Layout = Canonical.Layout;
pub fn derive(a: std.mem.Allocator, shape: *const Shape, external: u32, mode: Mode) !Layout {
    return switch (mode) {
        .canonical_v1 => Canonical.Layout.init(a, shape, external, 1),
        .degree_bounded_q2_v1 => blk: {
            const selected = try Bounded.Layout.init(a, shape, external, 1);
            // Transfer the exact allocated slot owner; there is no separate
            // hidden allocation or widened lifetime in the selected wrapper.
            break :blk .{ .a = selected.a, .slots = selected.slots, .digest = selected.digest };
        },
    };
}
pub fn requireCoverage(a: std.mem.Allocator, shape: *const Shape, external: u32, mode: Mode, slots: []const Source.Slot) !void {
    switch (mode) {
        .canonical_v1 => try Canonical.requireCoverage(a, shape, external, 1, slots),
        .degree_bounded_q2_v1 => try Bounded.requireCoverage(a, shape, external, 1, slots),
    }
}
