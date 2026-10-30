//! Explicit mixed-source layout. Existing native-only endpoint layout keeps
//! rejecting callers. This new identity restores every native RAM-clock edge
//! while admitting an independently bound external-retirement census.
const std = @import("std");
const core = @import("stwo_core");
const Old = @import("block_v8_native_endpoint_layout_v1.zig");
const Full = @import("block_v6_relation_layout_v1.zig");
const Bounded = @import("block_native_degree_bounded_splitter_v1.zig");
const Source = @import("block_v5_native_projection_fused_source_v1.zig");
const Shape = @import("../air/statement.zig").Blake3ExecutionStatement;
pub const production_active = false;
pub fn init(a: std.mem.Allocator, shape: *const Shape, external: u32) !Old.Layout {
    if (external == 0) return error.EmptyMixedCallerInventory;
    if (@import("block_v5_native_frame_v1.zig").required(shape)) return error.UnqualifiedMixedCallerOnlyFrame;
    var full = try Full.Layout.init(a, shape, external, 1);
    defer full.deinit();
    var bounded = try Bounded.split(a, shape, full.slots);
    errdefer bounded.deinit(a);
    var ch = core.proof_suites.Blake3.Channel{};
    ch.mixU32s(&.{ 0x42384d4c, 1, external, Bounded.MAX_DEGREE, @intCast(bounded.slots.len) });
    ch.mixRoot(full.digest);
    for (bounded.slots) |slot| Source.mixSlot(&ch, slot);
    return .{ .a = a, .slots = bounded.slots, .digest = ch.digestBytes(), .split_pairs = bounded.split_pairs };
}
