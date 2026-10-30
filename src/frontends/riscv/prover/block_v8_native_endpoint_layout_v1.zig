//! Experimental endpoint-local RAM relation roster. Unlike V7 actual-event
//! RAM, this restores the clock-gap RAM projections: they are required for
//! native MemoryAccess chains to telescope into source/address endpoints.
//! No production route currently selects this layout.
const std = @import("std");
const core = @import("stwo_core");
const Full = @import("block_v6_relation_layout_v1.zig");
const Source = @import("block_v5_native_projection_fused_source_v1.zig");
const Bounded = @import("block_native_degree_bounded_splitter_v1.zig");
const Shape = @import("../air/statement.zig").Blake3ExecutionStatement;
pub const VERSION: u32 = 2;
pub const MAX_DEGREE: u8 = Bounded.MAX_DEGREE;
pub const production_active = false;
pub const Layout = struct {
    a: std.mem.Allocator,
    slots: []Source.Slot,
    digest: [32]u8,
    split_pairs: usize,
    pub fn init(a: std.mem.Allocator, shape: *const Shape, external_retirements: u32) !Layout {
        // A batched caller can interleave with native RAM. Until its local
        // address/clock conversion is proved, no source may claim it happened
        // entirely before or after the native source's endpoint transition.
        if (shape.native_shard_version != 0) return error.UnsupportedEndpointNativeGeometry;
        if (external_retirements != 0) return error.UnsupportedEndpointCallerInterleaving;
        var full = try Full.Layout.init(a, shape, 0, 1);
        defer full.deinit();
        var bounded = try Bounded.split(a, shape, full.slots);
        errdefer bounded.deinit(a);
        // Full.Layout independently validated every typed entry, space
        // weight and clock-gap effect before this exact pair refinement.
        // Its old requireCoverage deliberately pins the UNSPLIT physical
        // roster, so candidates use this protocol's exact reconstruction below.
        var channel = core.proof_suites.Blake3.Channel{};
        channel.mixU32s(&.{ 0x42384e4c, VERSION, 1, MAX_DEGREE, @intCast(bounded.slots.len) });
        channel.mixRoot(full.digest);
        for (bounded.slots) |slot| Source.mixSlot(&channel, slot);
        return .{ .a = a, .slots = bounded.slots, .digest = channel.digestBytes(), .split_pairs = bounded.split_pairs };
    }
    pub fn deinit(self: *Layout) void {
        self.a.free(self.slots);
        self.* = undefined;
    }
};
/// Exact independently reconstructed order, ordinals, partition weights and
/// geometry. A V7 omission roster, duplicate or re-ordered claim is rejected.
pub fn requireCoverage(a: std.mem.Allocator, shape: *const Shape, external_retirements: u32, actual: []const Source.Slot) !void {
    var expected = try Layout.init(a, shape, external_retirements);
    defer expected.deinit();
    if (expected.slots.len != actual.len) return error.InvalidEndpointNativeCoverage;
    for (actual, expected.slots) |got, want| if (!std.meta.eql(got, want)) return error.InvalidEndpointNativeCoverage;
}
