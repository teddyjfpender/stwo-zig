//! Opt-in v7 layout: split only lookup pairs whose original symbolic equation
//! exceeds degree four. This changes physical claims and protocol identity;
//! it does not replace the existing v6 or v7 runtime defaults.
const std = @import("std");
const core = @import("stwo_core");
const Canonical = @import("block_v7_native_relation_layout_v1.zig");
const Source = @import("block_v5_native_projection_fused_source_v1.zig");
const Bounded = @import("block_native_degree_bounded_splitter_v1.zig");
const Shape = @import("../air/statement.zig").Blake3ExecutionStatement;
pub const VERSION: u32 = 1;
pub const Mode = enum(u32) { degree_bounded_q2_v1 = 1 };
pub const mode: Mode = .degree_bounded_q2_v1;
pub const MAX_DEGREE: u8 = Bounded.MAX_DEGREE;
pub const Layout = struct {
    a: std.mem.Allocator,
    slots: []Source.Slot,
    digest: [32]u8,
    split_pairs: usize,
    pub fn init(a: std.mem.Allocator, shape: *const Shape, external: u32, custody: u32) !Layout {
        // Canonical v7 first constructs and validates the complete original v6
        // roster, then applies its explicit actual-event RAM disposition.
        var original = try Canonical.Layout.init(a, shape, external, custody);
        defer original.deinit();
        var bounded = try Bounded.split(a, shape, original.slots);
        errdefer bounded.deinit(a);
        var channel = core.proof_suites.Blake3.Channel{};
        channel.mixU32s(&.{ 0x42374450, VERSION, @intFromEnum(mode), MAX_DEGREE, custody });
        channel.mixRoot(original.digest);
        channel.mixU64(bounded.slots.len);
        for (bounded.slots) |slot| Source.mixSlot(&channel, slot);
        return .{ .a = a, .slots = bounded.slots, .digest = channel.digestBytes(), .split_pairs = bounded.split_pairs };
    }
    pub fn deinit(self: *Layout) void {
        self.a.free(self.slots);
        self.* = undefined;
    }
};

/// Reconstruct every ordinal, weight, degree and physical position from the
/// admitted statement. Candidate slot metadata never chooses the partition.
pub fn requireCoverage(a: std.mem.Allocator, shape: *const Shape, external: u32, custody: u32, actual: []const Source.Slot) !void {
    var expected = try Layout.init(a, shape, external, custody);
    defer expected.deinit();
    if (actual.len != expected.slots.len) return error.InvalidDegreeBoundedCoverage;
    for (actual, expected.slots) |got, want| if (!std.meta.eql(got, want)) return error.InvalidDegreeBoundedCoverage;
}
