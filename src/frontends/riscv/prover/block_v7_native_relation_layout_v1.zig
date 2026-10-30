//! V7 actual-event RAM policy. Original opcode/register/range equations retain
//! complete symbolic coverage. RAM-only synthetic clock-gap projections have no
//! consumer: actual RAM continuity is independently closed by the WORD bus.
//! This is a distinct layout identity, never a weakened V6 coverage validator.
const std = @import("std");
const core = @import("stwo_core");
const Original = @import("block_v6_relation_layout_v1.zig");
const Source = @import("block_v5_native_projection_fused_source_v1.zig");
const Shape = @import("../air/statement.zig").Blake3ExecutionStatement;
pub const VERSION: u32 = 1;
pub const Policy = enum(u32) { actual_event_ram_v1 = 1 };
pub const policy: Policy = .actual_event_ram_v1;
fn omitted(slot: Source.Slot) bool {
    return switch (slot.kind) {
        .program => false,
        .lookup => |lookup| std.meta.activeTag(lookup.source) == .clock and lookup.partition == .clock_memory_access and lookup.register_custody_mode == 1,
    };
}
pub const Layout = struct {
    a: std.mem.Allocator,
    slots: []Source.Slot,
    digest: [32]u8,
    pub fn init(a: std.mem.Allocator, shape: *const Shape, external: u32, mode: u32) !Layout {
        if (mode != 1) return error.InvalidV7RelationCustodyMode;
        var full = try Original.Layout.init(a, shape, external, mode);
        defer full.deinit();
        var result: std.ArrayList(Source.Slot) = .empty;
        errdefer result.deinit(a);
        for (full.slots) |slot| if (!omitted(slot)) try result.append(a, slot);
        try requireFromCanonical(full.slots, result.items);
        var channel = core.proof_suites.Blake3.Channel{};
        channel.mixU32s(&.{ 0x42374c59, VERSION, @intFromEnum(policy), mode, @intCast(result.items.len) });
        channel.mixRoot(full.digest);
        for (result.items) |slot| Source.mixSlot(&channel, slot);
        return .{ .a = a, .slots = try result.toOwnedSlice(a), .digest = channel.digestBytes() };
    }
    pub fn deinit(self: *Layout) void {
        self.a.free(self.slots);
        self.* = undefined;
    }
};
/// Independent exact typed coverage. The complete old schedule is constructed
/// and validated first, then only the explicitly replaced RAM ghost route is
/// absent. In particular no caller-provided omission set is accepted.
pub fn requireCoverage(a: std.mem.Allocator, shape: *const Shape, external: u32, mode: u32, slots: []const Source.Slot) !void {
    if (mode != 1) return error.InvalidV7RelationCustodyMode;
    var full = try Original.Layout.init(a, shape, external, mode);
    defer full.deinit();
    try requireFromCanonical(full.slots, slots);
}
fn requireFromCanonical(full: []const Source.Slot, actual: []const Source.Slot) !void {
    var next: usize = 0;
    for (full) |slot| {
        if (omitted(slot)) continue;
        if (next >= actual.len or !std.meta.eql(slot, actual[next])) return error.InvalidV7RelationCoverage;
        next += 1;
    }
    if (next != actual.len) return error.InvalidV7RelationCoverage;
}
