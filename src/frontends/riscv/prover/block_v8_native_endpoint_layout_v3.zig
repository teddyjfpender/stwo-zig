//! Explicit direct-RAM-clock profile. Legacy VERSION2 is reconstructed first;
//! only the two reviewed typed load/store R20 numerators are refined.
const std = @import("std");
const core = @import("stwo_core");
const Old = @import("block_v8_native_endpoint_layout_v1.zig");
const Source = @import("block_v5_native_projection_fused_source_v1.zig");
const Lookup = @import("block_v5_native_lookup_request_source_v1.zig");
const Bounded = @import("block_native_degree_bounded_splitter_v1.zig");
const Interaction = @import("../air/lookups/opcode_interaction.zig");
const Shape = @import("../air/statement.zig").Blake3ExecutionStatement;
pub const VERSION: u32 = 3;
pub const production_active = false;
pub fn init(a: std.mem.Allocator, shape: *const Shape, external: u32) !Old.Layout {
    if (external != 0 or shape.localZeroCustody()) return error.UnsupportedDirectRamClockProfile;
    _ = try @import("block_v8_ram_clock_v3_kernel.zig").Policy.fromCycles(shape.public_data.clock);
    var old = if (shape.native_shard_version == 0) try Old.Layout.init(a, shape, external) else try wideBase(a, shape, external);
    defer old.deinit();
    const nominated = try a.dupe(Source.Slot, old.slots);
    defer a.free(nominated);
    for (nominated) |*slot| {
        if (slot.kind != .lookup or slot.kind.lookup.source != .opcode or slot.kind.lookup.source.opcode != .load_store) continue;
        slot.kind.lookup.direct_ram_clock_v3 = true;
        var plan = try Interaction.Plan.initForRecipe(a, .load_store, false);
        defer plan.deinit();
        const degrees = try Lookup.nodeDegrees(a, plan);
        defer a.free(degrees);
        const degree = try Bounded.symbolicDegree(slot.kind.lookup, plan, degrees);
        slot.degree = degree;
        slot.kind.lookup.degree = degree;
    }
    var bounded = try Bounded.split(a, shape, nominated);
    errdefer bounded.deinit(a);
    var channel = core.proof_suites.Blake3.Channel{};
    channel.mixU32s(&.{ 0x42384e33, VERSION, Bounded.MAX_DEGREE, @intCast(bounded.slots.len) });
    if (shape.native_shard_version != 0) channel.mixU32s(&.{ 0x4e575334, 4 });
    channel.mixRoot(old.digest);
    for (bounded.slots) |slot| Source.mixSlot(&channel, slot);
    return .{ .a = a, .slots = bounded.slots, .digest = channel.digestBytes(), .split_pairs = old.split_pairs + bounded.split_pairs };
}
pub fn requireCoverage(a: std.mem.Allocator, shape: *const Shape, actual: []const Source.Slot) !void {
    var expected = try init(a, shape, 0);
    defer expected.deinit();
    if (actual.len != expected.slots.len) return error.InvalidDirectRamClockCoverage;
    for (actual, expected.slots) |got, want| if (!std.meta.eql(got, want)) return error.InvalidDirectRamClockCoverage;
}

fn wideBase(a: std.mem.Allocator, shape: *const Shape, external: u32) !Old.Layout {
    if (shape.native_shard_version != 1 or external != 0) return error.UnsupportedDirectRamClockProfile;
    var full = try @import("block_v6_relation_layout_v1.zig").Layout.init(a, shape, 0, 1);
    defer full.deinit();
    var bounded = try Bounded.split(a, shape, full.slots);
    errdefer bounded.deinit(a);
    var channel = core.proof_suites.Blake3.Channel{};
    channel.mixU32s(&.{ 0x42384e4c, 2, 1, Bounded.MAX_DEGREE, @intCast(bounded.slots.len) });
    channel.mixRoot(full.digest);
    for (bounded.slots) |slot| Source.mixSlot(&channel, slot);
    return .{ .a = a, .slots = bounded.slots, .digest = channel.digestBytes(), .split_pairs = bounded.split_pairs };
}
