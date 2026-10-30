//! Frozen pre-refactor V7 roster/digest oracle, test-only.
//! Opt-in v7 layout: split only lookup pairs whose original symbolic equation
//! exceeds degree four. This changes physical claims and protocol identity;
//! it does not replace the existing v6 or v7 runtime defaults.
const std = @import("std");
const core = @import("stwo_core");
const Canonical = @import("../block_v7_native_relation_layout_v1.zig");
const Source = @import("../block_v5_native_projection_fused_source_v1.zig");
const Lookup = @import("../block_v5_native_lookup_request_source_v1.zig");
const Interaction = @import("../../air/lookups/opcode_interaction.zig");
const Shape = @import("../../air/statement.zig").Blake3ExecutionStatement;
pub const VERSION: u32 = 1;
pub const Mode = enum(u32) { degree_bounded_q2_v1 = 1 };
pub const mode: Mode = .degree_bounded_q2_v1;
pub const MAX_DEGREE: u8 = 4;
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
        var slots: std.ArrayList(Source.Slot) = .empty;
        errdefer slots.deinit(a);
        var splits: usize = 0;
        for (original.slots) |slot| {
            if (slot.degree <= MAX_DEGREE) {
                try slots.append(a, slot);
                continue;
            }
            if (slot.kind != .lookup or slot.kind.lookup.source != .opcode or slot.kind.lookup.entry_count != 2) return error.UnsupportedDegreeBoundedRelation;
            const lookup = slot.kind.lookup;
            var plan = try Interaction.Plan.initForRecipe(a, lookup.source.opcode, shape.localZeroCustody());
            defer plan.deinit();
            const degrees = try Lookup.nodeDegrees(a, plan);
            defer a.free(degrees);
            if (try symbolicDegree(lookup, plan, degrees) != slot.degree) return error.InvalidDegreeBoundedSource;
            for (lookup.entries) |ordinal| {
                var single = slot;
                single.kind.lookup.entries = .{ ordinal, 0 };
                single.kind.lookup.entry_count = 1;
                const degree = try symbolicDegree(single.kind.lookup, plan, degrees);
                if (degree > MAX_DEGREE) return error.UnsupportedDegreeBoundedRelation;
                single.degree = degree;
                single.kind.lookup.degree = degree;
                try slots.append(a, single);
            }
            splits += 1;
        }
        var channel = core.proof_suites.Blake3.Channel{};
        channel.mixU32s(&.{ 0x42374450, VERSION, @intFromEnum(mode), MAX_DEGREE, custody });
        channel.mixRoot(original.digest);
        channel.mixU64(slots.items.len);
        for (slots.items) |slot| Source.mixSlot(&channel, slot);
        return .{ .a = a, .slots = try slots.toOwnedSlice(a), .digest = channel.digestBytes(), .split_pairs = splits };
    }
    pub fn deinit(self: *Layout) void {
        self.a.free(self.slots);
        self.* = undefined;
    }
};

/// Preserve numerator signs and the exact original space/(1-space) weight.
/// For a singleton the absent denominator is one, hence degree zero.
fn symbolicDegree(slot: Lookup.Slot, plan: Interaction.Plan, degrees: []const u32) !u8 {
    if (slot.entry_count == 0 or slot.entry_count > 2 or degrees.len != plan.program.nodes.len) return error.InvalidDegreeBoundedSource;
    var numerator: [2]u32 = @splat(0);
    var denominator: [2]u32 = @splat(0);
    for (slot.entries[0..slot.entry_count], 0..) |ordinal, i| {
        if (ordinal >= plan.program.entries.len) return error.InvalidDegreeBoundedSource;
        const entry = plan.program.entries[ordinal];
        numerator[i] = degrees[entry.numerator];
        if (slot.register_custody_mode == 1 and (slot.partition == .register_memory_access or slot.partition == .ordinary_memory_access))
            numerator[i] = try std.math.add(u32, numerator[i], degrees[entry.values[0]]);
        for (entry.values[0..entry.arity]) |value| denominator[i] = @max(denominator[i], degrees[value]);
    }
    const recurrence = try std.math.add(u32, 1, try std.math.add(u32, denominator[0], denominator[1]));
    const degree = @max(recurrence, @max(try std.math.add(u32, numerator[0], denominator[1]), try std.math.add(u32, numerator[1], denominator[0])));
    return std.math.cast(u8, degree) orelse error.InvalidDegreeBoundedSource;
}

/// Reconstruct every ordinal, weight, degree and physical position from the
/// admitted statement. Candidate slot metadata never chooses the partition.
pub fn requireCoverage(a: std.mem.Allocator, shape: *const Shape, external: u32, custody: u32, actual: []const Source.Slot) !void {
    var expected = try Layout.init(a, shape, external, custody);
    defer expected.deinit();
    if (actual.len != expected.slots.len) return error.InvalidDegreeBoundedCoverage;
    for (actual, expected.slots) |got, want| if (!std.meta.eql(got, want)) return error.InvalidDegreeBoundedCoverage;
}
