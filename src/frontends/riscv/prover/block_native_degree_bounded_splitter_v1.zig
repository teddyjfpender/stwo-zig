//! Shared exact degree-four partition refinement. This is structural code,
//! not admission authority: callers independently derive their complete source
//! roster and bind the resulting physical slot order into their own protocol.
const std = @import("std");
const Source = @import("block_v5_native_projection_fused_source_v1.zig");
const Lookup = @import("block_v5_native_lookup_request_source_v1.zig");
const Interaction = @import("../air/lookups/opcode_interaction.zig");
const Shape = @import("../air/statement.zig").Blake3ExecutionStatement;
pub const MAX_DEGREE: u8 = 4;
pub const Split = struct {
    slots: []Source.Slot,
    split_pairs: usize,
    pub fn deinit(self: *Split, a: std.mem.Allocator) void {
        a.free(self.slots);
        self.* = undefined;
    }
};
pub fn split(a: std.mem.Allocator, shape: *const Shape, original: []const Source.Slot) !Split {
    var slots: std.ArrayList(Source.Slot) = .empty;
    errdefer slots.deinit(a);
    var splits: usize = 0;
    for (original) |slot| {
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
    return .{ .slots = try slots.toOwnedSlice(a), .split_pairs = splits };
}

pub fn symbolicDegree(slot: Lookup.Slot, plan: Interaction.Plan, degrees: []const u32) !u8 {
    if (slot.entry_count == 0 or slot.entry_count > 2 or degrees.len != plan.program.nodes.len) return error.InvalidDegreeBoundedSource;
    var numerator: [2]u32 = @splat(0);
    var denominator: [2]u32 = @splat(0);
    for (slot.entries[0..slot.entry_count], 0..) |ordinal, i| {
        if (ordinal >= plan.program.entries.len) return error.InvalidDegreeBoundedSource;
        const entry = plan.program.entries[ordinal];
        numerator[i] = degrees[entry.numerator];
        if (slot.direct_ram_clock_v3 and (ordinal == 10 or ordinal == 13)) {
            if (slot.source != .opcode or slot.source.opcode != .load_store)
                return error.InvalidDirectRamClockProjection;
            const access_index: usize = if (ordinal == 10) 8 else 11;
            numerator[i] = try std.math.add(u32, numerator[i], degrees[plan.program.entries[access_index].values[0]]);
        }
        if (slot.register_custody_mode == 1 and (slot.partition == .register_memory_access or slot.partition == .ordinary_memory_access))
            numerator[i] = try std.math.add(u32, numerator[i], degrees[entry.values[0]]);
        for (entry.values[0..entry.arity]) |value| denominator[i] = @max(denominator[i], degrees[value]);
    }
    const recurrence = try std.math.add(u32, 1, try std.math.add(u32, denominator[0], denominator[1]));
    const degree = @max(recurrence, @max(try std.math.add(u32, numerator[0], denominator[1]), try std.math.add(u32, numerator[1], denominator[0])));
    return std.math.cast(u8, degree) orelse error.InvalidDegreeBoundedSource;
}
