//! Compare the packed trusted selector grammar with its byte representation.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const Packed = @import("../../air/block/word_memory_fixed_v5.zig");
const Legacy = @import("../../air/block/memory_component_trace.zig");
const Word = @import("../../air/block/word_memory_trace_v5.zig");
const Claim = @import("../../air/block/memory_component.zig").Claim;
const Event = @import("../../air/block/memory_transition.zig").Transition;

test "word fixed12 preserves byte selectors and full u64 ordinal boundaries" {
    const a = std.testing.allocator;
    const first = Event{ .space = 1, .address = 0x2000, .clock = 2, .before = 5, .after = 6 };
    const last = Event{ .space = 1, .address = 0x2008, .clock = 4, .before = 7, .after = 8 };
    const prior = Event{ .space = 1, .address = 0x1ffc, .clock = 1, .before = 4, .after = 5 };
    for ([_]u64{ 0, 65534, 0xffff_fffe, std.math.maxInt(u64) - 3 }) |start| {
        for ([_]bool{ false, true }) |terminal| {
            if (start == std.math.maxInt(u64) - 3 and !terminal) continue;
            const claim = Claim{ .first_row = start, .total_rows = start + 3 + @as(u64, if (terminal) 0 else 2), .rows = 3, .log_size = 3, .first = first, .last = last, .preceding = if (start == 0) null else prior };
            var original = try Legacy.FixedTrace.init(a, claim);
            defer original.deinit();
            var reduced = try Packed.Trace.init(a, claim);
            defer reduced.deinit();
            try std.testing.expectEqual(@as(usize, 12 * 8), reduced.storage.len);
            for (0..8) |at| {
                var cells: [Packed.COLUMN_COUNT]Q = undefined;
                for (&cells, 0..) |*cell, i| cell.* = Q.fromBase(reduced.column(i)[at]);
                const fixed = Word.fixedPoint(cells, claim);
                inline for (.{ .{ "active", Legacy.fixed.active }, .{ "first", Legacy.fixed.first }, .{ "last", Legacy.fixed.last }, .{ "global_first", Legacy.fixed.global_first }, .{ "global_last", Legacy.fixed.global_last }, .{ "domain_last", Legacy.fixed.domain_last } }) |field| {
                    try std.testing.expectEqual(Q.fromBase(original.column(field[1])[at]), @field(fixed, field[0]));
                }
                for (0..4) |i| {
                    const radix = M.fromCanonical(256);
                    const ordinal = original.column(Legacy.fixed.ordinal + 2 * i)[at].add(original.column(Legacy.fixed.ordinal + 2 * i + 1)[at].mul(radix));
                    const previous = original.column(Legacy.fixed.previous_ordinal + 2 * i)[at].add(original.column(Legacy.fixed.previous_ordinal + 2 * i + 1)[at].mul(radix));
                    try std.testing.expectEqual(Q.fromBase(ordinal), fixed.ordinal[i]);
                    try std.testing.expectEqual(Q.fromBase(previous), fixed.previous_ordinal[i]);
                }
            }
        }
    }
}
