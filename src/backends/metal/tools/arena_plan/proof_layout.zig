//! Proof-layout derivation from admitted arena bindings.

const std = @import("std");
const stwo = @import("stwo");
const arena = stwo.backends.metal.arena_plan;
const arena_binding_mod = stwo.integrations.cairo_metal.arena_binding;

pub fn transcriptInputBinding(
    bindings: *const arena_binding_mod.PreparedProofBindings,
    wanted_ordinal: u32,
) !arena.Binding {
    for (bindings.transcript_inputs) |input| if (input.ordinal == wanted_ordinal) return input.binding;
    return error.MissingTranscriptInput;
}

pub fn bindingDegreeLogs(allocator: std.mem.Allocator, bindings: []const arena.Binding) ![]u32 {
    const logs = try allocator.alloc(u32, bindings.len);
    errdefer allocator.free(logs);
    for (bindings, logs) |binding, *log_size| {
        if (binding.size_bytes == 0 or binding.size_bytes % 4 != 0 or
            !std.math.isPowerOfTwo(binding.size_bytes / 4))
            return error.InvalidProofLayout;
        log_size.* = std.math.log2_int(u64, binding.size_bytes / 4);
    }
    return logs;
}

test "degree logs derive from canonical word capacities" {
    const empty_ticks = [_]u64{0} ** (arena.max_ticks / 64);
    const bindings = [_]arena.Binding{
        .{ .logical_id = 0, .slot = 0, .offset_bytes = 0, .size_bytes = 16, .materialization = .resident, .occupied = empty_ticks },
        .{ .logical_id = 1, .slot = 1, .offset_bytes = 16, .size_bytes = 32, .materialization = .resident, .occupied = empty_ticks },
    };
    const logs = try bindingDegreeLogs(std.testing.allocator, &bindings);
    defer std.testing.allocator.free(logs);
    try std.testing.expectEqualSlices(u32, &.{ 2, 3 }, logs);

    const invalid = [_]arena.Binding{
        .{ .logical_id = 0, .slot = 0, .offset_bytes = 0, .size_bytes = 12, .materialization = .resident, .occupied = empty_ticks },
    };
    try std.testing.expectError(error.InvalidProofLayout, bindingDegreeLogs(std.testing.allocator, &invalid));
}
