//! Validated resident-arena binding address conversion.

const std = @import("std");
const arena_plan = @import("stwo_metal_backend").arena_plan;
const Error = @import("errors.zig").Error;

pub fn wordOffset(binding: arena_plan.Binding) !u32 {
    if (binding.offset_bytes % @sizeOf(u32) != 0) return Error.InvalidBindingSize;
    return std.math.cast(u32, binding.offset_bytes / @sizeOf(u32)) orelse Error.InvalidBindingSize;
}

test "metal: resident word offsets require aligned representable bindings" {
    var binding: arena_plan.Binding = undefined;
    binding.offset_bytes = 16;
    try std.testing.expectEqual(@as(u32, 4), try wordOffset(binding));

    binding.offset_bytes = 2;
    try std.testing.expectError(Error.InvalidBindingSize, wordOffset(binding));

    binding.offset_bytes = (@as(u64, std.math.maxInt(u32)) + 1) * @sizeOf(u32);
    try std.testing.expectError(Error.InvalidBindingSize, wordOffset(binding));
}
