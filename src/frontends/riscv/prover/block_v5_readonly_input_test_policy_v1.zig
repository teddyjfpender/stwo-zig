//! Shared independent literal public-input/source policy for nonproving tests.
const std = @import("std");
const Sources = @import("block_v5_initial_sources_v1.zig");
const Selection = @import("block_v5_readonly_input_selection_v1.zig");
pub const base: u32 = 0x800000;
pub const input = [_]u8{ 7, 0, 0, 0, 9, 8, 7 };
pub const selected = [_]u32{base};
pub fn sources() !Sources.Pins {
    const Tree = @import("../air/memory_commitment/blake3_state_tree.zig");
    const leaves = [_]Tree.Leaf{ .{ .index = base / 4, .value = 7 }, .{ .index = base / 4 + 1, .value = 0x070809 } };
    var words: [16]u8 = undefined;
    inline for (0..2) |i| {
        std.mem.writeInt(u32, words[i * 8 ..][0..4], base + i * 4, .little);
        std.mem.writeInt(u32, words[i * 8 + 4 ..][0..4], leaves[i].value, .little);
    }
    var touch: [9]u8 = undefined;
    touch[0] = 1;
    std.mem.writeInt(u32, touch[1..5], base + 4, .little);
    std.mem.writeInt(u32, touch[5..9], leaves[1].value, .little);
    return .{ .layout = .{ .program_base = 0x1000, .program_end = 0x2000, .data_base = base, .data_end = base + 4096, .stack_bottom = 0, .stack_top = 0, .io_base = 0, .io_end = 0, .input_base = base, .input_end = base + 16, .output_len_addr = base + 32, .output_data_addr = base + 36, .output_base = base + 32, .output_end = base + 128 }, .initial_rw_root = (try Tree.TreeHasher.init(.memory).root(&leaves)).bytes, .initial_registers = @splat(0), .public_input_sha256 = Sources.sha256(&input), .public_input_len = input.len, .input_words = .{ .sha256 = Sources.sha256(&words), .records = 2 }, .rw_words = .{ .sha256 = Sources.sha256(&.{}), .records = 0 }, .first_touches = .{ .sha256 = Sources.sha256(&touch), .records = 1 } };
}
pub fn selection(a: std.mem.Allocator, actual: Sources.Pins) !Selection.Owned {
    return Selection.derive(a, try Selection.Authority.fromSources(actual), &input, &selected, .{});
}
pub fn pins(owned: *const Selection.Owned) Selection.Pins {
    return .{ .authority = owned.authority, .addresses = owned.addresses, .expected_digest = owned.digest, .limits = owned.limits };
}
