//! SHA compression extension contract. Activation requires its combined profile,
//! CPU/memory caller AIR and declared-program admission; base profiles reject it.
const std = @import("std");
// Canonical CPU leaf, source artifact and recursive custody gates are qualified.
// Admission remains restricted to the explicit Ethereum/SHA executable profile.
pub const production_active = true;
pub const proof_opcode_id: u32 = 50; // 48/49 belong to memcpy/stack-swap contracts.
pub const fixed_word: u32 = 0x0c00_000b;
pub const state_words = 8;
pub const block_words = 16;
pub const Decoded = struct { state_register: u5, block_register: u5 };
pub fn encode(state_register: u5, block_register: u5) u32 {
    return fixed_word | (@as(u32, state_register) << 15) | (@as(u32, block_register) << 20);
}
pub fn decode(word: u32) !Decoded {
    const state: u5 = @truncate(word >> 15);
    const block: u5 = @truncate(word >> 20);
    if (word != encode(state, block)) return error.InvalidShaEncoding;
    return .{ .state_register = state, .block_register = block };
}
test "SHA compression encoding preserves both registers and rejects reserved bits" {
    for (0..32) |s| for (0..32) |b| {
        const decoded = try decode(encode(@intCast(s), @intCast(b)));
        try std.testing.expectEqual(s, decoded.state_register);
        try std.testing.expectEqual(b, decoded.block_register);
    };
    for (0..32) |i| {
        const bit: u32 = @as(u32, 1) << @intCast(i);
        if (bit & 0x01ff8000 != 0) continue;
        try std.testing.expectError(error.InvalidShaEncoding, decode(encode(3, 7) ^ bit));
    }
}
