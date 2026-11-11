//! Independent fixed fixture; never a production acceptance authority.
const K = @import("stwo_riscv_frontend").rv64_air.crypto.keccak_sponge;
pub fn call() K.types.Call {
    var result = K.types.Call{ .pointer = 0x4000, .epoch = 1, .tick = 4, .packet = undefined, .state = undefined };
    for (&result.packet, [_]u64{ 0x8000, 0x9000, 0, K.types.Native.FINALIZE | K.types.Native.FRESH }) |*s, v| s.* = .{ .value = v, .epoch = 0, .tick = 0, .rights = 3 };
    for (&result.state) |*s| s.* = .{ .value = 0, .epoch = 0, .tick = 0, .rights = 3 };
    return result;
}
