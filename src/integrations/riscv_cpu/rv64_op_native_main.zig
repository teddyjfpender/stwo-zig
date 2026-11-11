//! Explicit experimental OP-native pure-P2 block producer/fresh receiver.
pub fn main() !void {
    try @import("poseidon2_outer/pure_p2_op_runtime.zig").main();
}
