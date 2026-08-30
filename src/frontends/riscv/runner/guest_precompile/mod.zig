//! Runner-owned guest precompile execution state.

pub const call_buffer = @import("call_buffer.zig");
pub const keccakf_call_buffer = @import("keccakf_call_buffer.zig");
pub const poseidon2_v1 = @import("poseidon2_v1.zig");

test {
    _ = call_buffer;
    _ = keccakf_call_buffer;
    _ = poseidon2_v1;
}
