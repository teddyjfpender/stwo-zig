//! Runner-owned guest precompile execution state.

pub const call_buffer = @import("call_buffer.zig");
pub const bulk_memcpy_call_buffer_v1 = @import("bulk_memcpy_call_buffer_v1.zig");
pub const bulk_memcpy_session_tape_v1 = @import("bulk_memcpy_session_tape_v1.zig");
pub const bulk_memcpy_v1 = @import("bulk_memcpy_v1.zig");
pub const ethereum_v1 = @import("ethereum_v1.zig");
pub const keccakf_call_buffer = @import("keccakf_call_buffer.zig");
pub const keccakf_v1 = @import("keccakf_v1.zig");
pub const poseidon2_v1 = @import("poseidon2_v1.zig");
pub const secp256k1_recover_call_buffer = @import("secp256k1_recover_call_buffer.zig");
pub const secp256k1_recover_v1 = @import("secp256k1_recover_v1.zig");
pub const session_state = @import("session_state.zig");

test {
    _ = call_buffer;
    _ = bulk_memcpy_call_buffer_v1;
    _ = bulk_memcpy_session_tape_v1;
    _ = bulk_memcpy_v1;
    _ = ethereum_v1;
    _ = keccakf_call_buffer;
    _ = keccakf_v1;
    _ = poseidon2_v1;
    _ = secp256k1_recover_call_buffer;
    _ = secp256k1_recover_v1;
    _ = session_state;
}
