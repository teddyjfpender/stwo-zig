//! Product composition over the canonical native execution owners.
const native = @import("stwo_riscv_frontend").runner.guest_precompile;
pub const bulk_memcpy_v1 = native.bulk_memcpy_v1;
pub const call_buffer = native.call_buffer;
pub const ethereum_v1 = @import("ethereum.zig");
pub const keccakf_call_buffer = native.keccakf_call_buffer;
pub const keccakf_v1 = native.keccakf_v1;
pub const poseidon2_v1 = native.poseidon2_v1;
pub const secp256k1_recover_call_buffer = native.secp256k1_recover_call_buffer;
pub const secp256k1_recover_v1 = native.secp256k1_recover_v1;
pub const session_state = @import("session_state.zig");
