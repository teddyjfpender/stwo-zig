//! Runner-owned guest precompile execution state.

pub const call_buffer = @import("stwo_riscv_precompiles").runner.call_buffer;
pub const bulk_memcpy_v1 = @import("stwo_riscv_rv32").execution.guest_precompile.bulk_memcpy;
pub const ethereum_v1 = @import("ethereum.zig");
pub const keccakf_call_buffer = @import("stwo_riscv_precompiles").runner.keccakf_call_buffer;
pub const keccakf_v1 = @import("stwo_riscv_rv32").execution.guest_precompile.keccakf;
pub const poseidon2_v1 = @import("stwo_riscv_rv32").execution.guest_precompile.poseidon2;
pub const secp256k1_recover_call_buffer = @import("stwo_riscv_precompiles").runner.secp256k1_recover_call_buffer;
pub const secp256k1_recover_v1 = @import("stwo_riscv_rv32").execution.guest_precompile.secp256k1_recover;
pub const session_state = @import("session_state.zig");

test {
    _ = call_buffer;
    _ = bulk_memcpy_v1;
    _ = ethereum_v1;
    _ = keccakf_call_buffer;
    _ = keccakf_v1;
    _ = poseidon2_v1;
    _ = secp256k1_recover_call_buffer;
    _ = secp256k1_recover_v1;
    _ = session_state;
}
