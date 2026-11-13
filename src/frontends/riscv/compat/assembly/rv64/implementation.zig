const native = @import("stwo_riscv_rv64").execution;
pub const profile = native.profile;
pub const decode = native.decode;
pub const memory = native.memory;
pub const machine = native.machine;
pub const elf = native.elf;
pub const Session = native.Session;
pub const Word = native.Word;
pub const csp_contract = native.csp_contract;
pub const execution_profile = native.execution_profile;
pub const services = native.services;
pub const compact_tape = native.compact_tape;
pub const compact_tape_wire = native.compact_tape_wire;
pub const boundary_capture = native.boundary_capture;
pub const fast_execution = native.fast_execution;
pub const ram_word_set = native.ram_word_set;
pub const checkpoint = native.checkpoint;

pub const arith256_mod = @import("stwo_riscv_rv64").arith256_mod;
pub const secp256k1_rcb = @import("stwo_riscv_rv64").secp256k1_rcb;
pub const sha256_compression = @import("stwo_riscv_rv64").sha256_compression;

/// Canonical captured-call ABI; execution/admission policy remains product-owned.
pub const service_calls = @import("stwo_riscv_rv64").service_calls;
