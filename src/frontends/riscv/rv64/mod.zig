//! Canonical typed domain interfaces; test hooks are explicitly unstable.

pub const arith256_mod = @import("stwo_riscv_precompiles").primitives.arith256;
pub const secp256k1_rcb = @import("stwo_riscv_precompiles").primitives.secp256k1;
pub const sha256_compression = @import("stwo_riscv_precompiles").primitives.sha256;
pub const access_census = @import("access_census.zig");
pub const air = struct {
    pub const api = @import("air/mod.zig");
    pub const memory = struct {
        pub const image = @import("air/memory/image.zig");
    };
};
pub const candidate_isa = @import("candidate_isa.zig");
pub const compact_tape_wire = @import("compact_tape_wire.zig");
pub const decode_cache = @import("decode_cache.zig");
pub const elf = @import("elf.zig");
pub const execution = @import("execution.zig");
pub const execution_profile = @import("execution_profile.zig");
pub const frequent_operations = @import("frequent_operations.zig");
pub const machine = @import("machine.zig");
pub const memory = @import("memory.zig");
pub const service_calls = @import("services/call_abi.zig");
pub const service_session = @import("service_session.zig");
pub const session = @import("session.zig");
pub const testing = struct {
    /// Honest native AIR fixtures for cross-package reference agreement.
    pub const bulk_memory = @import("air/delegations/bulk_memory/tests.zig");
    pub const inventory_source = @embedFile("tests/root.zig");
};

test {
    _ = @import("tests/root.zig");
}
