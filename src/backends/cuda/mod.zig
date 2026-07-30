//! Resident NVIDIA CUDA backend.
//!
//! CUDA is driven by a proof-owned session, not by the generic host-slice
//! backend contract. Device columns remain opaque, all transfers are counted,
//! generated kernels are strict-AOT, and no CPU fallback API exists.

pub const abi = @import("abi/mod.zig");
pub const aot = struct {
    pub const module_globals = @import("aot/module_globals.zig");
    pub const product_registry = @import("aot/product_registry.zig");
};
pub const product_aot = aot.product_registry;
pub const runtime = @import("runtime/mod.zig");
pub const upstream_sources = struct {
    pub const poseidon_witness_round_keys =
        @embedFile("vendor/upstream/poseidon_witness_round_keys.cuh");
    pub const pedersen_table_init =
        @embedFile("vendor/upstream/pedersen_table_init.cu");
};

pub const CudaBackend = struct {
    pub const Session = runtime.NativeSession;
    pub const Context = runtime.NativeContext;
    pub const resident = true;
    pub const allows_cpu_fallback = false;
};

test "api signature: CUDA backend exposes only resident session types" {
    comptime {
        if (CudaBackend.Session != runtime.NativeSession) {
            @compileError("CUDA session type drifted from the resident runtime");
        }
        if (CudaBackend.Context != runtime.NativeContext) {
            @compileError("CUDA context type drifted from the resident runtime");
        }
    }
}

test "CUDA backend advertises only the resident fail-closed architecture" {
    const std = @import("std");
    try std.testing.expect(CudaBackend.resident);
    try std.testing.expect(!CudaBackend.allows_cpu_fallback);
    try std.testing.expect(!@hasDecl(CudaBackend, "ColumnType"));
    try std.testing.expect(!@hasDecl(CudaBackend, "fallback"));
}

test {
    _ = abi;
    _ = product_aot;
    _ = runtime;
}
