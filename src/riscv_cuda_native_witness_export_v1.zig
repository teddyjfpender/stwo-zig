//! Compile with Zig's C backend, then the pinned native CUDA exporter.
comptime {
    @import("integrations/riscv_cuda/native_witness_exports_v1.zig").exportDeviceWriters();
}
