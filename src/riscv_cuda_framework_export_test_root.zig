const std = @import("std");
const Code = @import("backends/cuda/framework_polynomial_codegen_v1.zig");
test "export exact CUDA parent framework catalog" {
    const a = std.testing.allocator;
    const path = std.process.getEnvVarOwned(a, "STWO_CUDA_FRAMEWORK_EXPORT") catch return error.SkipZigTest;
    defer a.free(path);
    try @import("frontends/riscv/benchmarks/cuda_framework_catalog_v1.zig").exportCatalog(Code, a, path);
}
