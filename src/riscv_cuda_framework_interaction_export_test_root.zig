const std = @import("std");
const Base = @import("backends/cuda/framework_polynomial_codegen_v1.zig");
const Code = @import("backends/cuda/framework_interaction_codegen_v1.zig");
test "export exact CUDA parent interaction catalog" {
    const a = std.testing.allocator;
    const path = std.process.getEnvVarOwned(a, "STWO_CUDA_FRAMEWORK_INTERACTION_EXPORT") catch return error.SkipZigTest;
    defer a.free(path);
    try @import("frontends/riscv/benchmarks/cuda_framework_interaction_catalog_v1.zig").exportCatalog(Base, Code, a, path);
}
