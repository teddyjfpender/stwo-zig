const std = @import("std");
test {
    std.testing.refAllDecls(@import("integrations/riscv_cuda/resident_native_ingress_v1.zig"));
}
test {
    std.testing.refAllDecls(@import("integrations/riscv_cuda/resident_native_producer_v1.zig"));
}
test {
    std.testing.refAllDecls(@import("integrations/riscv_cuda/resident_native_composition_v1.zig"));
}
test "resident native ingress oracle export" {
    const a = std.testing.allocator;
    const path = std.process.getEnvVarOwned(a, "STWO_NATIVE_INGRESS_EXPORT") catch return error.SkipZigTest;
    defer a.free(path);
    try @import("integrations/riscv_cuda/resident_native_ingress_v1.zig").exportOracle(a, path);
}
test "resident native finite kernel bundle from detached original geometry" {
    const a = std.testing.allocator;
    const path = std.process.getEnvVarOwned(a, "STWO_NATIVE_BUNDLE_EXPORT") catch return error.SkipZigTest;
    defer a.free(path);
    const p = try @import("integrations/riscv_cuda/resident_native_plan_test_v1.zig").fixture(5, a, true);
    defer p.deinit();
    var composition = try @import("integrations/riscv_cuda/resident_native_composition_v1.zig").ForCommitments(5).Plan.init(a, p, .{});
    defer composition.deinit();
    try std.testing.expect(composition.extra_bytes > 0);
    var writer: std.Io.Writer.Allocating = .init(a);
    defer writer.deinit();
    try @import("integrations/riscv_cuda/resident_native_kernel_bundle_v1.zig").emit(5, a, &writer.writer, p);
    var file = try std.fs.cwd().createFile(path, .{});
    defer file.close();
    try file.writeAll(writer.written());
}
