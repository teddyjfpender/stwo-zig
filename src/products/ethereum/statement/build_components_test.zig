//! BUILD graph unit test; runtime component consumers are qualified separately.
const std = @import("std");
const construction = @import("build_components.zig");

test "component construction preserves selected modules without mutating native owners" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const directory = std.Build.Cache.Directory.cwd();
    const target = std.Build.ResolvedTarget{ .query = .{}, .result = @import("builtin").target };
    var graph = std.Build.Graph{
        .arena = a,
        .cache = .{ .gpa = a, .manifest_dir = std.fs.cwd() },
        .zig_exe = "zig",
        .env_map = std.process.EnvMap.init(a),
        .global_cache_root = directory,
        .zig_lib_directory = directory,
        .host = target,
        .time_report = false,
    };
    const b = try std.Build.create(&graph, directory, directory, &.{});
    const core = b.createModule(.{ .root_source_file = b.path("src/waist/core/mod.zig") });
    const native_front = b.createModule(.{ .root_source_file = b.path("src/frontends/riscv/mod.zig") });
    native_front.addImport("stwo_core", core);
    const native_backend = b.createModule(.{ .root_source_file = b.path("src/backends/cpu_scalar/mod.zig") });
    native_backend.addImport("stwo_core", core);
    const native_cpu = b.createModule(.{ .root_source_file = b.path("src/integrations/riscv_cpu/mod.zig") });
    native_cpu.addImport("stwo_core", core);
    native_cpu.addImport("stwo_riscv_frontend", native_front);
    native_cpu.addImport("stwo_cpu_backend", native_backend);
    const predecessors = construction.nativeCpuPredecessors(native_cpu);
    try std.testing.expect(predecessors.frontend == native_front);
    try std.testing.expect(predecessors.backend == native_backend);
    const native_cuda = b.createModule(.{ .root_source_file = b.path("src/integrations/riscv_cuda/mod.zig") });
    native_cuda.addImport("stwo_core", core);
    native_cuda.addImport("stwo_riscv_frontend", native_front);
    const front = construction.frontend(b, b.path("src/products/ethereum/statement/frontend.zig"), target, .Debug, native_front);
    const cpu = construction.cpu(b, b.path("src/products/ethereum/statement/cpu.zig"), target, .Debug, front, native_cpu);
    const cuda = construction.cuda(b, b.path("src/products/ethereum/statement/cuda.zig"), target, .Debug, front, cpu, native_cuda);
    const product = construction.primary(b, b.path("src/products/ethereum/statement/mod.zig"), target, .Debug, front, cpu, cuda);
    try std.testing.expect(front.import_table.get("stwo_riscv_frontend").? == native_front);
    try std.testing.expect(cpu.import_table.get("stwo_core").? == core);
    try std.testing.expect(cpu.import_table.get("stwo_riscv_cpu_integration").? == native_cpu);
    try std.testing.expect(cuda.import_table.get("ethereum_cpu_component").? == cpu);
    try std.testing.expect(product.import_table.get("legacy_riscv_frontend").? == front);
    try std.testing.expect(product.import_table.get("legacy_riscv_cpu_integration").? == cpu);
    try std.testing.expect(!native_front.import_table.contains("ethereum_frontend_component"));
    try std.testing.expect(!native_cpu.import_table.contains("ethereum_frontend_component"));
    // Rebinding the same owner is idempotent and cannot create another graph.
    const count = cpu.import_table.count();
    construction.bindCpu(cpu, front, native_cpu);
    try std.testing.expectEqual(count, cpu.import_table.count());
}
