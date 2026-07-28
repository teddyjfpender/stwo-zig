//! Package-owned frontend/backend composition modules.

const std = @import("std");
const graph = @import("modules.zig");

pub fn addRiscVCpuStack(
    b: *std.Build,
    protocol: graph.ProtocolModules,
    product: graph.Product,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    consumer: *std.Build.Module,
) void {
    const cpu_backend = graph.addCpuBackendImport(
        b,
        protocol,
        product,
        target,
        optimize,
        consumer,
    );
    const riscv_frontend = graph.addRiscVFrontendImport(
        b,
        protocol,
        product,
        target,
        optimize,
        consumer,
    );
    _ = addRiscVCpuImport(
        b,
        protocol,
        product,
        target,
        optimize,
        cpu_backend,
        riscv_frontend,
        consumer,
    );
}

pub fn addRiscVCpuImport(
    b: *std.Build,
    protocol: graph.ProtocolModules,
    product: graph.Product,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    cpu_backend: *std.Build.Module,
    riscv_frontend: *std.Build.Module,
    consumer: *std.Build.Module,
) *std.Build.Module {
    const integration = graph.create(b, .{
        .product = product,
        .root_source_file = "src/integrations/riscv_cpu/mod.zig",
        .target = target,
        .optimize = optimize,
    });
    integration.addImport("stwo_core", protocol.core);
    integration.addImport("stwo_prover_impl", protocol.prover);
    integration.addImport("stwo_cpu_backend", cpu_backend);
    integration.addImport("stwo_riscv_frontend", riscv_frontend);
    consumer.addImport("stwo_riscv_cpu_integration", integration);
    return integration;
}

pub fn addCairoCpuStack(
    b: *std.Build,
    protocol: graph.ProtocolModules,
    product: graph.Product,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    consumer: *std.Build.Module,
) void {
    const cpu_backend = graph.addCpuBackendImport(
        b,
        protocol,
        product,
        target,
        optimize,
        consumer,
    );
    const cairo_frontend = graph.addCairoFrontendImport(
        b,
        protocol,
        product,
        target,
        optimize,
        consumer,
    );
    _ = addCairoCpuImport(
        b,
        protocol,
        product,
        target,
        optimize,
        cpu_backend,
        cairo_frontend,
        consumer,
    );
}

pub fn addCairoCpuImport(
    b: *std.Build,
    protocol: graph.ProtocolModules,
    product: graph.Product,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    cpu_backend: *std.Build.Module,
    cairo_frontend: *std.Build.Module,
    consumer: *std.Build.Module,
) *std.Build.Module {
    const integration = graph.create(b, .{
        .product = product,
        .root_source_file = "src/integrations/cairo_cpu/mod.zig",
        .target = target,
        .optimize = optimize,
    });
    integration.addImport("stwo_core", protocol.core);
    integration.addImport("stwo_prover_impl", protocol.prover);
    integration.addImport("stwo_cpu_backend", cpu_backend);
    integration.addImport("stwo_cairo_frontend", cairo_frontend);
    consumer.addImport("stwo_cairo_cpu_integration", integration);
    return integration;
}
