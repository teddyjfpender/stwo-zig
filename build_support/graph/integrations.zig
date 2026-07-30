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
    integration.addImport("stwo_prover_api", protocol.prover_api);
    integration.addImport("stwo_prover_engine", protocol.prover);
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
    integration.addImport("stwo_prover_api", protocol.prover_api);
    integration.addImport("stwo_prover_engine", protocol.prover);
    integration.addImport("stwo_cpu_backend", cpu_backend);
    integration.addImport("stwo_cairo_frontend", cairo_frontend);
    consumer.addImport("stwo_cairo_cpu_integration", integration);
    return integration;
}

pub fn addCairoMetalImport(
    b: *std.Build,
    protocol: graph.ProtocolModules,
    product: graph.Product,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    metal_backend: *std.Build.Module,
    cairo_frontend: *std.Build.Module,
    metal_session: *std.Build.Module,
    consumer: *std.Build.Module,
) *std.Build.Module {
    const integration = graph.create(b, .{
        .product = product,
        .root_source_file = "src/integrations/cairo_metal/mod.zig",
        .target = target,
        .optimize = optimize,
    });
    protocol.addImports(integration);
    integration.addImport("stwo_metal_backend", metal_backend);
    integration.addImport("stwo_cairo_frontend", cairo_frontend);
    integration.addImport("stwo_metal_session", metal_session);
    consumer.addImport("stwo_cairo_metal_integration", integration);
    return integration;
}

/// Constructs the Native AIR to CUDA backend composition against the exact
/// protocol, backend, example, and proof-wire package modules selected by the
/// enclosing product.
pub fn createNativeCuda(
    b: *std.Build,
    protocol: graph.ProtocolModules,
    product: graph.Product,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    cuda_backend: *std.Build.Module,
    native_examples: *std.Build.Module,
    proof_wire: *std.Build.Module,
) *std.Build.Module {
    const integration = graph.create(b, .{
        .product = product,
        .root_source_file = "src/integrations/native_cuda/mod.zig",
        .target = target,
        .optimize = optimize,
    });
    protocol.addImports(integration);
    integration.addImport("stwo_cuda_backend", cuda_backend);
    integration.addImport("stwo_native_examples", native_examples);
    integration.addImport("stwo_proof_wire", proof_wire);
    return integration;
}

/// Declares a consumer's dependency on the package-owned Native CUDA API.
pub fn addNativeCudaImport(
    b: *std.Build,
    protocol: graph.ProtocolModules,
    product: graph.Product,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    cuda_backend: *std.Build.Module,
    native_examples: *std.Build.Module,
    proof_wire: *std.Build.Module,
    consumer: *std.Build.Module,
) *std.Build.Module {
    const integration = createNativeCuda(
        b,
        protocol,
        product,
        target,
        optimize,
        cuda_backend,
        native_examples,
        proof_wire,
    );
    consumer.addImport("stwo_native_cuda_integration", integration);
    return integration;
}

/// Constructs the Cairo frontend to CUDA backend composition against the
/// package-owned Native CUDA primitives selected by the enclosing product.
pub fn createCairoCuda(
    b: *std.Build,
    protocol: graph.ProtocolModules,
    product: graph.Product,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    cuda_backend: *std.Build.Module,
    cairo_frontend: *std.Build.Module,
    native_cuda: *std.Build.Module,
) *std.Build.Module {
    const integration = graph.create(b, .{
        .product = product,
        .root_source_file = "src/integrations/cairo_cuda/mod.zig",
        .target = target,
        .optimize = optimize,
    });
    protocol.addImports(integration);
    integration.addImport("stwo_cuda_backend", cuda_backend);
    integration.addImport("stwo_cairo_frontend", cairo_frontend);
    integration.addImport("stwo_native_cuda_integration", native_cuda);
    return integration;
}

/// Declares a consumer's dependency on the package-owned Cairo CUDA API.
pub fn addCairoCudaImport(
    b: *std.Build,
    protocol: graph.ProtocolModules,
    product: graph.Product,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    cuda_backend: *std.Build.Module,
    cairo_frontend: *std.Build.Module,
    native_cuda: *std.Build.Module,
    consumer: *std.Build.Module,
) *std.Build.Module {
    const integration = createCairoCuda(
        b,
        protocol,
        product,
        target,
        optimize,
        cuda_backend,
        cairo_frontend,
        native_cuda,
    );
    consumer.addImport("stwo_cairo_cuda_integration", integration);
    return integration;
}
