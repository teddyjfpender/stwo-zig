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
    const selected_cpu = consumer.import_table.get("stwo_riscv_cpu_integration");
    const predecessors = if (selected_cpu) |native| @import("stwo_ethereum_statement").Construction.nativeCpuPredecessors(native) else null;
    if (selected_cpu) |native| if (native.import_table.get("stwo_core") != protocol.core) @panic("caller CPU protocol drift");
    const cpu_backend = consumer.import_table.get("stwo_cpu_backend") orelse if (predecessors) |actual| actual.backend else graph.addCpuBackendImport(
        b,
        protocol,
        product,
        target,
        optimize,
        consumer,
    );
    const riscv_frontend = consumer.import_table.get("stwo_riscv_frontend") orelse if (predecessors) |actual| actual.frontend else graph.addRiscVFrontendImport(
        b,
        protocol,
        product,
        target,
        optimize,
        consumer,
    );
    if (predecessors) |actual| if (actual.frontend != riscv_frontend or actual.backend != cpu_backend) @panic("caller CPU predecessor drift");
    consumer.addImport("stwo_riscv_frontend", riscv_frontend);
    consumer.addImport("stwo_cpu_backend", cpu_backend);
    const native_cpu = selected_cpu orelse addRiscVCpuImport(
        b,
        protocol,
        product,
        target,
        optimize,
        cpu_backend,
        riscv_frontend,
        consumer,
    );
    _ = bindEthereumOwner(b, protocol, product, target, optimize, consumer, riscv_frontend, native_cpu);
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
    integration.addImport(
        "interop_postcard",
        riscv_frontend.import_table.get("interop_postcard") orelse
            @panic("canonical RISC-V frontend is missing interop_postcard"),
    );
    const postcard = riscv_frontend.import_table.get("interop_postcard").?;
    integration.addImport("stwo_proof_wire", postcard.import_table.get("stwo_proof_wire") orelse @panic("canonical RISC-V postcard is missing proof wire"));
    integration.addImport("stwo_artifact_store", graph.createArtifactStore(b, product, target, optimize));
    const cairo_frontend = graph.addCairoFrontendImport(b, protocol, product, target, optimize, consumer);
    if (consumer.import_table.get("stwo_circuit_recursion_wire")) |wire| {
        if (wire.import_table.get("stwo_core") != protocol.core)
            @panic("caller recursion wire protocol drift");
        integration.addImport("stwo_circuit_recursion_wire", wire);
    }
    @import("circuit_modules.zig").addCircuitProviders(
        .{ .b = b, .protocol = protocol, .target = target, .optimize = optimize },
        product,
        integration,
        cpu_backend,
        cairo_frontend,
    );
    // A complete facade may also expose recursion wire. It must borrow this
    // actual instance rather than instantiate its source a second time.
    if (consumer.import_table.get("stwo_circuit_recursion_wire")) |existing| {
        if (existing != integration.import_table.get("stwo_circuit_recursion_wire").?)
            @panic("caller recursion wire identity drift");
    } else consumer.addImport("stwo_circuit_recursion_wire", integration.import_table.get("stwo_circuit_recursion_wire").?);
    consumer.addImport("stwo_riscv_cpu_integration", integration);
    return integration;
}

/// Constructs the RISC-V frontend to CUDA provider composition. This package
/// owns only the structural/formal boundary until the RISC-V AOT catalogue and
/// execution-parity gate are complete.
pub fn createRiscVCuda(
    b: *std.Build,
    protocol: graph.ProtocolModules,
    product: graph.Product,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    cuda_backend: *std.Build.Module,
    riscv_frontend: *std.Build.Module,
    native_cpu: *std.Build.Module,
) *std.Build.Module {
    const integration = graph.create(b, .{
        .product = product,
        .root_source_file = "src/integrations/riscv_cuda/mod.zig",
        .target = target,
        .optimize = optimize,
    });
    protocol.addImports(integration);
    integration.addImport("stwo_riscv_cpu_integration", native_cpu);
    inline for (.{ "stwo_circuit_cpu_integration", "stwo_circuit_frontend" }) |name|
        integration.addImport(name, native_cpu.import_table.get(name).?);
    integration.addImport("stwo_cuda_backend", cuda_backend);
    integration.addImport("stwo_riscv_frontend", riscv_frontend);
    return integration;
}

/// Declares a consumer's dependency on the package-owned RISC-V CUDA seam.
pub fn addRiscVCudaImport(
    b: *std.Build,
    protocol: graph.ProtocolModules,
    product: graph.Product,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    cuda_backend: *std.Build.Module,
    riscv_frontend: *std.Build.Module,
    consumer: *std.Build.Module,
) *std.Build.Module {
    const native_cpu = consumer.import_table.get("stwo_riscv_cpu_integration") orelse blk: {
        const backend = consumer.import_table.get("stwo_cpu_backend") orelse graph.addCpuBackendImport(b, protocol, product, target, optimize, consumer);
        break :blk addRiscVCpuImport(b, protocol, product, target, optimize, backend, riscv_frontend, consumer);
    };
    const integration = createRiscVCuda(
        b,
        protocol,
        product,
        target,
        optimize,
        cuda_backend,
        riscv_frontend,
        native_cpu,
    );
    consumer.addImport("stwo_riscv_cuda_integration", integration);
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

// Product roots use the caller's actual protocol and native owner graph.
// Only a CUDA consumer constructs a CUDA component; CPU roots need no placeholder.
fn bindEthereumOwner(b: *std.Build, protocol: graph.ProtocolModules, product: graph.Product, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode, consumer: *std.Build.Module, native_frontend: *std.Build.Module, native_cpu: *std.Build.Module) bool {
    const source = consumer.root_source_file orelse return false;
    const relative = std.fs.path.relative(b.allocator, b.path("").getPath(b), source.getPath(b)) catch @panic("out of memory");
    const owned = @import("package_ownership.zig").resolve(relative) orelse return false;
    if (owned.package != .ethereum_statement) return false;
    const construction = @import("stwo_ethereum_statement").Construction;
    const front = construction.frontend(b, graph.source(b, "src/products/ethereum/statement/frontend.zig", target, optimize), target, optimize, native_frontend);
    const cpu = construction.cpu(b, graph.source(b, "src/products/ethereum/statement/cpu.zig", target, optimize), target, optimize, front, native_cpu);
    const owner = if (std.mem.startsWith(u8, owned.sub_path, "cuda/")) blk: {
        const backend = graph.createCudaBackend(b, protocol, product, target, optimize);
        const native_cuda = createRiscVCuda(b, protocol, product, target, optimize, backend, native_frontend, native_cpu);
        break :blk construction.cuda(b, graph.source(b, "src/products/ethereum/statement/cuda.zig", target, optimize), target, optimize, front, cpu, native_cuda);
    } else if (std.mem.startsWith(u8, owned.sub_path, "frontend/")) front else cpu;
    for (owner.import_table.keys(), owner.import_table.values()) |name, dependency|
        consumer.addImport(name, dependency);
    consumer.addImport("legacy_riscv_frontend", front);
    consumer.addImport("legacy_riscv_cpu_integration", cpu);
    consumer.addImport("ethereum_frontend_component", front);
    consumer.addImport("ethereum_cpu_component", cpu);
    return true;
}

/// Explicit legacy product namespace. Neutral module names keep their actual
/// owners; only the deprecated product facade selects Ethereum compatibility.
pub fn addEthereumFrontendCompatibility(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode, native_frontend: *std.Build.Module, consumer: *std.Build.Module) *std.Build.Module {
    const construction = @import("stwo_ethereum_statement").Construction;
    const front = construction.frontend(b, graph.source(b, "src/products/ethereum/statement/frontend.zig", target, optimize), target, optimize, native_frontend);
    consumer.addImport("legacy_riscv_frontend", front);
    return front;
}

pub fn addEthereumCpuCompatibility(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode, consumer: *std.Build.Module) void {
    const front = addEthereumFrontendCompatibility(b, target, optimize, consumer.import_table.get("stwo_riscv_frontend").?, consumer);
    const cpu = @import("stwo_ethereum_statement").Construction.cpu(b, graph.source(b, "src/products/ethereum/statement/cpu.zig", target, optimize), target, optimize, front, consumer.import_table.get("stwo_riscv_cpu_integration").?);
    consumer.addImport("legacy_riscv_cpu_integration", cpu);
}
