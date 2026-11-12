//! Typed product declarations and focused Zig module construction.

const std = @import("std");
const protocol_modules = @import("protocol_modules.zig");

const product_spec = @import("product_spec.zig");
pub const Frontend = product_spec.Frontend;
pub const Backend = product_spec.Backend;
pub const Role = product_spec.Role;
pub const Product = product_spec.Product;
pub const ModuleSpec = product_spec.ModuleSpec;
pub const coreProduct = product_spec.coreProduct;
pub const proverProduct = product_spec.proverProduct;

pub const ProtocolModules = protocol_modules.ProtocolModules;

pub const create = @import("module_construction.zig").create;
pub const addPublic = @import("module_construction.zig").addPublic;
pub const source = @import("module_construction.zig").source;

pub fn createProtocolModules(
    b: *std.Build,
    core: *std.Build.Module,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) ProtocolModules {
    const backend_contracts = create(b, .{
        .product = proverProduct(.library),
        .root_source_file = "src/waist/backend/mod.zig",
        .target = target,
        .optimize = optimize,
    });
    backend_contracts.addImport("stwo_core", core);

    const prover_api = create(b, .{
        .product = proverProduct(.library),
        .root_source_file = "src/waist/prover_api/mod.zig",
        .target = target,
        .optimize = optimize,
    });
    prover_api.addImport("stwo_core", core);

    const prover = create(b, .{
        .product = proverProduct(.library),
        .root_source_file = "src/engine/prover/mod.zig",
        .target = target,
        .optimize = optimize,
    });
    prover.addImport("stwo_core", core);
    prover.addImport("stwo_backend_contracts", backend_contracts);
    prover.addImport("stwo_prover_api", prover_api);

    return .{
        .core = core,
        .backend_contracts = backend_contracts,
        .prover_api = prover_api,
        .prover = prover,
    };
}

pub fn createPrivateProtocolModules(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) ProtocolModules {
    const core = create(b, .{
        .product = coreProduct(.library),
        .root_source_file = "src/waist/core/mod.zig",
        .target = target,
        .optimize = optimize,
    });
    return createProtocolModules(b, core, target, optimize);
}

/// Constructs the canonical RISC-V frontend against selected protocol modules.
pub const createRiscVFrontend = @import("riscv_modules.zig").createRiscVFrontend;
pub const addRiscVFrontendImport = @import("riscv_modules.zig").addRiscVFrontendImport;

/// Constructs the canonical Cairo frontend against a selected protocol set.
pub fn createCairoFrontend(
    b: *std.Build,
    protocol: ProtocolModules,
    product: Product,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) *std.Build.Module {
    const frontend = create(b, .{
        .product = product,
        .root_source_file = "src/frontends/cairo/mod.zig",
        .target = target,
        .optimize = optimize,
    });
    protocol.addImports(frontend);
    // The injected interop felt JSON writer behind `proof.cairo_serde`.
    const felt_json = create(b, .{
        .product = product,
        .root_source_file = "src/frontends/cairo/interop/felt_json.zig",
        .target = target,
        .optimize = optimize,
    });
    felt_json.addImport("stwo_core", protocol.core);
    frontend.addImport("interop_felt_json", felt_json);
    // The injected `ProverParameters` (the circuit registry's
    // `cairo_prover_params`, shared with the circuit-recursion wire package)
    // behind `proving.leaf_lane`.
    const prover_parameters = create(b, .{
        .product = product,
        .root_source_file = "src/frontends/cairo/interop/cairo_prover_parameters.zig",
        .target = target,
        .optimize = optimize,
    });
    prover_parameters.addImport("stwo_core", protocol.core);
    frontend.addImport("interop_cairo_prover_parameters", prover_parameters);
    return frontend;
}

/// Constructs the circuit-recursion wire package beside a Cairo frontend.
/// The two share the injected `interop_felt_json` and
/// `interop_cairo_prover_parameters` modules: a file belongs to one module per
/// compilation, so the wire package takes the frontend's instances.
pub fn createCircuitRecursionWire(
    b: *std.Build,
    protocol: ProtocolModules,
    product: Product,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    cairo_frontend: *std.Build.Module,
) *std.Build.Module {
    const wire = create(b, .{
        .product = product,
        .root_source_file = "src/waist/recursion_wire/mod.zig",
        .target = target,
        .optimize = optimize,
    });
    wire.addImport("stwo_core", protocol.core);
    inline for (.{ "interop_felt_json", "interop_cairo_prover_parameters" }) |name| {
        wire.addImport(name, cairo_frontend.import_table.get(name) orelse
            @panic("Cairo frontend is missing " ++ name));
    }
    return wire;
}

/// Declares a consumer's dependency on the package-owned Cairo API.
pub fn addCairoFrontendImport(
    b: *std.Build,
    protocol: ProtocolModules,
    product: Product,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    consumer: *std.Build.Module,
) *std.Build.Module {
    const frontend = createCairoFrontend(
        b,
        protocol,
        product,
        target,
        optimize,
    );
    consumer.addImport("stwo_cairo_frontend", frontend);
    return frontend;
}

/// Constructs the canonical CPU backend against a selected protocol set.
pub fn createCpuBackend(
    b: *std.Build,
    protocol: ProtocolModules,
    product: Product,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) *std.Build.Module {
    const backend = create(b, .{
        .product = product,
        .root_source_file = "src/backends/cpu_scalar/mod.zig",
        .target = target,
        .optimize = optimize,
    });
    protocol.addImports(backend);
    return backend;
}

/// Declares a consumer's dependency on the package-owned CPU backend API.
pub fn addCpuBackendImport(
    b: *std.Build,
    protocol: ProtocolModules,
    product: Product,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    consumer: *std.Build.Module,
) *std.Build.Module {
    const backend = createCpuBackend(
        b,
        protocol,
        product,
        target,
        optimize,
    );
    consumer.addImport("stwo_cpu_backend", backend);
    return backend;
}

/// Constructs the canonical host-independent CUDA backend contract module.
pub fn createCudaBackend(
    b: *std.Build,
    protocol: ProtocolModules,
    product: Product,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) *std.Build.Module {
    const backend = create(b, .{
        .product = product,
        .root_source_file = "src/backends/cuda/mod.zig",
        .target = target,
        .optimize = optimize,
    });
    backend.addImport("stwo_backend_contracts", protocol.backend_contracts);
    return backend;
}

/// Declares a consumer's dependency on the package-owned CUDA backend API.
pub fn addCudaBackendImport(
    b: *std.Build,
    protocol: ProtocolModules,
    product: Product,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    consumer: *std.Build.Module,
) *std.Build.Module {
    const backend = createCudaBackend(
        b,
        protocol,
        product,
        target,
        optimize,
    );
    consumer.addImport("stwo_cuda_backend", backend);
    return backend;
}

/// Constructs the canonical Metal backend against protocol-owned primitives.
pub fn createMetalBackend(
    b: *std.Build,
    protocol: ProtocolModules,
    product: Product,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) *std.Build.Module {
    const backend = create(b, .{
        .product = product,
        .root_source_file = "src/backends/metal/mod.zig",
        .target = target,
        .optimize = optimize,
    });
    protocol.addImports(backend);
    return backend;
}

/// Declares a consumer's dependency on the package-owned Metal backend API.
pub fn addMetalBackendImport(
    b: *std.Build,
    protocol: ProtocolModules,
    product: Product,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    consumer: *std.Build.Module,
) *std.Build.Module {
    const backend = createMetalBackend(
        b,
        protocol,
        product,
        target,
        optimize,
    );
    consumer.addImport("stwo_metal_backend", backend);
    return backend;
}

/// Constructs the host-neutral persistent typed artifact-store module.
pub fn createArtifactStore(
    b: *std.Build,
    product: Product,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) *std.Build.Module {
    return create(b, .{
        .product = product,
        .root_source_file = "src/engine/artifact_store/mod.zig",
        .target = target,
        .optimize = optimize,
    });
}

pub fn addArtifactStoreImport(
    b: *std.Build,
    product: Product,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    consumer: *std.Build.Module,
) *std.Build.Module {
    const artifact_store = createArtifactStore(b, product, target, optimize);
    consumer.addImport("stwo_artifact_store", artifact_store);
    return artifact_store;
}

/// Constructs the host-independent persistent Metal-session service module.
pub fn createMetalSession(
    b: *std.Build,
    product: Product,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    artifact_store_override: ?*std.Build.Module,
) *std.Build.Module {
    const metal_session = create(b, .{
        .product = product,
        .root_source_file = "src/backends/metal/session/mod.zig",
        .target = target,
        .optimize = optimize,
    });
    const artifact_store = artifact_store_override orelse
        createArtifactStore(b, product, target, optimize);
    metal_session.addImport("stwo_artifact_store", artifact_store);
    return metal_session;
}

/// Declares a consumer's dependency on the package-owned Metal-session API.
pub fn addMetalSessionImport(
    b: *std.Build,
    product: Product,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    consumer: *std.Build.Module,
) *std.Build.Module {
    const metal_session = createMetalSession(
        b,
        product,
        target,
        optimize,
        consumer.import_table.get("stwo_artifact_store"),
    );
    consumer.addImport("stwo_metal_session", metal_session);
    return metal_session;
}

/// Constructs the proof interchange codec against the selected protocol core.
pub const createProofWire = @import("module_construction.zig").createProofWire;

/// Declares a consumer's dependency on the package-owned proof-wire API.
pub fn addProofWireImport(
    b: *std.Build,
    protocol: ProtocolModules,
    product: Product,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    consumer: *std.Build.Module,
) *std.Build.Module {
    const proof_wire = createProofWire(
        b,
        protocol,
        product,
        target,
        optimize,
    );
    consumer.addImport("stwo_proof_wire", proof_wire);
    return proof_wire;
}

/// Constructs Native example AIRs against their explicit dependencies.
pub const createNativeExamples = @import("artifact_modules.zig").createNativeExamples;
pub const addNativeExamplesImport = @import("artifact_modules.zig").addNativeExamplesImport;
pub const SupportIo = @import("artifact_modules.zig").SupportIo;
pub const addSupportIoImport = @import("artifact_modules.zig").addSupportIoImport;
pub const addRiscVArtifactImport = @import("artifact_modules.zig").addRiscVArtifactImport;
pub const addNativeArtifactImport = @import("artifact_modules.zig").addNativeArtifactImport;
pub const addPostcardImport = @import("artifact_modules.zig").addPostcardImport;
pub const FacadeSupport = @import("artifact_modules.zig").FacadeSupport;
pub const addFacadeSupportImports = @import("artifact_modules.zig").addFacadeSupportImports;
