//! Typed product declarations and focused Zig module construction.

const std = @import("std");
const package_ownership = @import("package_ownership.zig");
const protocol_modules = @import("protocol_modules.zig");

pub const Frontend = enum { none, native, riscv, cairo, aggregate };
pub const Backend = enum { none, contracts, cpu, metal, cuda };
pub const Role = enum { library, cli, benchmark, @"test", gate };

pub const Product = struct {
    name: []const u8,
    frontend: Frontend,
    backend: Backend,
    role: Role,
    protocol_features: []const u8 = "default",

    pub fn validate(self: Product) !void {
        if (self.name.len == 0 or self.protocol_features.len == 0)
            return error.InvalidProductIdentity;
        switch (self.role) {
            .cli, .benchmark, .gate => {
                if (self.frontend == .none or self.backend == .none)
                    return error.IncompleteProductCapabilities;
            },
            .library, .@"test" => {},
        }
    }

    pub fn frontendManifest(self: Product) []const u8 {
        return switch (self.frontend) {
            .none => "none",
            .native => "native-examples",
            .riscv => "sail-rv32im-zkvm",
            .cairo => "cairo",
            .aggregate => "aggregate",
        };
    }

    pub fn backendManifest(self: Product) []const u8 {
        return @tagName(self.backend);
    }
};

pub const ModuleSpec = struct {
    product: Product,
    root_source_file: []const u8,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
};

pub const ProtocolModules = protocol_modules.ProtocolModules;

pub fn create(b: *std.Build, spec: ModuleSpec) *std.Build.Module {
    spec.product.validate() catch |err| std.debug.panic(
        "invalid build product {s}: {s}",
        .{ spec.product.name, @errorName(err) },
    );
    return b.createModule(.{
        .root_source_file = ownedRootSource(b, spec),
        .target = spec.target,
        .optimize = spec.optimize,
    });
}

pub fn addPublic(b: *std.Build, name: []const u8, spec: ModuleSpec) *std.Build.Module {
    spec.product.validate() catch |err| std.debug.panic(
        "invalid public build product {s}: {s}",
        .{ spec.product.name, @errorName(err) },
    );
    return b.addModule(name, .{
        .root_source_file = ownedRootSource(b, spec),
        .target = spec.target,
        .optimize = spec.optimize,
    });
}

/// Resolves package-owned roots; other roots remain aggregate-relative.
fn ownedRootSource(b: *std.Build, spec: ModuleSpec) std.Build.LazyPath {
    return source(
        b,
        spec.root_source_file,
        spec.target,
        spec.optimize,
    );
}

pub fn source(
    b: *std.Build,
    root_source_file: []const u8,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) std.Build.LazyPath {
    const owned = package_ownership.resolve(root_source_file) orelse
        return b.path(root_source_file);
    const dependency_options = .{
        .target = target,
        .optimize = optimize,
    };
    const dependency_name = package_ownership.dependencyName(owned.package);
    return b.dependency(dependency_name, dependency_options).path(owned.sub_path);
}

pub fn createProtocolModules(
    b: *std.Build,
    core: *std.Build.Module,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) ProtocolModules {
    const backend_contracts = create(b, .{
        .product = proverProduct(.library),
        .root_source_file = "src/backend/mod.zig",
        .target = target,
        .optimize = optimize,
    });
    backend_contracts.addImport("stwo_core", core);

    const prover_api = create(b, .{
        .product = proverProduct(.library),
        .root_source_file = "src/prover_api/mod.zig",
        .target = target,
        .optimize = optimize,
    });
    prover_api.addImport("stwo_core", core);

    const prover = create(b, .{
        .product = proverProduct(.library),
        .root_source_file = "src/prover/mod.zig",
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
        .root_source_file = "src/core/mod.zig",
        .target = target,
        .optimize = optimize,
    });
    return createProtocolModules(b, core, target, optimize);
}

/// Constructs the canonical RISC-V frontend against selected protocol modules.
pub fn createRiscVFrontend(
    b: *std.Build,
    protocol: ProtocolModules,
    product: Product,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    proof_wire_override: ?*std.Build.Module,
) *std.Build.Module {
    const frontend = create(b, .{
        .product = product,
        .root_source_file = "src/frontends/riscv/mod.zig",
        .target = target,
        .optimize = optimize,
    });
    protocol.addImports(frontend);
    const proof_wire = proof_wire_override orelse
        createProofWire(b, protocol, product, target, optimize);
    const postcard = create(b, .{
        .product = product,
        .root_source_file = "src/interop/postcard.zig",
        .target = target,
        .optimize = optimize,
    });
    postcard.addImport("stwo_core", protocol.core);
    postcard.addImport("stwo_proof_wire", proof_wire);
    frontend.addImport("interop_postcard", postcard);
    return frontend;
}

pub fn addRiscVFrontendImport(
    b: *std.Build,
    protocol: ProtocolModules,
    product: Product,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    consumer: *std.Build.Module,
) *std.Build.Module {
    const frontend = createRiscVFrontend(
        b,
        protocol,
        product,
        target,
        optimize,
        consumer.import_table.get("stwo_proof_wire"),
    );
    consumer.addImport("stwo_riscv_frontend", frontend);
    const postcard = frontend.import_table.get("interop_postcard") orelse
        @panic("canonical RISC-V frontend is missing interop_postcard");
    consumer.addImport("interop_postcard", postcard);
    return frontend;
}

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
    return frontend;
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
        .root_source_file = "src/artifact_store/mod.zig",
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
        .root_source_file = "src/tools/metal_session/mod.zig",
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
pub fn createProofWire(
    b: *std.Build,
    protocol: ProtocolModules,
    product: Product,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) *std.Build.Module {
    const proof_wire = create(b, .{
        .product = product,
        .root_source_file = "src/interop/proof_wire/mod.zig",
        .target = target,
        .optimize = optimize,
    });
    proof_wire.addImport("stwo_core", protocol.core);
    return proof_wire;
}

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
pub fn createNativeExamples(
    b: *std.Build,
    protocol: ProtocolModules,
    product: Product,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    cpu_backend: *std.Build.Module,
    proof_wire: *std.Build.Module,
) *std.Build.Module {
    const examples = create(b, .{
        .product = product,
        .root_source_file = "src/examples/mod.zig",
        .target = target,
        .optimize = optimize,
    });
    examples.addImport("stwo_core", protocol.core);
    examples.addImport("stwo_prover_api", protocol.prover_api);
    examples.addImport("stwo_prover_engine", protocol.prover);
    examples.addImport("stwo_cpu_backend", cpu_backend);
    examples.addImport("stwo_proof_wire", proof_wire);
    return examples;
}

/// Declares a consumer's dependency on the package-owned Native example API.
pub fn addNativeExamplesImport(
    b: *std.Build,
    protocol: ProtocolModules,
    product: Product,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    cpu_backend: *std.Build.Module,
    proof_wire: *std.Build.Module,
    consumer: *std.Build.Module,
) *std.Build.Module {
    const examples = createNativeExamples(
        b,
        protocol,
        product,
        target,
        optimize,
        cpu_backend,
        proof_wire,
    );
    consumer.addImport("stwo_native_examples", examples);
    return examples;
}

pub fn coreProduct(role: Role) Product {
    return .{
        .name = "stwo-core",
        .frontend = .none,
        .backend = .none,
        .role = role,
        .protocol_features = "stwo-core-v1",
    };
}

pub fn proverProduct(role: Role) Product {
    return .{
        .name = "stwo-prover",
        .frontend = .none,
        .backend = .contracts,
        .role = role,
        .protocol_features = "generic-prover+backend-contracts-v1",
    };
}
