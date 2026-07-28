//! Typed product declarations and focused Zig module construction.

const std = @import("std");
const package_ownership = @import("package_ownership.zig");

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

pub const ProtocolModules = struct {
    core: *std.Build.Module,
    backend_contracts: *std.Build.Module,
    prover: *std.Build.Module,

    pub fn addImports(self: ProtocolModules, module: *std.Build.Module) void {
        module.addImport("stwo_core", self.core);
        module.addImport("stwo_backend_contracts", self.backend_contracts);
        module.addImport("stwo_prover_impl", self.prover);
    }
};

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

/// Resolves canonical ownership roots through their package manifests. Other
/// product-local roots remain relative to the repository aggregate package.
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

    const prover = create(b, .{
        .product = proverProduct(.library),
        .root_source_file = "src/prover/mod.zig",
        .target = target,
        .optimize = optimize,
    });
    prover.addImport("stwo_core", core);
    prover.addImport("stwo_backend_contracts", backend_contracts);

    return .{
        .core = core,
        .backend_contracts = backend_contracts,
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

/// Constructs the canonical RISC-V frontend module against an already selected
/// protocol module set. Product roots must opt into this dependency explicitly.
pub fn createRiscVFrontend(
    b: *std.Build,
    protocol: ProtocolModules,
    product: Product,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) *std.Build.Module {
    const frontend = create(b, .{
        .product = product,
        .root_source_file = "src/frontends/riscv/mod.zig",
        .target = target,
        .optimize = optimize,
    });
    protocol.addImports(frontend);
    return frontend;
}

/// Declares a consumer's dependency on the package-owned RISC-V API.
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
    );
    consumer.addImport("stwo_riscv_frontend", frontend);
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

/// Constructs the canonical Metal backend with one shared CPU fallback module.
pub fn createMetalBackend(
    b: *std.Build,
    protocol: ProtocolModules,
    product: Product,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    cpu_backend: *std.Build.Module,
) *std.Build.Module {
    const backend = create(b, .{
        .product = product,
        .root_source_file = "src/backends/metal/mod.zig",
        .target = target,
        .optimize = optimize,
    });
    protocol.addImports(backend);
    backend.addImport("stwo_cpu_backend", cpu_backend);
    return backend;
}

/// Declares a consumer's dependency on the package-owned Metal backend API.
pub fn addMetalBackendImport(
    b: *std.Build,
    protocol: ProtocolModules,
    product: Product,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    cpu_backend: *std.Build.Module,
    consumer: *std.Build.Module,
) *std.Build.Module {
    const backend = createMetalBackend(
        b,
        protocol,
        product,
        target,
        optimize,
        cpu_backend,
    );
    consumer.addImport("stwo_metal_backend", backend);
    return backend;
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
