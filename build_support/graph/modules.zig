//! Typed product declarations and focused Zig module construction.

const std = @import("std");

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

const OwnedPackage = enum {
    core,
    backend_contracts,
    prover,
};

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
    const owned = ownedSource(root_source_file) orelse
        return b.path(root_source_file);
    const dependency_options = .{
        .target = target,
        .optimize = optimize,
    };
    return switch (owned.package) {
        .core => b.dependency(
            "stwo_core",
            dependency_options,
        ).path(owned.sub_path),
        .backend_contracts => b.dependency(
            "stwo_backend_contracts",
            dependency_options,
        ).path(owned.sub_path),
        .prover => b.dependency(
            "stwo_prover_impl",
            dependency_options,
        ).path(owned.sub_path),
    };
}

const OwnedSource = struct {
    package: OwnedPackage,
    sub_path: []const u8,
};

fn ownedSource(root_source_file: []const u8) ?OwnedSource {
    const prefixes = .{
        .{ "src/core/", OwnedPackage.core },
        .{ "src/backend/", OwnedPackage.backend_contracts },
        .{ "src/prover/", OwnedPackage.prover },
    };
    inline for (prefixes) |entry| {
        if (std.mem.startsWith(u8, root_source_file, entry[0])) return .{
            .package = entry[1],
            .sub_path = root_source_file[entry[0].len..],
        };
    }
    return null;
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

test "executable products require explicit capabilities" {
    try std.testing.expectError(error.IncompleteProductCapabilities, (Product{
        .name = "invalid",
        .frontend = .native,
        .backend = .none,
        .role = .cli,
    }).validate());
    try (Product{
        .name = "stwo-native-cpu",
        .frontend = .native,
        .backend = .cpu,
        .role = .cli,
    }).validate();
}

test "capability manifests have stable public names" {
    const riscv = Product{
        .name = "stwo-riscv-cpu",
        .frontend = .riscv,
        .backend = .cpu,
        .role = .gate,
    };
    try std.testing.expectEqualStrings("sail-rv32im-zkvm", riscv.frontendManifest());
    try std.testing.expectEqualStrings("cpu", riscv.backendManifest());
}

test "generic prover identifies backend contracts without a concrete backend" {
    const prover = proverProduct(.library);
    try prover.validate();
    try std.testing.expectEqualStrings("contracts", prover.backendManifest());
}

test "canonical owner roots resolve to package dependencies" {
    try std.testing.expectEqual(
        OwnedPackage.core,
        ownedSource("src/core/mod.zig").?.package,
    );
    try std.testing.expectEqual(
        OwnedPackage.backend_contracts,
        ownedSource("src/backend/mod.zig").?.package,
    );
    try std.testing.expectEqual(
        OwnedPackage.prover,
        ownedSource("src/prover/mod.zig").?.package,
    );
    try std.testing.expectEqualStrings(
        "native/runner.zig",
        ownedSource("src/prover/native/runner.zig").?.sub_path,
    );
    try std.testing.expect(ownedSource("src/products/prover/root.zig") == null);
}

test "aggregate SDK facade has an explicit library identity" {
    const facade = Product{
        .name = "stwo",
        .frontend = .aggregate,
        .backend = .contracts,
        .role = .library,
        .protocol_features = "aggregate-sdk-v1",
    };
    try facade.validate();
}
