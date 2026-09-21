//! Product capabilities and identity contracts independent of module construction.
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
