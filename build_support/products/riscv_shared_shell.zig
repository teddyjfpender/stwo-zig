//! Build-graph wiring shared by the focused RV32IM product owners.
//!
//! Each RV32IM product owner that builds a proof CLI binds the *same* shell
//! sources (`src/products/riscv_shared/*.zig`) and the *same* engine-generic
//! proof adapter (`src/integrations/riscv_cpu/proof_adapter.zig`) onto its own
//! backend. What lives here is the part of that binding which is identical in
//! every one of them; everything backend-specific stays in the product owner.
//!
//! Nothing here may name a foreign backend or frontend: this file shapes the
//! CPU product's graph, and `scripts/check_riscv_cpu_product.py` fails that
//! product's build on any foreign-backend marker in the sources it owns.

const std = @import("std");
const build_identity = @import("../build_identity.zig");
const graph_identity = @import("../graph/identity.zig");
const graph = @import("../graph/modules.zig");
const product_policy = @import("../graph/product.zig");

/// The shared focused-product shell (`src/products/riscv_shared/*.zig`) under
/// the module names the shell files themselves import.
///
/// The shell files import only `std`, so they need no protocol or facade
/// imports: every product-specific module reaches them through the binding.
/// Zig 0.15 forbids a relative `@import` that leaves the importing module's root
/// directory, so each shared file a product root names must be injected under
/// its own module name rather than reached as `../riscv_shared/*.zig`.
pub const shell_named_imports = [_]product_policy.NamedImport{
    .{ .name = "riscv_shared_app", .source = "src/products/riscv_shared/app.zig" },
    .{ .name = "riscv_shared_cli", .source = "src/products/riscv_shared/cli.zig" },
    .{ .name = "riscv_shared_registry", .source = "src/products/riscv_shared/registry.zig" },
};

/// The engine-generic proof adapter, shared verbatim by every product.
pub const adapter_source = "src/integrations/riscv_cpu/proof_adapter.zig";

/// What one product-local module is created against: the logical product
/// identity plus the target/optimize pair of the *call site*. The owners do not
/// all pass the same values — the CPU owner also binds a static cross-compiled
/// root — so every helper reads them from the binding instead of assuming one
/// product-wide pair.
pub const Binding = struct {
    b: *std.Build,
    product: graph.Product,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,

    /// A product-local leaf module: one whose source imports nothing but `std`
    /// and its own directory. The shared shell files, each product's capability
    /// file and the interop wire files are all in this class.
    pub fn leafModule(self: Binding, root_source_file: []const u8) *std.Build.Module {
        return graph.create(self.b, .{
            .product = self.product,
            .root_source_file = root_source_file,
            .target = self.target,
            .optimize = self.optimize,
        });
    }

    /// Attach every shared shell module to `module` under the names in
    /// `shell_named_imports`.
    pub fn addShellImports(self: Binding, module: *std.Build.Module) void {
        for (shell_named_imports) |shell| {
            module.addImport(shell.name, self.leafModule(shell.source));
        }
    }

    /// The engine-generic proof adapter. Every product binds it under the
    /// historical `riscv_cpu_capabilities` import name — each to *its own*
    /// capability file — so the adapter source compiles unchanged in all of them.
    pub fn adapterModule(self: Binding, spec: Adapter) *std.Build.Module {
        const module = self.leafModule(adapter_source);
        spec.protocol.addImports(module);
        module.addImport("stwo", spec.stwo);
        module.addImport("riscv_cpu_capabilities", spec.capabilities);
        module.addOptions("build_identity", graph_identity.buildOptions(self.b, spec.identity));
        return module;
    }
};

/// The adapter's product-specific bindings. Named rather than positional: two
/// bare module pointers at a call site say nothing about which facade and which
/// capability surface the adapter is being wired to.
pub const Adapter = struct {
    protocol: graph.ProtocolModules,
    identity: build_identity.Identity,
    stwo: *std.Build.Module,
    capabilities: *std.Build.Module,
};

/// The same product identity under a different build role. Each owner declares
/// one `Product` for its CLI and re-derives the library, benchmark and test
/// roles from it, so a role can never silently fork the identity.
pub fn roleProduct(base: graph.Product, role: graph.Role) graph.Product {
    return .{
        .name = base.name,
        .frontend = base.frontend,
        .backend = base.backend,
        .role = role,
        .protocol_features = base.protocol_features,
    };
}
