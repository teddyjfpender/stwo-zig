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
const test_filter = @import("riscv_test_filter.zig");

/// Fewest tests the RISC-V frontend package's own test binary must contain.
///
/// Measured on this tree: 473 (459 named plus 14 anonymous aggregation blocks).
/// The floor sits below that so ordinary work does not have to move it, and far
/// enough above an empty shell that losing the package's test aggregation cannot
/// pass. It is not decoration: before `src/frontends/riscv/test_inventory.zig`
/// existed the same artifact held 319, and no gate compiled any of them.
///
/// Raise it deliberately when the suite grows; never lower it to make a build
/// pass, because the thing it detects is exactly a build that passes.
pub const frontend_test_floor = 440;

/// Fewest tests the shared proof adapter's own test binary must contain.
///
/// `src/integrations/riscv_cpu/proof_adapter.zig` and its neighbours import
/// `stwo` and `riscv_cpu_capabilities`, which only a product graph supplies, so
/// the integration package's own `test` step cannot compile them and never did.
/// A product step is the only possible home for them, and until now no product
/// step had one -- which is how `test "adapter fail-closes through the shared
/// run-admission gate"` came to be written against a step that would never
/// compile it.
pub const adapter_test_floor = 5;

/// Generated names reached only through the frontend package's lexical test
/// inventory. Product executables never receive these design-time modules.
pub const frontend_generated_imports = [_][]const u8{
    "aggregate_capabilities",
    "typed_air_artifacts",
    "typed_air_h009_artifacts",
    "typed_air_h010_artifacts",
};

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

    /// An already-bound module's own in-file tests, as a suite a product test
    /// step can run.
    ///
    /// A `test` written next to the code it covers is compiled only by an
    /// artifact rooted at that code's module. Every module below is one a product
    /// *links*, which compiles the code and none of its tests, so without an
    /// artifact like this one those tests exist and run nowhere -- which is why
    /// `-Driscv-test-filter` reported "matched no test name" for names that
    /// demonstrably existed in the frontend, and why a pin placed beside the code
    /// it pinned did not run.
    pub fn moduleSuite(
        self: Binding,
        module: *std.Build.Module,
        minimum: usize,
    ) test_filter.Suite {
        return .{
            .tests = self.b.addTest(.{
                .root_module = module,
                .filters = test_filter.apply(self.b, &.{}),
            }),
            .minimum = minimum,
        };
    }

    /// The RISC-V frontend package's own tests: the largest test body in the
    /// repository, compiled by no product step until now. A fresh module rather
    /// than the product's own, so making it a test root cannot perturb the
    /// graph the product ships.
    pub fn frontendSuite(self: Binding, protocol: graph.ProtocolModules) test_filter.Suite {
        const frontend = graph.createRiscVFrontend(
            self.b,
            protocol,
            roleProduct(self.product, .@"test"),
            self.target,
            self.optimize,
            null,
        );
        // Compatibility, H-009, and H-010 tests consume checked-in typed-AIR fixtures
        // through separate generated module names. Keep those design-time
        // dependencies on this fresh test root: neither the product's frontend
        // module nor any production executable receives any of these imports.
        frontend.addImport("typed_air_artifacts", self.b.createModule(.{
            .root_source_file = self.b.path(
                "design/typed-air/artifacts/embedded.zig",
            ),
            .target = self.target,
            .optimize = self.optimize,
        }));
        frontend.addImport("typed_air_h009_artifacts", self.b.createModule(.{
            .root_source_file = self.b.path(
                "design/typed-air/artifacts/h009_embedded.zig",
            ),
            .target = self.target,
            .optimize = self.optimize,
        }));
        frontend.addImport("typed_air_h010_artifacts", self.b.createModule(.{
            .root_source_file = self.b.path(
                "design/typed-air/artifacts/h010_embedded.zig",
            ),
            .target = self.target,
            .optimize = self.optimize,
        }));
        return self.moduleSuite(frontend, frontend_test_floor);
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
