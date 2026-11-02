//! Shared build-catalog vocabulary, independent of the step/configuration data.
const construction_observer = @import("../graph/construction_observer.zig");

pub const Scope = enum {
    aggregate,
    architecture,
    cairo_cpu,
    cairo_metal,
    circuit_recursion_cpu,
    compatibility_tools,
    core,
    cairo_cuda,
    cuda_tools,
    deferred,
    metal_tools,
    native_cpu,
    native_cuda,
    native_metal,
    package,
    policy,
    prover,
    release,
    riscv_cpu,
    riscv_cpu_compat,
    riscv_metal,
    verification,
};

pub const Step = struct {
    name: []const u8,
    description: []const u8,
    scope: Scope,
};

pub const ScopeRole = enum {
    product,
    package_exports,
    compatibility_tools,
    backend_tools,
    gates,
    unavailable,
};

pub const Configure = struct {
    scope: Scope,
    role: ScopeRole,
    inherited_product_scope: ?Scope = null,
    product_ids: []const []const u8 = &.{},
    module_roots: []const []const u8 = &.{},
    generated_module_roots: []const []const u8 = &.{},
    dependency_module_roots: []const []const u8 = &.{},
    allowed_module_files: []const []const u8 = &.{},
    allowed_module_prefixes: []const []const u8 = &.{},
    external_tools: []const []const u8 = &.{},
    runtime_probes: []const []const u8 = &.{},
    constructors: []const []const u8,
    constructed_products: []const construction_observer.ProductIdentity = &.{},
};
