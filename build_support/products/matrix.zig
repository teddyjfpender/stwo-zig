//! Product construction facade backed by one typed catalog.

const std = @import("std");
const build_identity = @import("../build_identity.zig");
const construction_observer = @import("../graph/construction_observer.zig");
const delegation = @import("../graph/delegation.zig");
const graph = @import("../graph/modules.zig");
const product_policy = @import("../graph/product.zig");
const aggregate = @import("aggregate.zig");
const aggregate_cli = @import("aggregate_cli.zig");
const catalog_manifest = @import("catalog_manifest.zig");
const cairo_cpu = @import("cairo_cpu.zig");
const cairo_cuda = @import("cairo_cuda.zig");
const core = @import("core.zig");
const native_cpu = @import("native_cpu.zig");
const native_cuda = @import("native_cuda.zig");
const native_metal = @import("native_metal.zig");
const prover = @import("prover.zig");
const riscv_cpu = @import("riscv_cpu.zig");
const specs = @import("product_specs.zig");

pub const Scope = specs.Scope;
pub const Constructor = specs.Constructor;
pub const Spec = specs.Spec;
pub const products = specs.products;
pub const descriptors = specs.descriptors;
pub const ScopeManifest = catalog_manifest.ScopeManifest;

pub const ConstructionContext = struct {
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    identity: build_identity.Identity,
};

pub fn constructAggregate(b: *std.Build, metal_enabled: bool) void {
    const spec = findByScope(.aggregate) orelse @panic("aggregate product missing from catalog");
    if (spec.constructor != .aggregate) @panic("aggregate catalog constructor mismatch");
    aggregate_cli.addProduct(b, metal_enabled);
    construction_observer.recordConstructor(b, constructorName(spec.constructor));
    construction_observer.recordProduct(b, aggregate.product(metal_enabled));
    addIdentity(b, metal_enabled);
    construction_observer.recordConstructor(b, "products/matrix.addIdentity");
}

pub fn construct(context: ConstructionContext, scope: Scope) bool {
    for (products) |spec| {
        if (spec.scope != scope or spec.constructor == .unavailable) continue;
        switch (spec.constructor) {
            .aggregate => unreachable,
            .cairo_cpu => cairo_cpu.addProduct(.{
                .b = context.b,
                .target = context.target,
                .optimize = context.optimize,
                .identity = context.identity,
                .protocol = graph.createPrivateProtocolModules(context.b, context.target, context.optimize),
            }),
            .cairo_cuda => cairo_cuda.addProduct(.{
                .b = context.b,
                .target = context.target,
                .optimize = context.optimize,
                .identity = context.identity,
                .protocol = graph.createPrivateProtocolModules(context.b, context.target, context.optimize),
            }),
            .core => _ = core.addProduct(.{
                .b = context.b,
                .target = context.target,
                .optimize = context.optimize,
                .identity = context.identity,
            }),
            .prover => {
                const core_result = core.addProduct(.{
                    .b = context.b,
                    .target = context.target,
                    .optimize = context.optimize,
                    .identity = context.identity,
                });
                _ = prover.addProduct(.{
                    .b = context.b,
                    .target = context.target,
                    .optimize = context.optimize,
                    .core = core_result.module,
                    .identity = context.identity,
                });
            },
            .native_cpu => native_cpu.addProduct(.{
                .b = context.b,
                .target = context.target,
                .optimize = context.optimize,
                .identity = context.identity,
                .protocol = graph.createPrivateProtocolModules(context.b, context.target, context.optimize),
            }),
            .native_cuda => native_cuda.addProduct(.{
                .b = context.b,
                .target = context.target,
                .optimize = context.optimize,
                .identity = context.identity,
                .protocol = graph.createPrivateProtocolModules(context.b, context.target, context.optimize),
            }),
            .native_metal => native_metal.addProduct(.{
                .b = context.b,
                .target = context.target,
                .optimize = context.optimize,
                .identity = context.identity,
                .protocol = graph.createPrivateProtocolModules(context.b, context.target, context.optimize),
            }),
            .riscv_cpu => riscv_cpu.addProduct(.{
                .b = context.b,
                .target = context.target,
                .optimize = context.optimize,
                .identity = context.identity,
                .protocol = graph.createPrivateProtocolModules(context.b, context.target, context.optimize),
            }),
            .unavailable => unreachable,
        }
        construction_observer.recordConstructor(context.b, constructorName(spec.constructor));
        construction_observer.recordProduct(context.b, spec.descriptor.product);
        return true;
    }
    return false;
}

pub fn addRootProxies(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    options: delegation.Options,
) void {
    for (products) |spec| {
        addProxy(b, target, optimize, options, spec.descriptor.build_step, @tagName(spec.scope));
        if (spec.descriptor.test_step) |step| addProxy(
            b,
            target,
            optimize,
            options,
            step,
            @tagName(spec.scope),
        );
        if (spec.descriptor.benchmark_step) |step| {
            if (!std.mem.eql(u8, step, spec.descriptor.build_step))
                addProxy(b, target, optimize, options, step, @tagName(spec.scope));
        }
        if (spec.identity_step) |step| addProxy(
            b,
            target,
            optimize,
            options,
            step,
            @tagName(spec.scope),
        );
    }
    addProxy(b, target, optimize, options, "product-matrix-identity", "aggregate");
}

fn addProxy(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    options: delegation.Options,
    name: []const u8,
    scope: []const u8,
) void {
    delegation.addProxy(
        b,
        target,
        optimize,
        options,
        name,
        b.fmt("Build or validate product step {s}", .{name}),
        scope,
    );
}

pub fn find(name: []const u8) ?product_policy.Descriptor {
    return specs.findByProduct(name);
}

pub fn findByScope(scope: Scope) ?Spec {
    return specs.findByScope(scope);
}

pub fn addDeferredProducts(b: *std.Build, target: std.Build.ResolvedTarget) void {
    inline for (descriptors) |descriptor| {
        if (!descriptor.isConstructible())
            product_policy.registerUnavailable(b, descriptor, target.result.os.tag);
    }
}

pub fn scopeManifest(b: *std.Build, scope: Scope, aggregate_metal: bool) ScopeManifest {
    return catalog_manifest.scopeManifest(b, scope, aggregate_metal);
}

pub fn stepsForScope(b: *std.Build, scope: Scope) []const []const u8 {
    return catalog_manifest.stepsForScope(b, scope);
}

pub fn addIdentity(b: *std.Build, aggregate_metal: bool) void {
    catalog_manifest.addIdentity(b, aggregate_metal);
}

pub fn constructorName(constructor: Constructor) []const u8 {
    return catalog_manifest.constructorName(constructor);
}

test "aggregate descriptor records its selected capability" {
    try std.testing.expectEqualStrings("stwo-zig", aggregate.descriptor.product.name);
    try std.testing.expectEqual(.aggregate, aggregate.descriptor.product.frontend);
    try std.testing.expectEqual(.cpu, aggregate.descriptor.product.backend);
    try std.testing.expectEqualDeep(aggregate.descriptor.product, aggregate.product(false));
    try std.testing.expect(!std.meta.eql(aggregate.product(false), aggregate.product(true)));
    try std.testing.expectEqual(.metal, aggregate.descriptorFor(true).product.backend);
}
