//! Authoritative released and deferred product descriptors.

const product_policy = @import("../graph/product.zig");
const aggregate = @import("aggregate.zig");
const cairo_cpu = @import("cairo_cpu.zig");
const cairo_cuda = @import("cairo_cuda.zig");
const cairo_metal = @import("cairo_metal.zig");
const catalog = @import("catalog.zig");
const core = @import("core.zig");
const native_cpu = @import("native_cpu.zig");
const native_cuda = @import("native_cuda.zig");
const native_metal = @import("native_metal.zig");
const prover = @import("prover.zig");
const riscv_cpu = @import("riscv_cpu.zig");
const riscv_cuda = @import("riscv_cuda.zig");
const riscv_metal = @import("riscv_metal.zig");

pub const Scope = catalog.Scope;

pub const Constructor = enum {
    aggregate,
    cairo_cpu,
    cairo_cuda,
    cairo_metal,
    core,
    prover,
    native_cpu,
    native_cuda,
    riscv_cpu,
    native_metal,
    unavailable,
};

pub const Spec = struct {
    descriptor: product_policy.Descriptor,
    scope: Scope,
    constructor: Constructor,
    identity_step: ?[]const u8 = null,
    configure_tools: []const []const u8 = &.{},
    runtime_probes: []const []const u8 = &.{},
    generated_module_roots: []const []const u8 = &.{},
    dependency_module_roots: []const []const u8 = &.{},
    configure_allowed_files: []const []const u8 = &.{},
    configure_allowed_prefixes: []const []const u8 = &.{},
};

pub const products = [_]Spec{
    .{ .descriptor = aggregate.descriptor, .scope = .aggregate, .constructor = .aggregate, .identity_step = "identity-stwo-zig", .configure_tools = &.{"python3"}, .generated_module_roots = &.{"generated:options:"}, .configure_allowed_files = &.{"build_support/graph/identity/emitter.zig"} },
    .{ .descriptor = core.descriptor, .scope = .core, .constructor = .core, .identity_step = "identity-stwo-core", .configure_tools = &.{"python3"}, .generated_module_roots = &.{"generated:options:"}, .configure_allowed_files = &.{"build_support/graph/identity/emitter.zig"} },
    .{ .descriptor = prover.descriptor, .scope = .prover, .constructor = .prover, .identity_step = "identity-stwo-prover", .configure_tools = &.{"python3"}, .generated_module_roots = &.{"generated:options:"}, .configure_allowed_files = &.{ "build_support/graph/identity/emitter.zig", "src/products/core/surface.zig" } },
    .{ .descriptor = native_cpu.descriptor(.cli), .scope = .native_cpu, .constructor = .native_cpu, .configure_tools = &.{"python3"}, .generated_module_roots = &.{"generated:options:"} },
    .{ .descriptor = riscv_cpu.descriptor, .scope = .riscv_cpu, .constructor = .riscv_cpu, .configure_tools = &.{"python3"}, .generated_module_roots = &.{"generated:options:"}, .configure_allowed_files = &.{"src/tests.zig"} },
    .{
        .descriptor = native_metal.descriptor(.cli),
        .scope = .native_metal,
        .constructor = .native_metal,
        .configure_tools = &.{ "python3", "xcrun" },
        .runtime_probes = &.{ "Metal.framework", "Foundation.framework", "libobjc" },
        .generated_module_roots = &.{"generated:options:"},
        .configure_allowed_files = &.{"build_support/product_policy_test.zig"},
    },
    .{
        .descriptor = cairo_cpu.descriptor,
        .scope = .cairo_cpu,
        .constructor = .cairo_cpu,
        .configure_tools = &.{"python3"},
        .generated_module_roots = &.{"generated:options:"},
    },
    .{
        .descriptor = cairo_metal.descriptor,
        .scope = .cairo_metal,
        .constructor = .cairo_metal,
        .configure_tools = &.{ "python3", "xcrun" },
        .runtime_probes = &.{
            "Metal.framework",
            "Foundation.framework",
            "libobjc",
        },
        .generated_module_roots = &.{"generated:options:"},
    },
    .{ .descriptor = riscv_metal.descriptor, .scope = .deferred, .constructor = .unavailable },
    .{
        .descriptor = native_cuda.descriptor,
        .scope = .native_cuda,
        .constructor = .native_cuda,
        .configure_tools = &.{"python3"},
        .runtime_probes = &.{ "cuda", "cudart", "stwo_cuda_kernels" },
    },
    .{
        .descriptor = cairo_cuda.descriptor,
        .scope = .cairo_cuda,
        .constructor = .cairo_cuda,
        .configure_tools = &.{"python3"},
        .runtime_probes = &.{ "cuda", "cudart", "stwo_cuda_kernels" },
        .generated_module_roots = &.{"generated:options:"},
    },
    .{ .descriptor = riscv_cuda.descriptor, .scope = .deferred, .constructor = .unavailable },
};

pub const descriptors = blk: {
    var result: [products.len]product_policy.Descriptor = undefined;
    for (products, 0..) |spec, index| result[index] = spec.descriptor;
    break :blk result;
};

pub fn findByScope(scope: Scope) ?Spec {
    for (products) |spec| {
        if (spec.scope == scope and spec.constructor != .unavailable) return spec;
    }
    return null;
}

pub fn findByProduct(name: []const u8) ?product_policy.Descriptor {
    const std = @import("std");
    for (descriptors) |descriptor| {
        if (std.mem.eql(u8, descriptor.product.name, name)) return descriptor;
    }
    return null;
}

pub fn specForDescriptor(descriptor: product_policy.Descriptor) Spec {
    const std = @import("std");
    for (products) |spec| {
        if (std.mem.eql(u8, spec.descriptor.product.name, descriptor.product.name)) return spec;
    }
    unreachable;
}

test "every central product descriptor is valid" {
    inline for (descriptors) |descriptor| try descriptor.validate();
}

test "every catalog product is represented exactly once" {
    const std = @import("std");
    inline for (products, 0..) |candidate, index| {
        var product_count: usize = 0;
        var build_step_count: usize = 0;
        inline for (products) |other| {
            product_count += @intFromBool(std.mem.eql(
                u8,
                candidate.descriptor.product.name,
                other.descriptor.product.name,
            ));
            build_step_count += @intFromBool(std.mem.eql(
                u8,
                candidate.descriptor.build_step,
                other.descriptor.build_step,
            ));
        }
        try std.testing.expectEqual(@as(usize, 1), product_count);
        try std.testing.expectEqual(@as(usize, 1), build_step_count);
        try std.testing.expectEqualDeep(candidate.descriptor, descriptors[index]);
    }
}
