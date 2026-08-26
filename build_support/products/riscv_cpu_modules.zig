//! Shared module construction for RISC-V CPU product and focused test roots.
const std = @import("std");
const graph = @import("../graph/modules.zig");
const shared_shell = @import("riscv_shared_shell.zig");

pub fn roleProduct(product: graph.Product, role: graph.Role) graph.Product {
    return shared_shell.roleProduct(product, role);
}

pub fn binding(
    b: *std.Build,
    product: graph.Product,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) shared_shell.Binding {
    return .{
        .b = b,
        .product = product,
        .target = target,
        .optimize = optimize,
    };
}

pub fn capabilities(
    b: *std.Build,
    product: graph.Product,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) *std.Build.Module {
    return binding(b, product, target, optimize).leafModule(
        "src/products/riscv_cpu/capabilities.zig",
    );
}

pub fn outputTransaction(
    b: *std.Build,
    product: graph.Product,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) *std.Build.Module {
    return binding(b, product, target, optimize).leafModule(
        "src/interop/output_transaction.zig",
    );
}
