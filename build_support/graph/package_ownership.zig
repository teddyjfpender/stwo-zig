//! Checked source-owner to Zig-package projection.
//!
//! `src/**/package.contract.json` is authoritative. The package-workspace gate
//! rejects any prefix or dependency-name drift in this build-time projection.

const std = @import("std");

pub const Package = enum {
    core,
    backend_contracts,
    prover_api,
    prover,
    cairo_frontend,
    cpu_backend,
    cuda_backend,
    metal_backend,
    riscv_frontend,
    riscv_cpu_integration,
    cairo_cpu_integration,
    riscv_metal_integration,
    cairo_metal_integration,
    metal_session,
    proof_wire,
    native_examples,
    native_cuda_integration,
    cairo_cuda_integration,
};

pub const Source = struct {
    package: Package,
    sub_path: []const u8,
};

const Owner = struct {
    prefix: []const u8,
    package: Package,
    dependency_name: []const u8,
};

const owners = [_]Owner{
    .{ .prefix = "src/core/", .package = .core, .dependency_name = "stwo_core" },
    .{ .prefix = "src/backend/", .package = .backend_contracts, .dependency_name = "stwo_backend_contracts" },
    .{ .prefix = "src/prover_api/", .package = .prover_api, .dependency_name = "stwo_prover_api" },
    .{ .prefix = "src/prover/", .package = .prover, .dependency_name = "stwo_prover_engine" },
    .{ .prefix = "src/frontends/cairo/", .package = .cairo_frontend, .dependency_name = "stwo_cairo_frontend" },
    .{ .prefix = "src/backends/cpu_scalar/", .package = .cpu_backend, .dependency_name = "stwo_cpu_backend" },
    .{ .prefix = "src/backends/cuda/", .package = .cuda_backend, .dependency_name = "stwo_cuda_backend" },
    .{ .prefix = "src/backends/metal/", .package = .metal_backend, .dependency_name = "stwo_metal_backend" },
    .{ .prefix = "src/frontends/riscv/", .package = .riscv_frontend, .dependency_name = "stwo_riscv_frontend" },
    .{ .prefix = "src/integrations/riscv_cpu/", .package = .riscv_cpu_integration, .dependency_name = "stwo_riscv_cpu_integration" },
    .{ .prefix = "src/integrations/cairo_cpu/", .package = .cairo_cpu_integration, .dependency_name = "stwo_cairo_cpu_integration" },
    .{ .prefix = "src/integrations/riscv_metal/", .package = .riscv_metal_integration, .dependency_name = "stwo_riscv_metal_integration" },
    .{ .prefix = "src/integrations/cairo_metal/", .package = .cairo_metal_integration, .dependency_name = "stwo_cairo_metal_integration" },
    .{ .prefix = "src/tools/metal_session/", .package = .metal_session, .dependency_name = "stwo_metal_session" },
    .{ .prefix = "src/interop/proof_wire/", .package = .proof_wire, .dependency_name = "stwo_proof_wire" },
    .{ .prefix = "src/examples/", .package = .native_examples, .dependency_name = "stwo_native_examples" },
    .{ .prefix = "src/integrations/native_cuda/", .package = .native_cuda_integration, .dependency_name = "stwo_native_cuda_integration" },
    .{ .prefix = "src/integrations/cairo_cuda/", .package = .cairo_cuda_integration, .dependency_name = "stwo_cairo_cuda_integration" },
};

pub fn resolve(root_source_file: []const u8) ?Source {
    for (owners) |owner| {
        if (std.mem.startsWith(u8, root_source_file, owner.prefix)) return .{
            .package = owner.package,
            .sub_path = root_source_file[owner.prefix.len..],
        };
    }
    return null;
}

pub fn dependencyName(package: Package) []const u8 {
    for (owners) |owner| {
        if (owner.package == package) return owner.dependency_name;
    }
    unreachable;
}

test "canonical owner roots resolve to package dependencies" {
    try std.testing.expectEqual(Package.core, resolve("src/core/mod.zig").?.package);
    try std.testing.expectEqual(
        Package.backend_contracts,
        resolve("src/backend/mod.zig").?.package,
    );
    try std.testing.expectEqual(
        Package.prover_api,
        resolve("src/prover_api/mod.zig").?.package,
    );
    try std.testing.expectEqual(
        Package.prover,
        resolve("src/prover/mod.zig").?.package,
    );
    try std.testing.expectEqualStrings(
        "native/runner.zig",
        resolve("src/prover/native/runner.zig").?.sub_path,
    );
    try std.testing.expectEqual(
        Package.cairo_frontend,
        resolve("src/frontends/cairo/mod.zig").?.package,
    );
    try std.testing.expectEqual(
        Package.cpu_backend,
        resolve("src/backends/cpu_scalar/mod.zig").?.package,
    );
    try std.testing.expectEqual(
        Package.cuda_backend,
        resolve("src/backends/cuda/mod.zig").?.package,
    );
    try std.testing.expectEqual(
        Package.metal_backend,
        resolve("src/backends/metal/mod.zig").?.package,
    );
    try std.testing.expectEqual(
        Package.riscv_frontend,
        resolve("src/frontends/riscv/mod.zig").?.package,
    );
    try std.testing.expectEqual(
        Package.riscv_cpu_integration,
        resolve("src/integrations/riscv_cpu/mod.zig").?.package,
    );
    try std.testing.expectEqual(
        Package.cairo_cpu_integration,
        resolve("src/integrations/cairo_cpu/mod.zig").?.package,
    );
    try std.testing.expectEqual(
        Package.riscv_metal_integration,
        resolve("src/integrations/riscv_metal/mod.zig").?.package,
    );
    try std.testing.expectEqual(
        Package.cairo_metal_integration,
        resolve("src/integrations/cairo_metal/mod.zig").?.package,
    );
    try std.testing.expectEqual(
        Package.metal_session,
        resolve("src/tools/metal_session/mod.zig").?.package,
    );
    try std.testing.expectEqual(
        Package.proof_wire,
        resolve("src/interop/proof_wire/mod.zig").?.package,
    );
    try std.testing.expectEqual(
        Package.native_examples,
        resolve("src/examples/mod.zig").?.package,
    );
    try std.testing.expectEqual(
        Package.native_cuda_integration,
        resolve("src/integrations/native_cuda/mod.zig").?.package,
    );
    try std.testing.expectEqual(
        Package.cairo_cuda_integration,
        resolve("src/integrations/cairo_cuda/mod.zig").?.package,
    );
    try std.testing.expect(resolve("src/products/prover/root.zig") == null);
}
