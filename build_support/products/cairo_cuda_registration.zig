//! Cairo CUDA missing-toolchain registration and product identity.

const std = @import("std");
const graph = @import("../graph/product_spec.zig");

pub fn For(comptime descriptor: anytype, comptime toolchain_requirement: []const u8) type {
    return struct {
        pub fn registerMissingToolchain(b: *std.Build) void {
            const unavailable = b.addFail(toolchain_requirement);
            b.step(descriptor.build_step, toolchain_requirement).dependOn(&unavailable.step);
            b.step(descriptor.test_step.?, toolchain_requirement).dependOn(&unavailable.step);
            b.step(descriptor.benchmark_step.?, toolchain_requirement).dependOn(&unavailable.step);
            registerResidentUnavailable(b, toolchain_requirement);
        }

        pub fn registerResidentUnavailable(b: *std.Build, reason: []const u8) void {
            const unavailable = b.addFail(reason);
            b.step("benchmark-circuit-cuda-resident", reason).dependOn(&unavailable.step);
            b.step("circuit-recursion-cuda-resident", reason).dependOn(&unavailable.step);
        }
    };
}

pub const protocol_features = "cairo-stwo-v1+cuda-resident-proof-v1+strict-aot-v1";

pub fn product(role: graph.Role) graph.Product {
    return .{
        .name = "stwo-cairo-cuda",
        .frontend = .cairo,
        .backend = .cuda,
        .role = role,
        .protocol_features = protocol_features,
    };
}
