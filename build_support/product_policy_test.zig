//! Product matrix state and negative-capability tests.

const std = @import("std");
const cuda = @import("backends/cuda.zig");
const metal = @import("backends/metal.zig");
const product_policy = @import("graph/product.zig");
const native_metal = @import("products/native_metal.zig");
const matrix = @import("products/matrix.zig");

test "deferred compositions are named, reasoned, and non-installable" {
    for (matrix.descriptors) |descriptor| {
        if (descriptor.isConstructible()) continue;
        try descriptor.validate();
        try std.testing.expect(!descriptor.isConstructible());
        try std.testing.expect(descriptor.executable == null);
        try std.testing.expect(descriptor.unavailable_reason.?.len != 0);
    }
}

test "Cairo products expose deliberate release states" {
    for (matrix.descriptors) |descriptor| {
        if (descriptor.product.frontend != .cairo) continue;
        const expected: product_policy.State = switch (descriptor.product.backend) {
            .cpu => .released,
            .metal => .parity_gated,
            .cuda => .staged,
            .none, .contracts => unreachable,
        };
        try std.testing.expectEqual(expected, descriptor.state);
    }
}

test "RISC-V accelerators expose deliberate release states" {
    for (matrix.descriptors) |descriptor| {
        if (descriptor.product.frontend != .riscv or descriptor.product.backend == .cpu)
            continue;
        const expected: product_policy.State = switch (descriptor.product.backend) {
            .metal => .parity_gated,
            .cuda => .unavailable,
            .none, .contracts, .cpu => unreachable,
        };
        try std.testing.expectEqual(expected, descriptor.state);
    }
}

test "CUDA products are explicit Linux constructions without toolchain defaults" {
    for (matrix.descriptors) |descriptor| {
        if (descriptor.product.backend != .cuda) continue;
        if (descriptor.product.frontend == .native or
            descriptor.product.frontend == .cairo)
        {
            try std.testing.expect(descriptor.isConstructible());
            try std.testing.expect(descriptor.isAvailableOn(.linux));
            try std.testing.expect(!descriptor.isAvailableOn(.macos));
        } else {
            try std.testing.expect(!descriptor.isConstructible());
        }
    }
    try std.testing.expectError(error.MissingCudaCompiler, (cuda.Toolchain{}).validate());
}

test "Native Metal is parity-gated and macOS compatible" {
    const descriptor = matrix.find("stwo-native-metal").?;
    try descriptor.validate();
    try std.testing.expect(descriptor.isAvailableOn(.macos));
    try std.testing.expect(!descriptor.isAvailableOn(.linux));
    try std.testing.expect(metal.supports(.macos));
    try std.testing.expect(!metal.supports(.linux));
    try std.testing.expectEqualStrings(
        native_metal.descriptor(.cli).product.name,
        descriptor.product.name,
    );
}

test "composition matrix has unique logical product identities" {
    for (matrix.descriptors, 0..) |descriptor, index| {
        for (matrix.descriptors[index + 1 ..]) |other|
            try std.testing.expect(!std.mem.eql(u8, descriptor.product.name, other.product.name));
    }
}
