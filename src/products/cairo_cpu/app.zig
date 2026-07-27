//! Lifecycle binding for the Cairo CPU/SIMD product.

const std = @import("std");
const package = @import("stwo_cairo_cpu");
const application = @import("cairo_product").application;
const capability_surface = @import("capabilities.zig");
const product_identity = @import("identity.zig");

const Product = struct {
    pub const name = "stwo-cairo-cpu";
    pub const backend_name = "cpu";
    pub const backend_description =
        "CPU scalar/SIMD only; no runtime fallback.";
    pub const stwo = package;
    pub const transaction = package.integrations.cairo_cpu.prover.transaction;
    pub const capabilities = capability_surface;
    pub const identity = product_identity;
    pub const ProofContext = void;

    pub fn beginProof(_: std.mem.Allocator) !ProofContext {}

    pub fn finishProof(_: *ProofContext) !application.BackendEvidence {
        return .{
            .execution = "cpu-simd",
            .classification = "host-only",
        };
    }

    pub fn endProof(
        _: *ProofContext,
        evidence: application.BackendEvidence,
    ) !application.BackendEvidence {
        return evidence;
    }

    pub fn abortProof(_: *ProofContext) void {}
};

pub fn main() !void {
    return application.run(Product);
}

test "Cairo CPU application binds the CPU transaction" {
    try std.testing.expectEqualStrings("cpu", Product.backend_name);
}
