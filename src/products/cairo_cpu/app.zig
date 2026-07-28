//! Lifecycle binding for the Cairo CPU/SIMD product.

const std = @import("std");
const package = @import("stwo_cairo_cpu");
const application = @import("cairo_product").application;
const capability_surface = @import("capabilities.zig");
const witness_cpu_aot = @import("cairo_witness_cpu_aot");
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

    pub fn witnessExecutor() ?package.frontends.cairo.witness.generated_executor.Executor {
        return witness_cpu_aot.executor();
    }

    pub fn interactionExecutor(
        _: *ProofContext,
    ) ?package.frontends.cairo.witness.interaction_executor.Executor {
        return null;
    }

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

test "Cairo CPU generated writers cover every authenticated program" {
    var bundle = try package.frontends.cairo.witness.bundle.Bundle.readFile(
        std.testing.allocator,
        "vectors/cairo/official/witness_programs_v1.bin",
    );
    defer bundle.deinit();
    try std.testing.expectEqual(
        bundle.entries.len,
        witness_cpu_aot.generated_program_count,
    );
    const executor = Product.witnessExecutor().?;
    for (bundle.entries) |entry| {
        try std.testing.expect(executor.resolve(entry.program) != null);
    }
}
