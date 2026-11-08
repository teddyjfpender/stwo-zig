//! Lifecycle binding for the Cairo CPU/SIMD product.

const std = @import("std");
const package = @import("stwo_cairo_cpu");
const application = @import("cairo_product").application;
const capability_surface = @import("capabilities.zig");
const composition_cpu_aot = @import("cairo_composition_cpu_aot");
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
    // Sample the committed evaluations directly, as the Metal product does.
    // Keeping a second coefficient representation can push large Cairo proofs
    // into memory compression and paging during composition and sampling.
    pub const sampled_evaluation = package.frontends.cairo.proving.transaction.SampledEvaluationStorage.committed_columns;

    pub fn sampledEvaluationStorage() package.frontends.cairo.proving.transaction.SampledEvaluationStorage {
        const value = std.process.getEnvVarOwned(std.heap.page_allocator, "STWO_CAIRO_COMPACT_POLYNOMIALS") catch return sampled_evaluation;
        defer std.heap.page_allocator.free(value);
        if (std.mem.eql(u8, value, "preprocessed")) return .compact_preprocessed;
        return if (std.mem.eql(u8, value, "1")) .compact_polynomials else sampled_evaluation;
    }

    pub fn compositionExecutor() ?package.frontends.cairo.proving.air.native_evaluator.Executor {
        const value = std.process.getEnvVarOwned(std.heap.page_allocator, "STWO_CAIRO_NATIVE_COMPOSITION") catch return composition_cpu_aot.executor();
        defer std.heap.page_allocator.free(value);
        return if (std.mem.eql(u8, value, "1")) composition_cpu_aot.executor() else null;
    }

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

test {
    _ = @import("native_composition_test.zig");
}
