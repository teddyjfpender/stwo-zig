//! Canonical full-width BLAKE3 proving with retained historical artifact verification.

const std = @import("std");
const stwo = @import("stwo");
const capabilities = @import("riscv_cpu_capabilities");
const artifact_validation = @import("proof_adapter/artifact_validation.zig");
const artifact_verifier = @import("proof_adapter/artifact_verifier.zig");
const pcs_profile = @import("proof_adapter/pcs_profile.zig");
const profile_router = @import("proof_adapter/profile_router.zig");

pub const AdapterError = error{AdapterNotReleaseGated};

pub const PENDING_DIAGNOSTIC =
    "RISC-V adapter: staged only; the formal release contract is not yet fully satisfied";

pub const Benchmark = struct {
    warmups: usize,
    samples: usize,
    profiled: bool,
};

pub const Backend = enum { cpu, metal, unavailable_device };
pub const Protocol = pcs_profile.Protocol;

pub const Mode = union(enum) {
    prove,
    bench: Benchmark,
};

pub const Options = struct {
    backend: Backend,
    protocol: Protocol,
    mode: Mode,
    experimental: bool,
    /// Sibling temporary path owned and published by the CLI transaction.
    proof_temporary: ?[]const u8,
    /// Final path recorded in the report; the adapter never publishes it.
    proof_report_path: ?[]const u8,
    workers: ?usize = null,
    csp_ecdsa: bool = false,
    host_byte_budget: ?usize = null,
};

pub fn run(
    comptime Engine: type,
    comptime backend: Backend,
    allocator: std.mem.Allocator,
    elf_path: []const u8,
    input_path: ?[]const u8,
    options: Options,
) ![]u8 {
    if (comptime Engine.Hasher != stwo.core.proof_suites.Blake3.Hasher) return error.LegacyProofGenerationRemoved;
    comptime stwo.frontends.riscv.prover_mod.assertProverEngine(Engine);
    comptime std.debug.assert(backend != .unavailable_device);
    try capabilities.requireAdmission(options.experimental);
    if (options.backend != backend) return error.AdapterNotReleaseGated;
    // Build pipelines and libraries before the first timed sample. This does not
    // distort `resources`: the footprint is an absolute process-lifetime peak
    // read from the *after* snapshot.
    if (comptime @hasDecl(Engine, "warmup")) try Engine.warmup();
    const process_identity = try artifact_validation.measureProcessIdentity(allocator);
    return profile_router.run(Engine, backend, allocator, elf_path, input_path, options, process_identity);
}

/// Cryptographically verifies a staged artifact using the focused verifier.
pub fn verifyArtifact(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    artifact: stwo.interop.riscv_artifact.Artifact,
    requested_policy: Protocol,
    expected_statement_digest: [32]u8,
    elf_path: []const u8,
) !void {
    return artifact_verifier.verify(
        Engine,
        allocator,
        artifact,
        requested_policy,
        expected_statement_digest,
        elf_path,
    );
}

/// Routes retained base, guest-profile and full-width BLAKE3 artifacts by exact wire identity.
pub const verifyPath = profile_router.verifyPath;
pub const verifyCspPath = @import("proof_adapter/blake3_execution_verifier.zig").verifyCspPath;

/// The engine this module's own tests exercise, resolved from whichever product
/// facade compiled them. The tests must not name a concrete integration package:
/// this file is a shared seam, and when it is compiled as a test root inside the
/// Metal product `stwo.integrations.riscv_cpu` does not exist to be resolved.
///
/// Each focused facade declares exactly one RISC-V integration --
/// `src/stwo_riscv_cpu.zig` declares only `riscv_cpu` and
/// `src/products/riscv_metal/root.zig` declares only `riscv_metal` -- so
/// `@hasDecl` is a total discriminator here rather than a feature probe. The
/// condition is comptime-known, so only the branch that resolves is analysed and
/// the absent facade member is never named in the compiled product. The
/// aggregate `src/stwo.zig` facade routes through `integrations/mod.zig`, which
/// declares `riscv_cpu`, and so takes the same branch as the CPU product.
const LegacyTestEngine = if (@hasDecl(stwo.integrations, "riscv_cpu"))
    stwo.integrations.riscv_cpu.CpuProverEngine
else
    stwo.integrations.riscv_metal.MetalProverEngine;

const suite = stwo.core.proof_suites.Blake3;
const TestEngine = @import("stwo_prover_engine").engine.ProverEngine(LegacyTestEngine.Backend, suite.Hasher, suite.MerkleChannel, suite.Channel);

/// The backend tag `TestEngine` commits to. `run` rejects an `Options.backend`
/// that disagrees with its comptime `backend` parameter, so the two must be
/// selected together.
const test_backend: Backend = if (@hasDecl(stwo.integrations, "riscv_cpu")) .cpu else .metal;

test "adapter preserves the complete sampled benchmark contract" {
    const options = Options{
        .backend = test_backend,
        .protocol = .functional,
        .mode = .{ .bench = .{ .warmups = 3, .samples = 7, .profiled = true } },
        .experimental = !capabilities.adapter_release_gated,
        .proof_temporary = "proof.tmp",
        .proof_report_path = "proof.json",
    };
    try std.testing.expectEqual(@as(usize, 3), options.mode.bench.warmups);
    try std.testing.expectEqual(@as(usize, 7), options.mode.bench.samples);
    try std.testing.expect(options.mode.bench.profiled);
    try std.testing.expectError(
        error.FileNotFound,
        run(TestEngine, test_backend, std.testing.allocator, "guest.elf", "input.bin", options),
    );
}

test {
    _ = @import("proof_adapter/benchmark_report.zig");
    _ = @import("proof_adapter/provenance_test.zig");
    _ = @import("proof_adapter/staged_pcs_profile_test.zig");
    _ = @import("proof_adapter/verified_request_binding_test.zig");
    _ = @import("proof_adapter/wire_arena_allocation_test.zig");
}

test "adapter fail-closes through the shared run-admission gate" {
    const prover = stwo.frontends.riscv.prover_mod;
    // Every completion reason but the two proof-bearing ones must be refused,
    // and the refusal must come from the gate this adapter calls rather than
    // from a private copy. The full-width request invokes `admitRunForProving`, so
    // a regression here is a regression in what the adapter enforces.
    for (std.enums.values(stwo.frontends.riscv.runner.CompletionReason)) |reason| {
        const provable = reason == .halt_flag or reason == .self_loop;
        const rejection = prover.classifyCompletion(reason);
        try std.testing.expectEqual(provable, rejection == null);
        if (rejection) |value| try std.testing.expectEqual(
            prover.RunAdmissionError.UnprovableCompletion,
            value.toError(),
        );
    }
}

test "adapter refuses legacy proving before input or runtime access" {
    try std.testing.expectError(error.LegacyProofGenerationRemoved, run(LegacyTestEngine, test_backend, std.testing.allocator, "missing.elf", null, .{
        .backend = test_backend,
        .protocol = .secure,
        .mode = .prove,
        .experimental = false,
        .proof_temporary = null,
        .proof_report_path = null,
    }));
}
