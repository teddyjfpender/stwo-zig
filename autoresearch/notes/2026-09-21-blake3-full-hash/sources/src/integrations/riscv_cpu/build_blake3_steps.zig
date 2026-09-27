//! Focused BLAKE3 migration gates; intentionally independent of full prover suites.
const support = @import("build_support.zig");
pub fn add(ctx: anytype) void {
    const b = ctx.b;
    const target = ctx.target;
    const optimize = ctx.optimize;
    const core = ctx.core;
    const prover = ctx.prover;
    const cpu_backend = ctx.cpu_backend;
    const frontend = ctx.frontend;
    const integration = ctx.integration;
    const hash_root = support.createHarnessModule(b, "../../frontends/riscv/blake3_hash_test_root.zig", target, optimize, core, cpu_backend, frontend, integration);
    const hash_names: []const []const u8 = &.{
        "BLAKE3 hash DAG matches standard hashing across blocks chunks and unbalanced trees",
        "BLAKE3 hash global wires reject chaining flags and digest substitutions",
        "BLAKE3 hash graph releases every partial allocation",
    };
    const hash_tests = b.addTest(.{ .root_module = hash_root, .filters = hash_names });
    b.step("test-blake3-hash", "Check canonical full-hash schedules and cross-compression typed wires")
        .dependOn(support.ProofTestGuard.add(b, b.addRunArtifact(hash_tests), hash_names, "BLAKE3 hash graph guard"));
    const framework_root = support.createHarnessModule(b, "../../frontends/riscv/blake3_framework_test_root.zig", target, optimize, core, cpu_backend, frontend, integration);
    framework_root.addImport("stwo_prover_engine", prover);
    const framework_names: []const []const u8 = &.{
        "BLAKE3 boundary pins semantics and exports committed framework programs",
        "BLAKE3 padded framework and production table interaction claims close",
    };
    const framework_tests = b.addTest(.{ .root_module = framework_root, .filters = framework_names });
    b.step("test-blake3-framework", "Check typed boundary exports and full padded interaction claim closure")
        .dependOn(support.ProofTestGuard.add(b, b.addRunArtifact(framework_tests), framework_names, "BLAKE3 framework guard"));
    const proof_names: []const []const u8 = &.{
        "BLAKE3 compression committed proof verifies with trusted preprocessing",
        "BLAKE3 full hash committed proofs cover empty partial and unbalanced chunk trees",
    };
    const proof_tests = b.addTest(.{ .root_module = framework_root, .filters = proof_names });
    b.step("test-blake3-proof", "Prove and verify the complete BLAKE3 compression circuit on CPU")
        .dependOn(support.ProofTestGuard.add(b, b.addRunArtifact(proof_tests), proof_names, "BLAKE3 committed proof guard"));
    const blake3_wiring_root = support.createHarnessModule(b, "../../frontends/riscv/blake3_wiring_test_root.zig", target, optimize, core, cpu_backend, frontend, integration);
    const blake3_wiring_names: []const []const u8 = &.{
        "BLAKE3 call components pin semantics and authenticate relation plans",
        "BLAKE3 fixed compression wire graph closes and rejects endpoint substitutions",
        "BLAKE3 ordered call construction releases partial allocations",
    };
    const blake3_wiring_tests = b.addTest(.{ .root_module = blake3_wiring_root, .filters = blake3_wiring_names });
    b.step("test-blake3-wiring", "Check typed BLAKE3 call bindings and exact compression wire closure")
        .dependOn(support.ProofTestGuard.add(b, b.addRunArtifact(blake3_wiring_tests), blake3_wiring_names, "BLAKE3 wiring guard"));
    const blake3_packed_root = support.createHarnessModule(b, "../../frontends/riscv/blake3_packed_test_root.zig", target, optimize, core, cpu_backend, frontend, integration);
    const blake3_packed_names: []const []const u8 = &.{
        "BLAKE3 compact G matches typed bit reference and canonical lookup schemas",
        "BLAKE3 compact G rejects coordinate mutations and requires lookup bounds",
        "BLAKE3 compact G covers all seven rounds of a native compression trace",
    };
    const blake3_packed_tests = b.addTest(.{ .root_module = blake3_packed_root, .filters = blake3_packed_names });
    b.step("test-blake3-packed", "Check compact typed BLAKE3 arithmetic and exact lookup requests")
        .dependOn(support.ProofTestGuard.add(b, b.addRunArtifact(blake3_packed_tests), blake3_packed_names, "BLAKE3 packed guard"));
    const blake3_compression_root = support.createHarnessModule(b, "../../frontends/riscv/blake3_compression_test_root.zig", target, optimize, core, cpu_backend, frontend, integration);
    const blake3_compression_names: []const []const u8 = &.{
        "BLAKE3 typed G has degree two and agrees with native arithmetic",
        "BLAKE3 typed G rejects every single-bit mutation and nonboolean witnesses",
        "BLAKE3 seven-round compression matches standard hash across chunks",
        "BLAKE3 typed arithmetic covers all scheduled compression calls",
    };
    const blake3_compression_test = b.addTest(.{ .root_module = blake3_compression_root, .filters = blake3_compression_names });
    b.step("test-blake3-compression", "Check canonical compression and typed degree-two G arithmetic")
        .dependOn(support.ProofTestGuard.add(b, b.addRunArtifact(blake3_compression_test), blake3_compression_names, "BLAKE3 compression guard"));
    const blake3_benchmark_root = support.createHarnessModule(b, "blake3_hash_benchmark.zig", target, optimize, core, cpu_backend, frontend, integration);
    const blake3_benchmark = b.addExecutable(.{ .name = "blake3-hash-benchmark", .root_module = blake3_benchmark_root });
    b.step("benchmark-blake3-hash", "Measure native BLAKE3 and Poseidon hashing, excluding recursive constraints")
        .dependOn(&b.addRunArtifact(blake3_benchmark).step);
    const blake3_root = support.createHarnessModule(b, "blake3_test_root.zig", target, optimize, core, cpu_backend, frontend, integration);
    blake3_root.addImport("stwo_prover_engine", prover);
    const blake3_names: []const []const u8 = &.{
        "BLAKE3 official primitive vectors and streaming boundaries",
        "BLAKE3 independent protocol vectors retain full digest bits",
        "BLAKE3 field rejection and operation domains",
        "BLAKE3 CPU PCS and FRI roundtrip with core verifier",
        "BLAKE3 CPU commitments reject tampered roots and wrong hash family",
    };
    const blake3_tests = b.addTest(.{ .root_module = blake3_root, .filters = blake3_names });
    b.step("test-blake3-protocol", "Check BLAKE3 reference vectors, transcript, commitments and CPU PCS/FRI")
        .dependOn(support.ProofTestGuard.add(b, b.addRunArtifact(blake3_tests), blake3_names, "BLAKE3 protocol test guard"));
}
