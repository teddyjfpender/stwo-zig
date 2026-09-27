//! CPU instantiation of the backend-generic compact secp256k1 proof harness.

const std = @import("std");
const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
const frontend = @import("stwo_riscv_frontend");
const proof_harness = @import("secp256k1_proof_harness");

const LegacyEngine = frontend.prover_mod.ProverEngineForBackend(CpuBackend);

test "secp256k1 typed ECDSA bundle proves and independently verifies" {
    _ = try proof_harness.Harness(LegacyEngine).runSelected(std.heap.smp_allocator);
}

test "CSP ECDSA guest proves caller memory and result at canonical security" {
    try cspProof(LegacyEngine);
}
test "BLAKE3 CSP ECDSA guest proves and verifies at canonical security" {
    const suite = @import("stwo_core").proof_suites.Blake3;
    const Engine = @import("stwo_prover_engine").engine.ProverEngine(CpuBackend, suite.Hasher, suite.MerkleChannel, suite.Channel);
    try cspProof(Engine);
}
fn cspProof(comptime Engine: type) !void {
    try std.testing.expectEqual(@as(usize, 70), frontend.prover_mod.SECURE_PCS_CONFIG.fri_config.n_queries);
    try std.testing.expectEqual(@as(u32, 26), frontend.prover_mod.SECURE_PCS_CONFIG.pow_bits);
    const allocator = std.heap.smp_allocator;
    const csp = frontend.prover_mod.guest_precompile.ecdsa_csp;
    const root = try std.process.getEnvVarOwned(allocator, "STWO_CSP_FIXTURE_ROOT");
    defer allocator.free(root);
    const input_path = try std.fs.path.join(allocator, &.{ root, "inputs/ecdsa_secp256k1.bin" });
    defer allocator.free(input_path);
    const input = try std.fs.cwd().readFileAlloc(allocator, input_path, 161);
    defer allocator.free(input);
    const id = csp.recoveryId(input) orelse return error.MissingRecoveryId;
    const elf_path = try std.fs.path.join(allocator, &.{ root, if (id == 0) "guests/ecdsa_secp256k1_precompile_even.elf" else "guests/ecdsa_secp256k1_precompile_odd.elf" });
    defer allocator.free(elf_path);
    const elf = try std.fs.cwd().readFileAlloc(allocator, elf_path, 1024 * 1024);
    defer allocator.free(elf);
    const profile_enabled = std.process.hasEnvVarConstant("STWO_CSP_PROFILE");
    const stage_profile = @import("stwo_prover_engine").stage_profile;
    var recorder = stage_profile.Recorder.initWithOptions(allocator, "cpu", "csp_ecdsa_guest", .{ .capture_tasks = false });
    defer recorder.deinit();
    const result = csp.proveWithRecorder(Engine, allocator, elf, input, frontend.prover_mod.SECURE_PCS_CONFIG, 16, if (profile_enabled) &recorder else null) catch |err| {
        std.debug.print("CSP guest failure: {s}\n", .{@errorName(err)});
        return err;
    };
    defer allocator.free(result.encoded);
    try std.testing.expectEqual(if (Engine.Hasher == @import("stwo_core").proof_suites.Blake3.Hasher) @import("stwo_core").channel.transcript_receipt.Suite.blake3 else .blake2s, result.transcript_receipt.suite);
    try std.testing.expectEqual(@as(u16, if (Engine.Hasher == @import("stwo_core").proof_suites.Blake3.Hasher) 2 else 1), result.transcript_receipt.version);
    std.debug.print("CSP_ECDSA_GUEST suite={s} queries=70 pow_bits=26 execution_ns={d} proving_ns={d} verify_ns={d} cycles={d} proof_bytes={d}\n", .{
        if (Engine.Hasher == @import("stwo_core").proof_suites.Blake3.Hasher) "blake3" else "blake2s", result.execution_ns, result.proving_ns, result.verification_ns, result.cycles, result.proof_bytes,
    });
    if (profile_enabled) {
        var profile = try recorder.snapshot(allocator);
        defer profile.deinit(allocator);
        const json = try std.json.Stringify.valueAlloc(allocator, profile, .{});
        defer allocator.free(json);
        std.debug.print("CSP_ECDSA_PROFILE suite={s} {s}\n", .{ @tagName(result.transcript_receipt.suite), json });
    }
    input[0] ^= 1;
    try std.testing.expectError(error.CspInputMismatch, csp.verify(Engine, allocator, elf, input, frontend.prover_mod.SECURE_PCS_CONFIG, result.encoded));
    input[0] ^= 1;
    const other_path = try std.fs.path.join(allocator, &.{ root, if (id == 0) "guests/ecdsa_secp256k1_precompile_odd.elf" else "guests/ecdsa_secp256k1_precompile_even.elf" });
    defer allocator.free(other_path);
    const other_elf = try std.fs.cwd().readFileAlloc(allocator, other_path, 1024 * 1024);
    defer allocator.free(other_elf);
    try std.testing.expectError(error.CspElfBindingMismatch, csp.verify(Engine, allocator, other_elf, input, frontend.prover_mod.SECURE_PCS_CONFIG, result.encoded));
    try std.testing.expectError(error.OutputAddressNotAccessed, csp.prove(Engine, allocator, other_elf, input, frontend.prover_mod.SECURE_PCS_CONFIG, 16));
    input[32] = 3;
    try std.testing.expect(csp.recoveryId(input) == null);
    input[32] = 4;
    const original_s = input[129..161].*;
    @memset(input[129..161], 0xff);
    try std.testing.expect(csp.recoveryId(input) == null);
    @memset(input[129..161], 0);
    try std.testing.expect(csp.recoveryId(input) == null);
    @memcpy(input[129..161], &original_s);
    result.encoded[result.encoded.len - 1] ^= 1;
    if (csp.verify(Engine, allocator, elf, input, frontend.prover_mod.SECURE_PCS_CONFIG, result.encoded)) |_| {
        return error.TamperedProofAccepted;
    } else |_| {}
}
