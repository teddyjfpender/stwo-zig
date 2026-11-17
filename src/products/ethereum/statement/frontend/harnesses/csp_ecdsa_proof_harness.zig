//! Shared canonical CSP qualification for explicitly selected proof engines.
const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

pub fn cspProof(comptime Engine: type, backend_name: []const u8) !void {
    try std.testing.expectEqual(@as(usize, 70), frontend.prover_mod.SECURE_PCS_CONFIG.fri_config.n_queries);
    try std.testing.expectEqual(@as(u32, 26), frontend.prover_mod.SECURE_PCS_CONFIG.pow_bits);
    const allocator = std.heap.smp_allocator;
    const csp = @import("../prover/guest_precompile/ecdsa_csp.zig");
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
    var recorder = stage_profile.Recorder.initWithOptions(allocator, backend_name, "csp_ecdsa_guest", .{ .capture_tasks = false });
    defer recorder.deinit();
    const result = csp.proveWithRecorder(Engine, allocator, elf, input, frontend.prover_mod.SECURE_PCS_CONFIG, 16, if (profile_enabled) &recorder else null) catch |err| {
        std.debug.print("CSP guest failure: {s}\n", .{@errorName(err)});
        if (err == error.ConstraintsNotSatisfied) {
            var elf_hash: [32]u8 = undefined;
            var input_hash: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(elf, &elf_hash, .{});
            std.crypto.hash.sha2.Sha256.hash(input, &input_hash, .{});
            std.debug.print("CSP failure identity cpu={s} elf={s} input={s}\n", .{
                @import("builtin").target.cpu.model.name,
                std.fmt.bytesToHex(elf_hash, .lower),
                std.fmt.bytesToHex(input_hash, .lower),
            });
            // Diagnostic only: preserve the original required proof's failure.
            // The control changes scheduling, never the statement or security.
            if (csp.prove(Engine, allocator, elf, input, frontend.prover_mod.SECURE_PCS_CONFIG, 1)) |control| {
                defer allocator.free(control.encoded);
                std.debug.print("CSP one-worker control: PASS suite={s} proof_bytes={d}\n", .{
                    @tagName(control.transcript_receipt.suite), control.proof_bytes,
                });
            } else |control_error| {
                std.debug.print("CSP one-worker control: FAIL {s}\n", .{@errorName(control_error)});
            }
        }
        return err;
    };
    defer allocator.free(result.encoded);
    try std.testing.expectEqual(if (Engine.Hasher == @import("stwo_core").proof_suites.Blake3.Hasher) @import("stwo_core").channel.transcript_receipt.Suite.blake3 else .blake2s, result.transcript_receipt.suite);
    try std.testing.expectEqual(@as(u16, if (Engine.Hasher == @import("stwo_core").proof_suites.Blake3.Hasher) 2 else 1), result.transcript_receipt.version);
    std.debug.print("CSP_ECDSA_GUEST backend={s} suite={s} queries=70 pow_bits=26 execution_ns={d} proving_ns={d} verify_ns={d} cycles={d} proof_bytes={d}\n", .{
        backend_name, if (Engine.Hasher == @import("stwo_core").proof_suites.Blake3.Hasher) "blake3" else "blake2s", result.execution_ns, result.proving_ns, result.verification_ns, result.cycles, result.proof_bytes,
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
