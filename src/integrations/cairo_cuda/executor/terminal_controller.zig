//! Sole Cairo CUDA terminal read and strict canonical proof reconstruction.

const std = @import("std");
const compact = @import("stwo_cairo_frontend").compact_verifier_interchange;
const runtime_session = @import("stwo_cuda_backend").runtime.session;
const proof_transaction = @import("stwo_cuda_backend").runtime.proof_transaction;
const resident_plan = @import("resident_plan.zig");
const terminal_decode = @import("terminal_decode.zig");

pub const Output = struct {
    proof: terminal_decode.CanonicalProof,
    verdict: runtime_session.Verdict,

    pub fn deinit(self: *Output, allocator: std.mem.Allocator) void {
        self.proof.deinit(allocator);
        self.* = undefined;
    }
};

/// Performs exactly one D2H of the terminal bundle, closes the resident
/// transaction, validates strict AOT/no-fallback evidence, and reconstructs
/// the byte-exact canonical Cairo proof.
pub fn finish(
    allocator: std.mem.Allocator,
    transaction: *proof_transaction.ResidentProofTransaction,
    plan: *const resident_plan.Plan,
    protocol: compact.CompactProtocolV1,
) !Output {
    try protocol.validate();
    const slot = plan.slot(.terminal_bundle, 0) orelse
        return error.InvalidTerminalBinding;
    if (slot.words !=
        try terminal_decode.transportWordCount(allocator, protocol))
    {
        return error.InvalidTerminalBinding;
    }
    const transport = try allocator.alloc(u32, slot.words);
    defer allocator.free(transport);
    const verdict = try transaction.assembleAndFinish(
        transport,
        slot.id,
    );
    if (!verdict.isResident())
        return error.NonResidentProofVerdict;
    const canonical = terminal_decode.CanonicalProof.decode(
        allocator,
        protocol,
        transport,
        measuredRead(verdict),
    ) catch |err| {
        // Preserve already-read transport only for an explicitly requested
        // failure diagnostic. Never publish it as a proof or bypass decoding.
        writeFailureTransport(allocator, transport) catch |dump_error| {
            std.debug.print("cairo-cuda failure transport write failed: {s}\n", .{@errorName(dump_error)});
        };
        return err;
    };
    return .{ .proof = canonical, .verdict = verdict };
}

fn measuredRead(
    verdict: runtime_session.Verdict,
) terminal_decode.MeasuredTerminalRead {
    return .{
        .measured = true,
        .d2h_proof_operations = verdict.counters.d2h_proof_operations,
        .d2h_proof_bytes = verdict.counters.d2h_proof_bytes,
        .runtime_compile_attempts = verdict.aot.aot_misses,
        .cpu_fallback_attempts = verdict.counters.cpu_fallback_attempts,
    };
}

test "terminal measurement maps only observed residency counters" {
    var verdict = std.mem.zeroInit(
        runtime_session.Verdict,
        .{ .provider = .nvidia_cuda },
    );
    verdict.counters.d2h_proof_operations = 1;
    verdict.counters.d2h_proof_bytes = 4096;
    verdict.counters.cpu_fallback_attempts = 2;
    verdict.aot.aot_misses = 3;
    const measured = measuredRead(verdict);
    try std.testing.expect(measured.measured);
    try std.testing.expectEqual(@as(u64, 1), measured.d2h_proof_operations);
    try std.testing.expectEqual(@as(u64, 4096), measured.d2h_proof_bytes);
    try std.testing.expectEqual(@as(u64, 3), measured.runtime_compile_attempts);
    try std.testing.expectEqual(@as(u64, 2), measured.cpu_fallback_attempts);
}

fn writeFailureTransport(allocator: std.mem.Allocator, transport: []const u32) !void {
    const path = std.process.getEnvVarOwned(allocator, "STWO_CAIRO_CUDA_FAILURE_TRANSPORT") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => return,
        else => return err,
    };
    defer allocator.free(path);
    if (!std.fs.path.isAbsolute(path)) return error.InvalidDiagnosticPath;
    const file = try std.fs.createFileAbsolute(path, .{ .exclusive = true });
    defer file.close();
    try file.writeAll(std.mem.sliceAsBytes(transport));
    try file.sync();
}
