//! Atomic diagnostic proof and measured CUDA receipts; no verifier claim.
const std = @import("std");
const stwo = @import("stwo_cairo_cuda");
const compact = stwo.frontend.compact_verifier_interchange;

/// Host wall intervals, without additional GPU synchronization. Device event
/// intervals in the verdict separately measure work enqueued by these phases.
pub const IngressTimings = struct {
    paths_ns: u64,
    runtime_ns: u64,
    source_ns: u64,
    controllers_ns: u64,
    twiddles_ns: u64,
    allocation_ns: u64,
    binding_ns: u64,
    static_ns: u64,
    writers_ns: u64,
    statement_and_session_ns: u64,
};

pub const Receipt = struct {
    index: u32,
    protocol: compact.CompactProtocolV1,
    input_sha256: [32]u8,
    executable_sha256: [32]u8,
    planned_arena_bytes: u64,
    prepared_arena_reused: bool = false,
    preprocessed_reused: bool = false,
    ingress_ns: u64,
    /// CPU work can overlap the preceding PIE's CUDA proof. These intervals
    /// are reported separately from critical-path ingress wall time.
    source_lookahead_prepare_ns: u64 = 0,
    source_lookahead_wait_ns: u64 = 0,
    input_capture_timings: stwo.integration.canonical_source.InputTimings,
    ingress_timings: IngressTimings,
    proof_execute_and_decode_ns: u64,
    adapted_input_until_publication_ns: u64,
    /// Null when the verified proof was handed directly to a recursive sink.
    proof_sha256: ?[32]u8,
    proof_bytes: ?u64,
    verdict: stwo.backend.runtime.session.Verdict,
};

pub fn writeProof(path: []const u8, diagnostic: anytype, output: anytype, executable_digest: [32]u8) !compact.EnvelopeSummary {
    const input_hex = std.fmt.bytesToHex(diagnostic.digests.adapted_input, .lower);
    const manifest_hex = std.fmt.bytesToHex(diagnostic.digests.direct_manifest, .lower);
    const executable_hex = std.fmt.bytesToHex(executable_digest, .lower);
    var buffer: [65536]u8 = undefined;
    var atomic = try std.fs.cwd().atomicFile(path, .{ .write_buffer = &buffer });
    defer atomic.deinit();
    const result = try compact.writeEnvelopeV1(&atomic.file_writer.interface, diagnostic.protocol, diagnostic.statement_bytes, output.proof.bytes(), .{
        .adapted_input_sha256 = &input_hex,
        .artifact_manifest_sha256 = &manifest_hex,
        .runner_executable_sha256 = &executable_hex,
        .backend_executable_sha256 = &executable_hex,
    });
    try atomic.file_writer.interface.flush();
    try atomic.finish();
    return result;
}

/// Official Rust-verifier JSON, after independent Zig verification. The Rust
/// verifier must still accept this file before a benchmark can be qualified.
pub fn writeCanonicalProof(path: []const u8, prepared: anytype, decoded: anytype, interaction_pow: u64) !u64 {
    var buffer: [65536]u8 = undefined;
    var atomic = try std.fs.cwd().atomicFile(path, .{ .write_buffer = &buffer });
    defer atomic.deinit();
    const Base = stwo.frontend.proof.json.Document(@TypeOf(decoded.proof));
    const document = Base{
        .input = &prepared.input,
        .composition = &prepared.composition,
        .claimed_sums = decoded.claimed_sums,
        .interaction_pow = interaction_pow,
        .channel_salt = prepared.protocol.channel_salt,
        .preprocessed_variant = prepared.variant,
        .stark_proof = &decoded.proof,
    };
    if (prepared.protocol.fri_lifting_log_size) |lifting| {
        if (prepared.protocol.channel_profile != .blake2s_m31) return error.InvalidCairoLeafLifting;
        const Pinned = stwo.frontend.proof.json.PinnedLeafDocument(@TypeOf(decoded.proof));
        try std.json.Stringify.value(Pinned{
            .document = document,
            .trace_lifting_log_size = lifting,
            .preprocessed_lifting_log_size = lifting,
        }, .{}, &atomic.file_writer.interface);
    } else {
        if (prepared.protocol.channel_profile != .blake2s) return error.InvalidCairoLeafLifting;
        try std.json.Stringify.value(document, .{}, &atomic.file_writer.interface);
    }
    try atomic.file_writer.interface.writeByte('\n');
    try atomic.file_writer.interface.flush();
    const size = (try atomic.file_writer.file.stat()).size;
    try atomic.finish();
    return size;
}

pub fn writeReport(path: []const u8, receipts: []const Receipt) !void {
    try writeReportWithTeardown(path, receipts, null);
}

pub fn writeFinalReport(path: []const u8, receipts: []const Receipt, runtime_teardown_ns: u64) !void {
    try writeReportWithTeardown(path, receipts, runtime_teardown_ns);
}

fn writeReportWithTeardown(path: []const u8, receipts: []const Receipt, runtime_teardown_ns: ?u64) !void {
    var buffer: [65536]u8 = undefined;
    var atomic = try std.fs.cwd().atomicFile(path, .{ .write_buffer = &buffer });
    defer atomic.deinit();
    const handed_off = receipts.len != 0 and receipts[0].proof_sha256 == null;
    try std.json.Stringify.value(.{
        .schema = if (handed_off) "stwo-zig-cairo-cuda-verified-sink-receipt-v1" else "stwo-zig-cairo-cuda-canonical-receipt-v2",
        .production_eligible = false,
        .verification_status = if (handed_off) "zig_verified_delivered_to_recursive_sink" else "zig_verified_rust_verification_pending",
        .timing_scope = if (handed_off)
            "adapted input to verified Cairo handoff; excludes PIE execution/adaptation and the recursive sink's work; in-command source lookahead overlaps previous proofs, so per-trial windows are not additive"
        else
            "adapted input to official Rust proof JSON; excludes PIE execution/adaptation; in-command source lookahead overlaps previous proofs, so per-trial windows are not additive; proving stage reported separately from ingress and verification",
        .runtime_lifecycle = "one runtime and bounded arena cache per process; startup charged to first trial; subsequent trials prepare fresh proof inputs; teardown reported separately",
        .runtime_teardown_ns = runtime_teardown_ns,
        .completed_trials = receipts,
    }, .{ .whitespace = .indent_2 }, &atomic.file_writer.interface);
    try atomic.file_writer.interface.writeByte('\n');
    try atomic.file_writer.interface.flush();
    try atomic.finish();
}

pub fn sha256File(path: []const u8) ![32]u8 {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    var buffer: [1024 * 1024]u8 = undefined;
    while (true) {
        const n = try file.read(&buffer);
        if (n == 0) break;
        hash.update(buffer[0..n]);
    }
    return hash.finalResult();
}

/// Authenticated public inputs for an offline failure oracle. These sidecars
/// accompany an unverified transport, never a published proof or receipt.
pub fn writeFailureInputs(allocator: std.mem.Allocator, diagnostic: anytype) !void {
    const path = std.process.getEnvVarOwned(allocator, "STWO_CAIRO_CUDA_FAILURE_TRANSPORT") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => return,
        else => return err,
    };
    defer allocator.free(path);
    if (!std.fs.path.isAbsolute(path)) return error.InvalidDiagnosticPath;
    const protocol = try diagnostic.protocol.encode();
    inline for (.{ .{ ".protocol", &protocol }, .{ ".statement", diagnostic.statement_bytes } }) |sidecar| {
        const name = try std.fmt.allocPrint(allocator, "{s}{s}", .{ path, sidecar[0] });
        defer allocator.free(name);
        const file = try std.fs.createFileAbsolute(name, .{ .exclusive = true });
        defer file.close();
        try file.writeAll(sidecar[1]);
        try file.sync();
    }
}
