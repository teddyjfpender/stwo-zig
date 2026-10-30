//! Opt-in fresh-process verifier. The expected report digest is external
//! benchmark admission; received metadata never selects its own authority.
const std = @import("std");
const Engine = @import("stwo_prover_engine");
const Capture = @import("prover/block_v7_real_window_capture_v1.zig");
const Scope = @import("prover/block_v7_real_window_statement_v1.zig");
const Proof = @import("prover/block_v7_real_window_proof_v1.zig");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Report = struct {
    schema: []const u8,
    config: @import("stwo_core").pcs.PcsConfig,
    window: Capture.Window,
    elf_sha256: []const u8,
    original_input_sha256: []const u8,
    incoming_sha256: []const u8,
    outgoing_sha256: []const u8,
    metadata_identity: []const u8,
    proof_sha256: []const u8,
};
fn digest(value: []const u8) !Capture.Digest {
    if (value.len != 64) return error.InvalidExpectedWindowIdentity;
    var result: Capture.Digest = undefined;
    _ = try std.fmt.hexToBytes(&result, value);
    return result;
}
fn environment(name: [:0]const u8) ![]const u8 {
    return std.posix.getenv(name) orelse error.MissingWindowReloadInput;
}
test "fresh process reload verifies externally admitted retained Ethereum window" {
    const directory = std.posix.getenv("STWO_REAL_WINDOW_RELOAD_DIRECTORY") orelse return error.SkipZigTest;
    var timer = try std.time.Timer.start();
    const budget = try Engine.host_budget_allocator.SharedHostBudget.create(std.testing.allocator, 24 << 30);
    defer budget.destroy();
    const a = budget.allocator();
    var dir = try std.fs.cwd().openDir(directory, .{});
    defer dir.close();
    const raw_report = try dir.readFileAlloc(a, "report.json", 1 << 20);
    defer a.free(raw_report);
    if (!std.meta.eql(Capture.sha(raw_report), try digest(try environment("STWO_REAL_WINDOW_EXPECTED_REPORT_SHA256")))) return error.UntrustedRealWindowReport;
    var report = try std.json.parseFromSlice(Report, a, raw_report, .{ .ignore_unknown_fields = true });
    defer report.deinit();
    const r = report.value;
    if (!std.mem.eql(u8, r.schema, "stwo-explicit-real-window-original-proof-v1")) return error.InvalidRealWindowReport;
    const config = @import("recursion/blake3_execution_parent_protocol.zig").CSP_CONFIG;
    if (!std.meta.eql(config, r.config)) return error.UnqualifiedRealWindowProfile;
    const elf_pin = try digest("ef68fdca9e627a4969e64aa97119f52f2d9c9d6b6e8d5cbbeb541fb93dab0688");
    const input_pin = try digest("737368031bfec21aa2bd557a3a71d2cbf253ec730199f7ec4c3bccd628df8e82");
    if (!std.meta.eql(elf_pin, try digest(r.elf_sha256)) or !std.meta.eql(input_pin, try digest(r.original_input_sha256))) return error.UntrustedRealWindowSource;
    const elf = try std.fs.cwd().readFileAlloc(a, try environment("STWO_REAL_WINDOW_RELOAD_ELF"), 32 << 20);
    defer a.free(elf);
    const limits: Capture.Limits = .{};
    const max_snapshot = 148 + 8 * limits.max_snapshot_words;
    const raw_incoming = try std.fs.cwd().readFileAlloc(a, try environment("STWO_REAL_WINDOW_RELOAD_INCOMING"), max_snapshot);
    defer a.free(raw_incoming);
    const raw_outgoing = try std.fs.cwd().readFileAlloc(a, try environment("STWO_REAL_WINDOW_RELOAD_OUTGOING"), max_snapshot);
    defer a.free(raw_outgoing);
    var incoming = try Capture.Snapshot.decode(a, raw_incoming, try digest(r.incoming_sha256), limits);
    defer incoming.deinit(a);
    var outgoing = try Capture.Snapshot.decode(a, raw_outgoing, try digest(r.outgoing_sha256), limits);
    defer outgoing.deinit(a);
    const metadata = try dir.readFileAlloc(a, "window.admission", (Proof.Limits{}).manifest.max_bytes);
    defer a.free(metadata);
    const bytes = try dir.readFileAlloc(a, "window.proof", (Proof.Limits{}).max_proof_bytes);
    defer a.free(bytes);
    if (!std.meta.eql(Capture.sha(bytes), try digest(r.proof_sha256))) return error.UntrustedRealWindowProofBytes;
    const trusted: Scope.Trusted = .{ .elf_sha256 = elf_pin, .incoming_sha256 = try digest(r.incoming_sha256), .outgoing_sha256 = try digest(r.outgoing_sha256), .window = r.window };
    const loading_ns = timer.read();
    const result = try Proof.For(Cpu).verify(a, elf, incoming, outgoing, trusted, input_pin, config, metadata, try digest(r.metadata_identity), bytes, .{});
    const total_ns = timer.read();
    std.debug.print("V7_REAL_WINDOW_COLD_RELOAD cycles={d} loading_ns={d} fresh_verification_ns={d} whole_request_ns={d} charged_peak={d} transcript={x} proof_verified=true skipped_prefix_authenticated=false\n", .{ r.window.cycles, loading_ns, total_ns - loading_ns, total_ns, budget.snapshot().peak_live_bytes, result });
}
