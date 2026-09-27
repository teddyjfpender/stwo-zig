//! Fresh-process verification of a canonical BLAKE3 execution root.
//! The expected key is a receiver-owned pin, never authority taken from a report.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const protocol = @import("recursion/blake3_execution_parent_protocol.zig");
const spans = @import("recursion/span_statement_blake3.zig");
const artifact = @import("recursion/blake3_stream_prover.zig").RootArtifact;

const Envelope = struct {
    admission: protocol.Admission,
    statement: spans.SpanStatement,
};

pub fn main() !void {
    const backing = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(backing);
    defer std.process.argsFree(backing, args);
    if (args.len != 4) return error.ExpectedProofReportAndIndependentlyTrustedKeyHex;
    if (args[3].len != 64) return error.InvalidTrustedKeyHex;
    var expected: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&expected, args[3]) catch return error.InvalidTrustedKeyHex;
    const budget = try engine.host_budget_allocator.SharedHostBudget.create(backing, 1024 * 1024 * 1024);
    defer budget.destroy();
    const a = budget.allocator();
    const report = try std.fs.cwd().readFileAlloc(a, args[2], 1024 * 1024);
    defer a.free(report);
    const envelope = try std.json.parseFromSlice(Envelope, a, report, .{ .ignore_unknown_fields = true });
    defer envelope.deinit();
    const admission = envelope.value.admission;
    // Check receiver authority before opening or allocating the proof. Report
    // timing, hashes, claimed success and expected_id alone confer no trust.
    try admission.validate();
    if (!std.mem.eql(u8, &expected, &admission.expected_id)) return error.UntrustedBlake3ParentKey;
    if (admission.key.profile != .csp_q70_pow26) return error.ExpectedCanonicalBlockSecurity;
    _ = try spans.RootStatement.init(envelope.value.statement);
    const bytes = try std.fs.cwd().readFileAlloc(a, args[1], @import("recursion/blake3_native_parent_codec.zig").HEADER_BYTES + @import("recursion/artifact_limits.zig").MAX_CANONICAL_PROOF_BYTES);
    defer a.free(bytes);
    const received = artifact{ .allocator = a, .bytes = bytes, .statement = envelope.value.statement, .expected_key_id = expected };
    var timer = try std.time.Timer.start();
    var verified = try received.verify(a, admission, expected);
    defer verified.deinit();
    const root = try verified.root();
    const verification_ns = timer.read();
    const encoded = try std.json.Stringify.valueAlloc(a, .{
        .complete_execution_proof_verified = true,
        .verification_scope = "fresh process; canonical security; independently supplied root-key pin",
        .expected_key_id = std.fmt.bytesToHex(expected, .lower),
        .verification_ns = verification_ns,
        .peak_tracked_bytes = budget.snapshot().peak_live_bytes,
        .root = root,
    }, .{ .whitespace = .indent_2 });
    defer a.free(encoded);
    try std.fs.File.stdout().writeAll(encoded);
    try std.fs.File.stdout().writeAll("\n");
}
