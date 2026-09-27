//! Standalone V2 exact-count block proof receiver. The roster digest is pinned
//! by the caller; no JSON field may choose the trusted proof keys or span.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const spans = @import("recursion/span_statement_blake3.zig");
const parent = @import("recursion/blake3_execution_parent_protocol.zig");
const transport = @import("recursion/blake3_exact_forest_transport.zig");

const BundleMember = struct {
    statement: spans.SpanStatement,
    admission: parent.Admission,
    proof_path: []const u8,
};
const Bundle = struct {
    version: u32,
    job: spans.JobContext,
    members: []const BundleMember,
};

pub fn main() !void {
    const backing = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(backing);
    defer std.process.argsFree(backing, args);
    if (args.len != 3) return error.ExpectedBundleAndIndependentlyTrustedRosterDigestHex;
    if (args[2].len != 64) return error.InvalidTrustedRosterDigestHex;
    var trusted: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&trusted, args[2]) catch return error.InvalidTrustedRosterDigestHex;

    const budget = try engine.host_budget_allocator.SharedHostBudget.create(
        backing,
        4 * 1024 * 1024 * 1024,
    );
    defer budget.destroy();
    const a = budget.allocator();
    const json = try std.fs.cwd().readFileAlloc(a, args[1], 2 * 1024 * 1024);
    defer a.free(json);
    const parsed = try std.json.parseFromSlice(Bundle, a, json, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    const bundle = parsed.value;
    if (bundle.version != transport.VERSION) return error.InvalidExactForestVersion;
    if (bundle.members.len == 0 or bundle.members.len > spans.MAX_SLOT_HEIGHT + 1)
        return error.IncompleteStream;
    const members = try a.alloc(transport.FileMember, bundle.members.len);
    defer a.free(members);
    for (bundle.members, members) |source, *member| {
        member.* = .{
            .statement = source.statement,
            .admission = source.admission,
            .proof_path = source.proof_path,
        };
    }
    var timer = try std.time.Timer.start();
    const complete = try transport.verifyStreamingFiles(a, bundle.job, members, trusted);
    const elapsed_ns = timer.read();
    const output = try std.json.Stringify.valueAlloc(a, .{
        .complete_execution_proof_verified = true,
        .verification_scope = "fresh process; canonical security; independently pinned V2 exact-count roster; every dyadic proof checked",
        .proof_count = members.len,
        .segment_count = bundle.job.segment_count,
        .cycle_count = complete.cycle_count,
        .trusted_roster_digest = std.fmt.bytesToHex(trusted, .lower),
        .verification_ns = elapsed_ns,
        .peak_tracked_bytes = budget.snapshot().peak_live_bytes,
    }, .{ .whitespace = .indent_2 });
    defer a.free(output);
    try std.fs.File.stdout().writeAll(output);
    try std.fs.File.stdout().writeAll("\n");
}
