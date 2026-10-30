//! Bounded corpus preparation from an independently selected incoming snapshot.
//! This runs the original guest and captures an endpoint; it grants no proof
//! authority and does not replay or authenticate the skipped prefix.
const std = @import("std");
const Capture = @import("block_v7_real_window_capture_v1.zig");
const Initial = @import("block_v7_initial_intervals_v1.zig");
const Window = @import("block_v7_real_window_policy_v2.zig");
const Runner = @import("../runner/mod.zig");
pub const Limits = struct { initial: Initial.Limits = .{}, max_cycles: u32 = 1 << 20, chunk_cycles: u32 = 1 << 14, max_snapshot_words: usize = 8_000_000 };
pub const Stats = struct { cycles: u64 = 0, core_rows: u64 = 0, keccak_calls: u64 = 0, recovery_calls: u64 = 0, sha_calls: u64 = 0, setup_ns: u64 = 0, execution_ns: u64 = 0, snapshot_ns: u64 = 0 };
pub const Result = struct {
    outgoing: Capture.Snapshot,
    stats: Stats,
    pub fn deinit(self: *Result, a: std.mem.Allocator) void {
        self.outgoing.deinit(a);
        self.* = undefined;
    }
};
pub fn capture(a: std.mem.Allocator, elf: []const u8, elf_sha256: Capture.Digest, incoming: Capture.Snapshot, incoming_sha256: Capture.Digest, cycles: u32, limits: Limits) !Result {
    if (cycles == 0 or cycles > limits.max_cycles or limits.chunk_cycles == 0 or !std.meta.eql(Capture.sha(elf), elf_sha256) or !std.meta.eql(incoming.identity(), incoming_sha256)) return error.InvalidV7ContinuationInput;
    var timer = try std.time.Timer.start();
    var session = try Runner.EthereumShaExecutionSession.init(a, elf, .{ .trace_retention = .segment_owned, .clock_frame = .leaf_local, .stop_on_halt_flag = true, .require_current_output_accesses = false });
    defer session.deinit();
    const loaded = try Initial.loadAddresses(a, elf, limits.initial);
    defer a.free(loaded);
    try Window.validateSnapshot(incoming, &session.memory, loaded, session.elf_info.memory_layout, limits.initial);
    if (Window.valueAt(incoming.words, session.elf_info.halt_flag) != 0) return error.NonterminalWindowHalted;
    const addresses = try a.alloc(u32, incoming.words.len);
    defer a.free(addresses);
    for (addresses, incoming.words) |*address, word| address.* = word.address;
    for (try session.memory.canonicalAlignedWordAddresses()) |address| session.memory.writeU32AssumePrepared(address, 0);
    try session.memory.prepareAlignedWordWrites(addresses);
    for (incoming.words) |word| session.memory.writeU32AssumePrepared(word.address, word.value);
    session.cpu = incoming.cpu;
    var stats = Stats{ .setup_ns = timer.lap() };
    var continuation: ?@import("../runner/result.zig").ContinuationToken = null;
    while (stats.cycles < cycles) {
        const n: usize = @intCast(@min(limits.chunk_cycles, cycles - stats.cycles));
        var segment = if (continuation) |token| try session.resumeSegment(token, n) else try session.startSegment(n);
        defer segment.deinit();
        if (segment.base.cycle_count != n or segment.base.completion_reason != null) return error.RealWindowPastCompletion;
        continuation = segment.base.continuation orelse return error.RealWindowPastCompletion;
        stats.cycles += n;
        stats.core_rows += segment.base.execution_trace.rows.items.len;
        stats.keccak_calls += segment.extension.keccakf_calls.records().len;
        stats.recovery_calls += segment.extension.signer_recovery_calls.records().len;
        stats.sha_calls += segment.extension.sha_calls.records().len;
    }
    stats.execution_ns = timer.lap();
    const outgoing = try Capture.snapshot(a, session.cpu, &session.memory, .{ .max_snapshot_words = limits.max_snapshot_words });
    stats.snapshot_ns = timer.lap();
    return .{ .outgoing = outgoing, .stats = stats };
}
