//! Genuine q3 native+access proof parity, including optional profiling. Each
//! branch starts from a fresh ELF execution and independently builds its epoch.
const std = @import("std");
const core = @import("stwo_core");
const Engine = @import("stwo_prover_engine");
const Native = @import("../block_v7_native_proof_v1.zig");
const Epoch = @import("../block_v7_execution_epoch_v1.zig");
const Support = @import("../block_v7_execution_test_support.zig");
const Cache = @import("../block_v7_shared_quotient_cache_v1.zig");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Result = struct {
    proof: Native.Proof,
    bytes: []u8,
    cache: Cache.Stats,
    fn deinit(self: *@This(), a: std.mem.Allocator) void {
        self.proof.deinit(a);
        a.free(self.bytes);
    }
};
fn prove(comptime cached: bool) !Result {
    return proveMode(cached, false);
}
fn proveMode(comptime cached: bool, fused: bool) !Result {
    const code = [_]u32{ 0x00700313, 0x00900393, 0x02730433, 0x001002b7, 0x10028293, 0x0082a023, 0x0002a483, 0x0000006f };
    const elf = @import("../../runner/guest_precompile/test_elf.zig").buildReleaseProgram(code.len, &code, 512, .rv32im_zkvm_v1);
    const a = std.testing.allocator;
    const config = @import("../../recursion/blake3_execution_parent_protocol.zig").Profile.diagnostic_q8_pow0.config();
    var session = try @import("../../runner/mod.zig").BaseExecutionSession.init(a, &elf, .{ .trace_retention = .segment_owned, .clock_frame = .leaf_local });
    defer session.deinit();
    var executed = try session.startSegment(code.len - 1);
    defer executed.deinit();
    try std.testing.expectEqual(@as(u32, 63), executed.exit_cpu.regs[9]);
    var counters = try @import("../../air/lookups/tables/mod.zig").counter.Set.init(a);
    defer counters.deinit(a);
    var segment = try Support.Segment.init(a, &executed, config, @splat(7), 0, .rv32im_zkvm_v1, 0, &counters);
    defer segment.deinit();
    const entries = [_]Epoch.Entry{try segment.pin.entry(a)};
    var counts: Epoch.Counts = @splat(0);
    counts[0] = 1;
    const epoch = try Epoch.Epoch.init(@splat(9), config, counts, &entries, entries.len);
    var stats: Cache.Stats = .{};
    var recorder = Engine.stage_profile.Recorder.initWithOptions(a, "cpu", "native-cache-parity", .{ .capture_tasks = false });
    defer recorder.deinit();
    var proof = try Native.For(Cpu).proveWithOptions(a, &segment.first, segment.owner, segment.source.inputs, segment.pin, epoch, &entries, .{
        .fused_projection_rows = fused,
        // Tiny cap deliberately forces eviction/fallback across component
        // boundaries while the public production default remains 256 MiB.
        .native_main_cache_bytes = if (cached) 256 else 0,
        .cache_stats = &stats,
        .recorder = if (cached) &recorder else null,
    });
    errdefer proof.deinit(a);
    _ = try Native.For(Cpu).verify(a, &proof, segment.pin, epoch, &entries);
    try Support.roundTrip(a, &proof.stark);
    if (cached) {
        var profile = try recorder.snapshot(a);
        defer profile.deinit(a);
        try std.testing.expect(profile.stages.len != 0);
        try std.testing.expect(stats.recovered_columns != 0);
        try std.testing.expect(stats.capacity_misses != 0);
        try std.testing.expect(stats.evicted_columns != 0);
    }
    var bytes = std.Io.Writer.Allocating.init(a);
    defer bytes.deinit();
    try @import("interop_postcard").serializeProof(core.proof_suites.Blake3.Hasher, &bytes.writer, proof.stark);
    return .{ .proof = proof, .bytes = try a.dupe(u8, bytes.written()), .cache = stats };
}
test "row-fused projections preserve freshly verified native access proof bytes" {
    const a = std.testing.allocator;
    var original = try proveMode(true, false);
    defer original.deinit(a);
    var fused = try proveMode(true, true);
    defer fused.deinit(a);
    try std.testing.expectEqualSlices(u8, original.bytes, fused.bytes);
    try std.testing.expectEqualDeep(original.proof.claims, fused.proof.claims);
    try std.testing.expectEqualDeep(original.proof.memory_claims, fused.proof.memory_claims);
}
test "v7 native leased cache preserves genuine q3 access proof bytes claims and recorder independence" {
    const a = std.testing.allocator;
    var original = try prove(false);
    defer original.deinit(a);
    var leased = try prove(true);
    defer leased.deinit(a);
    // Both runners, wide witnesses, schemes and cache owners are gone here.
    try std.testing.expectEqualSlices(u8, original.bytes, leased.bytes);
    try std.testing.expectEqualDeep(original.proof.claims, leased.proof.claims);
    try std.testing.expectEqualDeep(original.proof.memory_claims, leased.proof.memory_claims);
}
