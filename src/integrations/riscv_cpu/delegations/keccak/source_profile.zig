//! Bounded source-only attribution. These native counters/digests are not proof.
const std = @import("std");
const fixture = @import("../../tests/rv64_keccak_proof_test.zig");
pub fn write(a: std.mem.Allocator, output_path: []const u8, count: usize, workers: usize) !void {
    if (count > 18078) return error.InvalidFixtureCallCount;
    const K = @import("stwo_riscv_frontend").rv64_air.crypto.keccak;
    const inputs = try a.alloc(K.trace.State, count);
    defer a.free(inputs);
    for (inputs, 0..) |*state, i| state.* = fixture.inputState(i);
    var profile = K.trace.BuildProfile{};
    var timer = try std.time.Timer.start();
    var trace = try K.trace.Trace.initWithLogProfiled(a, inputs, 1, try K.layout.logSize(count), &profile);
    defer trace.deinit();
    const trace_ns = timer.lap();
    var count_profile = K.interaction.CountProfile{};
    const counts = try K.interaction.Counts.fromTraceWithOptions(&trace, .{ .pool = @import("stwo_prover_engine").work_pool.currentScopedPool(), .profile = &count_profile });
    const counts_ns = timer.lap();
    var main_hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(std.mem.sliceAsBytes(trace.main), &main_hash, .{});
    var counts_hash: [32]u8 = undefined;
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update(std.mem.asBytes(&counts.chi));
    h.update(std.mem.asBytes(&counts.xor5));
    h.final(&counts_hash);
    const hash_ns = timer.lap();
    const encoded = try std.json.Stringify.valueAlloc(a, .{ .scope = "native source construction only; seeded inputs, no proof/time extrapolation", .calls = count, .workers = workers, .log_size = trace.log_size, .main_bytes = trace.main.len * @sizeOf(@TypeOf(trace.main[0])), .metadata_bytes = trace.metadata.len * @sizeOf(K.trace.PackedRow), .trace_ns = trace_ns, .counts_ns = counts_ns, .source_ns = trace_ns + counts_ns, .hash_ns = hash_ns, .count_profile = count_profile, .profile = profile, .main_sha256 = std.fmt.bytesToHex(main_hash, .lower), .counts_sha256 = std.fmt.bytesToHex(counts_hash, .lower) }, .{ .whitespace = .indent_2 });
    defer a.free(encoded);
    var file = try std.fs.cwd().createFile(output_path, .{ .exclusive = true });
    defer file.close();
    try file.writeAll(encoded);
}
