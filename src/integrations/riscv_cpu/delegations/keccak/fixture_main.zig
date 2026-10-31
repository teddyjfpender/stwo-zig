//! Durable primitive proof qualification; not a CPU/RAM execution proof.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const fixture = @import("../../tests/rv64_keccak_proof_test.zig");
const bridge = @import("../../tests/rv64_keccak_bridge_proof_test.zig");
pub fn main() !void {
    const a = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    if (args.len < 3 or args.len > 5) return error.ExpectedProduceOrVerifyAndDirectory;
    const count = if (args.len >= 4) try std.fmt.parseInt(usize, args[3], 10) else 3;
    if (count > 4096) return error.InvalidFixtureCallCount;
    const workers = if (args.len == 5) try std.fmt.parseInt(usize, args[4], 10) else 0;
    var pool: engine.work_pool.WorkPool = undefined;
    var initialized = false;
    defer if (initialized) pool.deinit();
    var binding: ?engine.work_pool.ScopedPoolBinding = null;
    defer if (binding) |*value| value.deinit();
    if (workers != 0) {
        try pool.initInPlaceWithOptions(.{ .worker_count = workers, .stack_size = 1024 * 1024 });
        initialized = true;
        binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
    }
    if (std.mem.eql(u8, args[1], "produce")) {
        try fixture.produceArtifact(a, args[2], count);
    } else if (std.mem.eql(u8, args[1], "verify")) {
        try fixture.verifyArtifact(a, args[2], count);
    } else if (std.mem.eql(u8, args[1], "quartet-produce")) {
        try fixture.produceQuartetArtifact(a, args[2], count);
    } else if (std.mem.eql(u8, args[1], "quartet-verify")) {
        try fixture.verifyQuartetArtifact(a, args[2], count);
    } else if (std.mem.eql(u8, args[1], "bridge-produce")) {
        try bridge.produceArtifact(a, args[2], count);
    } else if (std.mem.eql(u8, args[1], "bridge-verify")) {
        try bridge.verifyArtifact(a, args[2], count);
    } else if (std.mem.eql(u8, args[1], "released-produce")) {
        try fixture.produceReleasedArtifact(a, args[2], count);
    } else if (std.mem.eql(u8, args[1], "released-bridge-produce")) {
        try bridge.produceReleasedArtifact(a, args[2], count);
    } else if (std.mem.eql(u8, args[1], "produce-log14")) {
        try fixture.produceArtifactWithLog(a, args[2], count, 14);
    } else if (std.mem.eql(u8, args[1], "verify-log14")) {
        try fixture.verifyArtifactWithLog(a, args[2], count, 14);
    } else if (std.mem.eql(u8, args[1], "produce-log15")) {
        try fixture.produceArtifactWithLog(a, args[2], count, 15);
    } else if (std.mem.eql(u8, args[1], "verify-log15")) {
        try fixture.verifyArtifactWithLog(a, args[2], count, 15);
    } else return error.ExpectedProduceOrVerifyAndDirectory;
}
