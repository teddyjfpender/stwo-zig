//! Durable projective arithmetic control, not a CPU/RAM service proof.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const fixture = @import("fixture.zig");
const bridge = @import("bridge_fixture.zig");
const Kind = @import("stwo_riscv_frontend").rv64_air.crypto.secp256k1.program.Kind;
pub fn main() !void {
    const a = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    if (args.len < 5 or args.len > 6) return error.ExpectedModeDirectoryKindCountWorkers;
    const kind = std.meta.stringToEnum(Kind, args[3]) orelse return error.InvalidProjectiveKind;
    const count = try std.fmt.parseInt(usize, args[4], 10);
    if (count > 4096) return error.InvalidFixtureCallCount;
    const workers = if (args.len == 6) try std.fmt.parseInt(usize, args[5], 10) else 0;
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
    if (std.mem.eql(u8, args[1], "produce")) try fixture.produceArtifact(a, args[2], kind, count) else if (std.mem.eql(u8, args[1], "verify")) try fixture.verifyArtifact(a, args[2], kind, count) else if (std.mem.eql(u8, args[1], "bridge-produce")) try bridge.produceArtifact(a, args[2], kind, count) else if (std.mem.eql(u8, args[1], "bridge-verify")) try bridge.verifyArtifact(a, args[2], kind, count) else if (std.mem.eql(u8, args[1], "word-bridge-produce")) try bridge.produceWordsArtifact(a, args[2], kind, count) else if (std.mem.eql(u8, args[1], "word-bridge-verify")) try bridge.verifyWordsArtifact(a, args[2], kind, count) else if (std.mem.eql(u8, args[1], "released-produce")) try fixture.produceReleasedArtifact(a, args[2], kind, count) else if (std.mem.eql(u8, args[1], "released-word-bridge-produce")) try bridge.produceReleasedArtifact(a, args[2], kind, count, .little_endian_words_v2) else if (std.mem.eql(u8, args[1], "released-bridge-produce")) try bridge.produceReleasedArtifact(a, args[2], kind, count, .big_endian_bytes_v1) else return error.ExpectedProduceOrVerify;
}
