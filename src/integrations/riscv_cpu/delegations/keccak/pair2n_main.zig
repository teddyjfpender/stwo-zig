//! Durable standalone q70/P26 diagnostic, never a CPU/service receiver.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const K = @import("stwo_riscv_frontend").rv64_air.crypto.keccak;
const Fixture = @import("pair2n_fixture.zig");
const Receipt = @import("../../rv64_ethereum_batch_receipt.zig");
const Metadata = struct { schema: u32 = 1, calls: u32, log: u32, claims: Fixture.Claims, proof_bytes: u64, proof_sha256: [32]u8 };
fn hash(bytes: []const u8) [32]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return digest;
}
pub fn main() !void {
    const a = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    if (args.len < 3 or args.len > 6) return error.ExpectedProduceVerifyDirectoryCallsLogWorkers;
    const calls = if (args.len > 3) try std.fmt.parseInt(u32, args[3], 10) else 5;
    const log = if (args.len > 4) try std.fmt.parseInt(u32, args[4], 10) else try K.layout.logSize(calls);
    if (log > 18) return error.Pair2nFixtureGeometryLimit;
    try K.layout.validateGeometry(calls, 1, log);
    const workers = if (args.len > 5) try std.fmt.parseInt(usize, args[5], 10) else 1;
    if (workers == 0 or workers > 32) return error.InvalidWorkers;
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = workers, .stack_size = 1 << 20 });
    defer pool.deinit();
    var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    const inputs = try a.alloc(K.trace.State, calls);
    defer a.free(inputs);
    for (inputs, 0..) |*state, i| state.* = Fixture.input(i + 2);
    const cfg = try Fixture.config(true);
    if (std.mem.eql(u8, args[1], "produce")) {
        var encoded = try Fixture.produce(a, inputs, 1, log, cfg);
        defer encoded.deinit(a);
        try Fixture.verify(a, inputs, 1, log, cfg, encoded);
        try std.fs.cwd().makeDir(args[2]);
        var dir = try std.fs.cwd().openDir(args[2], .{});
        defer dir.close();
        const meta = Metadata{ .calls = calls, .log = log, .claims = encoded.claims, .proof_bytes = encoded.bytes.len, .proof_sha256 = hash(encoded.bytes) };
        const json = try std.json.Stringify.valueAlloc(a, meta, .{ .whitespace = .indent_2 });
        defer a.free(json);
        try Receipt.writeExclusive(dir, "proof.bin", encoded.bytes);
        try Receipt.writeExclusive(dir, "statement.json", json);
        try std.posix.fsync(dir.fd);
    } else if (std.mem.eql(u8, args[1], "verify")) {
        var dir = try std.fs.cwd().openDir(args[2], .{});
        defer dir.close();
        const json = try dir.readFileAlloc(a, "statement.json", 65536);
        defer a.free(json);
        var parsed = try std.json.parseFromSlice(Metadata, a, json, .{});
        defer parsed.deinit();
        const meta = parsed.value;
        if (meta.schema != 1 or meta.calls != calls or meta.log != log or meta.proof_bytes > 64 << 20) return error.InvalidPair2nStatement;
        const bytes = try dir.readFileAlloc(a, "proof.bin", 64 << 20);
        defer a.free(bytes);
        if (bytes.len != meta.proof_bytes or !std.mem.eql(u8, &hash(bytes), &meta.proof_sha256)) return error.Pair2nProofChanged;
        try Fixture.verify(a, inputs, 1, log, cfg, .{ .bytes = bytes, .claims = meta.claims });
    } else return error.ExpectedProduceOrVerify;
}
