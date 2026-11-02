//! Experimental TRUE register-only BINARY CPU execution: two CPU shards and
//! one shared BINARY/AND worker, THREE independently verified physical proofs.
//! No RAM, generic RV64, Ethereum execution, or arbitrary-alpha path is accepted.
const std = @import("std");
const air = @import("stwo_riscv_frontend").rv64_air;
const rv = @import("stwo_riscv_frontend").rv64;
const CPU = @import("../word16/cpu.zig");
const Binary = @import("binary_worker.zig");
const Public = @import("public.zig");
const D = @import("../rv64_distributed_v1/manifest.zig");
const Wire = @import("../rv64_distributed_v1/wire.zig");
const Q = @import("stwo_core").fields.qm31.QM31;
pub const Expected = Public.Expected;
pub const Boundaries = Public.Boundaries;
pub const Encoded = struct {
    shards: Boundaries,
    manifest: D.Manifest,
    cpu: [2]CPU.Encoded,
    binary: Binary.Encoded,
    pub fn deinit(self: *Encoded, a: std.mem.Allocator) void {
        for (&self.cpu) |*proof| proof.deinit(a);
        self.binary.deinit(a);
        self.manifest.deinit();
    }
};
fn binaryLog(expected: Expected) u32 {
    return @intCast(@max(5, std.math.log2_int_ceil(u64, expected.total_steps)));
}
fn programView(program: *const air.word16_cpu.rom.Setup) air.program.setup.Program {
    return .{ .base = program.addresses[0], .words = program.words, .addresses = program.addresses };
}
pub fn statementDigest(expected: Expected, shards: Boundaries) ![32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("rv64.distributed.binary-execution.reset-v1.statement");
    hash.update(&Wire.contextBytes(expected.context()));
    var raw: [8]u8 = undefined;
    std.mem.writeInt(u64, &raw, expected.total_steps, .little);
    hash.update(&raw);
    for (shards) |shard| {
        std.mem.writeInt(u64, &raw, shard.first_step, .little);
        hash.update(&raw);
        hash.update(&(try Public.shardDigest(shard)));
    }
    for (expected.worker_jobs) |job| hash.update(&job);
    return hash.finalResult();
}
fn inventory(expected: Expected, shards: Boundaries, cpu: [2]*const CPU.Materials, binary: *const Binary.Materials) ![3]D.T.Spec {
    return .{
        try cpu[0].descriptor(0, shards[0].first_step, shards[0].public, expected.worker_jobs[0]),
        try cpu[1].descriptor(1, shards[1].first_step, shards[1].public, expected.worker_jobs[1]),
        binary.descriptor(2, expected.total_steps, expected.worker_jobs[2], try statementDigest(expected, shards)),
    };
}
fn admit(expected: Expected, program: *const air.word16_cpu.rom.Setup, shards: Boundaries) !void {
    try expected.validate(program, shards);
    try D.validateContext(expected.context());
    // Conservative complete padded masses are admitted before CPU/provider
    // witness allocation; no native instruction-count claim authorizes them.
    var positive: u64 = 0;
    for (shards) |shard| positive += @as(u64, 1) << @intCast(shard.cpu_log);
    _ = try air.word16_v1.function_bus.admitPositiveMass(&.{positive});
    _ = try air.word16_v1.binary_source.massForLog(binaryLog(expected));
}
/// Immutable program/geometry owner. Request counts, endpoints and public
/// coefficients are reconstructed for EVERY descriptor use, never cached here.
pub const Prepared = struct {
    first: CPU.Materials,
    second: ?CPU.Materials,
    binary: Binary.Materials,
    pub fn init(a: std.mem.Allocator, expected: Expected, program: *const air.word16_cpu.rom.Setup, shards: Boundaries) !Prepared {
        try admit(expected, program, shards);
        var first = try CPU.Materials.initOpen(a, programView(program), shards[0].cpu_log);
        errdefer first.deinit();
        var second: ?CPU.Materials = null;
        if (shards[0].cpu_log != shards[1].cpu_log) second = try CPU.Materials.initOpen(a, programView(program), shards[1].cpu_log);
        errdefer if (second) |*value| value.deinit();
        return .{ .first = first, .second = second, .binary = try Binary.Materials.init(a, binaryLog(expected)) };
    }
    pub fn deinit(self: *Prepared) void {
        self.binary.deinit();
        if (self.second) |*value| value.deinit();
        self.first.deinit();
    }
    /// Equal geometry shares ONE immutable owner. Each Stage1 owns a separate
    /// lease/scheme and every request still reconstructs public coefficients.
    pub fn secondMaterial(self: *const Prepared) *const CPU.Materials {
        return if (self.second) |*value| value else &self.first;
    }
    pub fn descriptors(self: *const Prepared, expected: Expected, shards: Boundaries) ![3]D.T.Spec {
        if (expected.total_steps < 2 or expected.total_steps > Public.MAX_STEPS) return error.InvalidDistributedBinaryExecution;
        if (!std.mem.eql(u8, &expected.program_identity, &self.first.program.identity) or
            !std.mem.eql(u8, &expected.program_identity, &self.secondMaterial().program.identity) or
            self.first.geometry.mode != .open_function or self.secondMaterial().geometry.mode != .open_function or
            self.first.geometry.cpu_log != shards[0].cpu_log or self.secondMaterial().geometry.cpu_log != shards[1].cpu_log or
            self.binary.log_size != binaryLog(expected)) return error.DistributedExecutionPreparedMismatch;
        return inventory(expected, shards, .{ &self.first, self.secondMaterial() }, &self.binary);
    }
};
/// Each native record is observed once by its thin source. Local retirement
/// clock advice is 1-based per shard; architectural PC/register values persist.
/// Every CPU and shared-provider main is committed before Manifest derivation.
pub fn produce(a: std.mem.Allocator, expected: Expected, program: *const air.word16_cpu.rom.Setup, shards: Boundaries, records: [2][]const rv.machine.Retirement) !Encoded {
    var prepared = try Prepared.init(a, expected, program, shards);
    defer prepared.deinit();
    const specs = try prepared.descriptors(expected, shards);
    _ = try D.validateInventory(.{ .context = expected.context(), .specs = &specs });
    var first = try CPU.Stage1.init(a, &prepared.first, expected.context(), specs[0], shards[0].public, records[0]);
    defer first.deinit();
    var second = try CPU.Stage1.init(a, prepared.secondMaterial(), expected.context(), specs[1], shards[1].public, records[1]);
    defer second.deinit();
    const facts0 = try first.binaryFacts(a);
    defer a.free(facts0);
    const facts1 = try second.binaryFacts(a);
    defer a.free(facts1);
    const facts = try std.mem.concat(a, Binary.Fact, &.{ facts0, facts1 });
    defer a.free(facts);
    var binary = try Binary.Stage1.init(a, &prepared.binary, expected.context(), specs[2], facts);
    defer binary.deinit();
    var manifest = try D.Manifest.init(a, .{ .context = expected.context(), .specs = &specs }, &.{ first.receipt, second.receipt, binary.receipt });
    errdefer manifest.deinit();
    var proof0 = try first.complete(&manifest, 0);
    errdefer proof0.deinit(a);
    var proof1 = try second.complete(&manifest, 1);
    errdefer proof1.deinit(a);
    return .{ .shards = shards, .manifest = manifest, .cpu = .{ proof0, proof1 }, .binary = try binary.complete(&manifest, 2) };
}
/// Receiver inputs are independently expected program/genesis/terminal/counts
/// and job inventory. Intermediate snapshots are proof-bound advice and must
/// satisfy adjacency. No open REG/ROM/range debt can cancel across CPU shards.
pub fn verify(a: std.mem.Allocator, expected: Expected, program: *const air.word16_cpu.rom.Setup, encoded: *const Encoded) !void {
    var prepared = try Prepared.init(a, expected, program, encoded.shards);
    defer prepared.deinit();
    try verifyPrepared(a, &prepared, expected, program, encoded);
}
pub fn verifyPrepared(a: std.mem.Allocator, prepared: *const Prepared, expected: Expected, program: *const air.word16_cpu.rom.Setup, encoded: *const Encoded) !void {
    try admit(expected, program, encoded.shards);
    const specs = try prepared.descriptors(expected, encoded.shards);
    try encoded.manifest.validateExpected(.{ .context = expected.context(), .specs = &specs });
    var debt = Q.zero();
    debt = debt.add(try CPU.verifyOpen(a, &prepared.first, &encoded.manifest, 0, encoded.shards[0].public, encoded.cpu[0]));
    debt = debt.add(try CPU.verifyOpen(a, prepared.secondMaterial(), &encoded.manifest, 1, encoded.shards[1].public, encoded.cpu[1]));
    debt = debt.add(try Binary.verifyOpen(a, &prepared.binary, &encoded.manifest, 2, encoded.binary));
    if (!debt.isZero()) return error.UnclosedDistributedExecutionFunction;
}
