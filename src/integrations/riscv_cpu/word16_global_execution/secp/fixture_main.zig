//! Durable actual CPU/global-RAM/RCB prefix fixture; receiver rebuilds expected
//! software, image, registers and all independently sized immutable keys.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const A = @import("stwo_riscv_frontend").rv64_air;
const S = A.crypto.secp256k1;
const F = @import("fixture.zig");
const E = @import("execution.zig");
const R = @import("roster.zig");
const P = @import("protocol.zig");
const G = @import("../protocol.zig");
const Metadata = struct { schema: u32, specs: [4][32]u8, roots: [4]G.Receipt, digest: [32]u8, requests: [2]P.Request, cpu_claims: [2]E.CpuClaims, truth_claims: [2][3]G.Q };
fn write(dir: std.fs.Dir, name: []const u8, bytes: []const u8) !void {
    var f = try dir.createFile(name, .{ .exclusive = true });
    defer f.close();
    try f.writeAll(bytes);
    try f.sync();
}
pub fn main() !void {
    const a = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    if (args.len < 3 or args.len > 4) return error.ExpectedProduceOrVerifyDirectoryWorkers;
    const workers = if (args.len == 4) try std.fmt.parseInt(usize, args[3], 10) else 1;
    if (workers == 0 or workers > 32) return error.InvalidWorkers;
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = workers, .stack_size = 1024 * 1024 });
    defer pool.deinit();
    var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    if (std.mem.eql(u8, args[1], "produce")) {
        var c = try F.Case.init(a, .none);
        defer c.deinit();
        const keys = c.keys();
        try E.verify(a, &keys, c.truthKeys(), c.expected(), &c.bundle);
        try std.fs.cwd().makeDir(args[2]);
        var dir = try std.fs.cwd().openDir(args[2], .{});
        defer dir.close();
        const meta = Metadata{ .schema = 1, .specs = c.bundle.manifest.specs[0..4].*, .roots = c.bundle.manifest.roots[0..4].*, .digest = c.bundle.manifest.digest, .requests = .{ c.bundle.cpus[0].request, c.bundle.cpus[1].request }, .cpu_claims = .{ c.bundle.cpus[0].claims, c.bundle.cpus[1].claims }, .truth_claims = .{ c.bundle.truths[0].claims, c.bundle.truths[1].claims } };
        const json = try std.json.Stringify.valueAlloc(a, meta, .{ .whitespace = .indent_2 });
        defer a.free(json);
        try write(dir, "metadata.json", json);
        for (c.bundle.cpus, [_][]const u8{ "cpu0.bin", "cpu1.bin" }) |cproof, name| try write(dir, name, cproof.bytes);
        for (c.bundle.truths, [_][]const u8{ "add.bin", "double.bin" }) |tproof, name| try write(dir, name, tproof.bytes);
        try std.posix.fsync(dir.fd);
    } else if (std.mem.eql(u8, args[1], "verify")) {
        var dir = try std.fs.cwd().openDir(args[2], .{});
        defer dir.close();
        const json = try dir.readFileAlloc(a, "metadata.json", 4 * 1024 * 1024);
        defer a.free(json);
        var parsed = try std.json.parseFromSlice(Metadata, a, json, .{ .allocate = .alloc_always });
        defer parsed.deinit();
        const m = parsed.value;
        if (m.schema != 1) return error.InvalidSecpFixtureSchema;
        var manifest = try G.Manifest.init(a, &m.specs, &m.roots);
        defer manifest.deinit();
        if (!std.mem.eql(u8, &manifest.digest, &m.digest)) return error.GlobalExecutionManifestChanged;
        var bytes: [4][]u8 = undefined;
        var n: usize = 0;
        defer for (bytes[0..n]) |b| a.free(b);
        for ([_][]const u8{ "cpu0.bin", "cpu1.bin", "add.bin", "double.bin" }, &bytes) |name, *b| {
            b.* = try dir.readFileAlloc(a, name, 64 * 1024 * 1024);
            n += 1;
        }
        var cpus = [2]E.CpuEncoded{ .{ .bytes = bytes[0], .request = m.requests[0], .claims = m.cpu_claims[0] }, .{ .bytes = bytes[1], .request = m.requests[1], .claims = m.cpu_claims[1] } };
        const bundle = E.Bundle{ .manifest = manifest, .cpus = &cpus, .truths = .{ .{ .bytes = bytes[2], .claims = m.truth_claims[0] }, .{ .bytes = bytes[3], .claims = m.truth_claims[1] } } };
        var s0 = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &F.WORDS }, .{ .cpu_log = 5 }, .{ 5, 5 });
        defer s0.deinit();
        var s1 = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &F.WORDS }, .{ .cpu_log = 5 }, .{ 5, 5 });
        defer s1.deinit();
        var ta = try R.TruthSetup.init(a, .add, .{ try S.layout.logSize(.product, &S.program.add, 1), try S.layout.logSize(.linear, &S.program.add, 1) });
        defer ta.deinit();
        var td = try R.TruthSetup.init(a, .double, .{ try S.layout.logSize(.product, &S.program.double, 1), try S.layout.logSize(.linear, &S.program.double, 1) });
        defer td.deinit();
        try E.verify(a, &.{ &s0, &s1 }, .{ &ta, &td }, F.expectedFor(s0.materials.program.identity), &bundle);
    } else return error.ExpectedProduceOrVerifyDirectoryWorkers;
}
