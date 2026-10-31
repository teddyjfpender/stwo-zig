//! Durable shared-truth diagnostic, independently expected four-instruction program.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const F = @import("fixture.zig");
const Base = @import("../fixture.zig");
const R = @import("roster.zig");
const E = @import("execution.zig");
const P = @import("protocol.zig");
const G = @import("../../protocol.zig");
const Q = G.Q;
const Metadata = struct { schema: u32, specs: [3][32]u8, roots: [3]G.Receipt, digest: [32]u8, requests: [2]P.Request, cpu_claims: [2]E.CpuClaims, truth_claims: [3]Q };
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
    if (workers == 0 or workers > 32) return error.InvalidFixtureWorkers;
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = workers, .stack_size = 1024 * 1024 });
    defer pool.deinit();
    var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    if (std.mem.eql(u8, args[1], "produce")) {
        var c = try F.Case.init(a, .none);
        defer c.deinit();
        const keys = c.keys();
        try E.verify(a, &keys, c.truth, c.expected(), &c.bundle);
        try std.fs.cwd().makeDir(args[2]);
        var dir = try std.fs.cwd().openDir(args[2], .{});
        defer dir.close();
        const metadata = Metadata{ .schema = 2, .specs = c.bundle.manifest.specs[0..3].*, .roots = c.bundle.manifest.roots[0..3].*, .digest = c.bundle.manifest.digest, .requests = .{ c.bundle.cpus[0].request, c.bundle.cpus[1].request }, .cpu_claims = .{ c.bundle.cpus[0].claims, c.bundle.cpus[1].claims }, .truth_claims = c.bundle.truth.claims };
        const json = try std.json.Stringify.valueAlloc(a, metadata, .{ .whitespace = .indent_2 });
        defer a.free(json);
        const accounting = try @import("accounting.zig").measure(a, &c);
        const accounting_json = try std.json.Stringify.valueAlloc(a, accounting, .{ .whitespace = .indent_2 });
        defer a.free(accounting_json);
        try write(dir, "accounting.json", accounting_json);
        try write(dir, "metadata.json", json);
        try write(dir, "cpu0.bin", c.bundle.cpus[0].bytes);
        try write(dir, "cpu1.bin", c.bundle.cpus[1].bytes);
        try write(dir, "truth.bin", c.bundle.truth.bytes);
        try std.posix.fsync(dir.fd);
    } else if (std.mem.eql(u8, args[1], "verify")) {
        var dir = try std.fs.cwd().openDir(args[2], .{});
        defer dir.close();
        const json = try dir.readFileAlloc(a, "metadata.json", 4 * 1024 * 1024);
        defer a.free(json);
        var parsed = try std.json.parseFromSlice(Metadata, a, json, .{ .allocate = .alloc_always });
        defer parsed.deinit();
        const m = parsed.value;
        if (m.schema != 2) return error.InvalidSharedTruthFixtureSchema;
        var manifest = try G.Manifest.init(a, &m.specs, &m.roots);
        defer manifest.deinit();
        if (!std.mem.eql(u8, &manifest.digest, &m.digest)) return error.GlobalExecutionManifestChanged;
        const p0 = try dir.readFileAlloc(a, "cpu0.bin", 64 * 1024 * 1024);
        defer a.free(p0);
        const p1 = try dir.readFileAlloc(a, "cpu1.bin", 64 * 1024 * 1024);
        defer a.free(p1);
        const pt = try dir.readFileAlloc(a, "truth.bin", 64 * 1024 * 1024);
        defer a.free(pt);
        var cpus = [2]E.CpuEncoded{ .{ .bytes = p0, .request = m.requests[0], .claims = m.cpu_claims[0] }, .{ .bytes = p1, .request = m.requests[1], .claims = m.cpu_claims[1] } };
        var bundle = E.Bundle{ .manifest = manifest, .cpus = &cpus, .truth = .{ .bytes = pt, .claims = m.truth_claims } };
        var s0 = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &Base.WORDS }, .{ .cpu_log = 5 }, 5);
        defer s0.deinit();
        var s1 = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &Base.WORDS }, .{ .cpu_log = 5 }, 5);
        defer s1.deinit();
        var truth = try R.TruthSetup.init(a, 5);
        defer truth.deinit();
        try E.verify(a, &.{ &s0, &s1 }, &truth, Base.Case.expectedFor(s0.materials.program.identity), &bundle);
    } else return error.ExpectedProduceOrVerifyDirectoryWorkers;
}
