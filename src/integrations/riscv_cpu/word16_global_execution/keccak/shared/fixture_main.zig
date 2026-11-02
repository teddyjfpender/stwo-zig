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
    if (std.mem.eql(u8, args[1], "produce-bounded")) return produceBounded(a, args[2]);
    if (std.mem.eql(u8, args[1], "verify-bounded")) return verifyBounded(a, args[2]);
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

const BoundedMetadata = struct { schema: u32, specs: [4][32]u8, roots: [4]G.Receipt, digest: [32]u8, requests: [2]P.Request, cpu_claims: [2]E.CpuClaims, truth_claims: [2][3]Q };
fn produceBounded(a: std.mem.Allocator, path: []const u8) !void {
    var c = try F.BoundedCase.init(a, .none);
    defer c.deinit();
    const keys = c.keys();
    const truths = c.roster();
    try E.verifyBounded(a, &keys, &truths, c.expected(), &c.bundle);
    try std.fs.cwd().makeDir(path);
    var dir = try std.fs.cwd().openDir(path, .{});
    defer dir.close();
    const metadata = BoundedMetadata{ .schema = 3, .specs = c.bundle.manifest.specs[0..4].*, .roots = c.bundle.manifest.roots[0..4].*, .digest = c.bundle.manifest.digest, .requests = .{ c.bundle.cpus[0].request, c.bundle.cpus[1].request }, .cpu_claims = .{ c.bundle.cpus[0].claims, c.bundle.cpus[1].claims }, .truth_claims = .{ c.bundle.truths[0].claims, c.bundle.truths[1].claims } };
    const json = try std.json.Stringify.valueAlloc(a, metadata, .{ .whitespace = .indent_2 });
    defer a.free(json);
    try write(dir, "metadata.json", json);
    for (c.bundle.cpus, [_][]const u8{ "cpu0.bin", "cpu1.bin" }) |p, name| try write(dir, name, p.bytes);
    for (c.bundle.truths, [_][]const u8{ "truth0.bin", "truth1.bin" }) |p, name| try write(dir, name, p.bytes);
    try std.posix.fsync(dir.fd);
}
fn verifyBounded(a: std.mem.Allocator, path: []const u8) !void {
    var dir = try std.fs.cwd().openDir(path, .{});
    defer dir.close();
    const json = try dir.readFileAlloc(a, "metadata.json", 4 * 1024 * 1024);
    defer a.free(json);
    var parsed = try std.json.parseFromSlice(BoundedMetadata, a, json, .{ .allocate = .alloc_always });
    defer parsed.deinit();
    const m = parsed.value;
    if (m.schema != 3) return error.InvalidSharedTruthFixtureSchema;
    var manifest = try G.Manifest.init(a, &m.specs, &m.roots);
    defer manifest.deinit();
    if (!std.mem.eql(u8, &manifest.digest, &m.digest)) return error.GlobalExecutionManifestChanged;
    var bytes: [4][]u8 = undefined;
    var read: usize = 0;
    defer for (bytes[0..read]) |b| a.free(b);
    for ([_][]const u8{ "cpu0.bin", "cpu1.bin", "truth0.bin", "truth1.bin" }, &bytes) |name, *b| {
        b.* = try dir.readFileAlloc(a, name, 64 * 1024 * 1024);
        read += 1;
    }
    var cpus = [2]E.CpuEncoded{ .{ .bytes = bytes[0], .request = m.requests[0], .claims = m.cpu_claims[0] }, .{ .bytes = bytes[1], .request = m.requests[1], .claims = m.cpu_claims[1] } };
    var encoded_truths = [2]E.TruthEncoded{ .{ .bytes = bytes[2], .claims = m.truth_claims[0] }, .{ .bytes = bytes[3], .claims = m.truth_claims[1] } };
    const bundle = E.BoundedBundle{ .manifest = manifest, .cpus = &cpus, .truths = &encoded_truths };
    var s0 = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &Base.WORDS }, .{ .cpu_log = 5 }, 5);
    defer s0.deinit();
    var s1 = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &Base.WORDS }, .{ .cpu_log = 5 }, 5);
    defer s1.deinit();
    var t0 = try R.TruthSetup.init(a, 5);
    defer t0.deinit();
    var t1 = try R.TruthSetup.init(a, 5);
    defer t1.deinit();
    const truths = [_]P.Truth{ .{ .setup = &t0, .first_id = 1, .calls = 1 }, .{ .setup = &t1, .first_id = 2, .calls = 1 } };
    try E.verifyBounded(a, &.{ &s0, &s1 }, &truths, Base.Case.expectedFor(s0.materials.program.identity), &bundle);
}
