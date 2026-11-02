//! Durable q70/P26 diagnostic: actual two-shard CPU/K/RAM prefix. This fixed
//! public test program certifies no Ethereum block or requested halt/output.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const F = @import("fixture.zig");
const E = @import("execution.zig");
const R = @import("roster.zig");
const P = @import("../protocol.zig");
const G = @import("../../word16_execution/geometry.zig");
const Metadata = struct { schema: u32, specs: [2][32]u8, roots: [2]P.Receipt, digest: [32]u8, requests: [2]E.Request, claims: [2]E.Claims };
fn write(dir: std.fs.Dir, name: []const u8, data: []const u8) !void {
    var file = try dir.createFile(name, .{ .exclusive = true });
    defer file.close();
    try file.writeAll(data);
    try file.sync();
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
        var c = try F.Case.init(a);
        defer c.deinit();
        const keys = c.keys();
        try E.verify(a, &keys, c.expected(), &c.bundle);
        try std.fs.cwd().makePath(args[2]);
        var dir = try std.fs.cwd().openDir(args[2], .{});
        defer dir.close();
        const metadata = Metadata{ .schema = 1, .specs = c.bundle.manifest.specs[0..2].*, .roots = c.bundle.manifest.roots[0..2].*, .digest = c.bundle.manifest.digest, .requests = .{ c.bundle.proofs[0].request, c.bundle.proofs[1].request }, .claims = .{ c.bundle.proofs[0].claims, c.bundle.proofs[1].claims } };
        const json = try std.json.Stringify.valueAlloc(a, metadata, .{ .whitespace = .indent_2 });
        defer a.free(json);
        try write(dir, "metadata.json", json);
        try write(dir, "proof0.bin", c.bundle.proofs[0].bytes);
        try write(dir, "proof1.bin", c.bundle.proofs[1].bytes);
    } else if (std.mem.eql(u8, args[1], "verify")) {
        var dir = try std.fs.cwd().openDir(args[2], .{});
        defer dir.close();
        const json = try dir.readFileAlloc(a, "metadata.json", 4 * 1024 * 1024);
        defer a.free(json);
        var parsed = try std.json.parseFromSlice(Metadata, a, json, .{ .allocate = .alloc_always });
        defer parsed.deinit();
        const m = parsed.value;
        if (m.schema != 1) return error.InvalidServiceFixtureSchema;
        var manifest = try P.Manifest.init(a, &m.specs, &m.roots);
        defer manifest.deinit();
        if (!std.mem.eql(u8, &manifest.digest, &m.digest)) return error.GlobalExecutionManifestChanged;
        const p0 = try dir.readFileAlloc(a, "proof0.bin", 64 * 1024 * 1024);
        defer a.free(p0);
        const p1 = try dir.readFileAlloc(a, "proof1.bin", 64 * 1024 * 1024);
        defer a.free(p1);
        var proofs = [_]E.Encoded{ .{ .bytes = p0, .claims = m.claims[0], .request = m.requests[0] }, .{ .bytes = p1, .claims = m.claims[1], .request = m.requests[1] } };
        var bundle = E.Bundle{ .manifest = manifest, .proofs = &proofs };
        const geometry = G.Geometry{ .cpu_log = 5 };
        var s0 = try R.Setup.initProgram(a, .{ .base = 4096, .words = &F.WORDS }, geometry, .{ .klog = 5, .blog = 5 });
        defer s0.deinit();
        var s1 = try R.Setup.initProgram(a, .{ .base = 4096, .words = &F.WORDS }, geometry, .{ .klog = 5, .blog = 5 });
        defer s1.deinit();
        try E.verify(a, &.{ &s0, &s1 }, F.Case.expectedFor(s0.materials.program.identity), &bundle);
    } else return error.ExpectedProduceOrVerifyDirectoryWorkers;
}
