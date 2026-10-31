//! Durable bounded fixture; full wire is reusable by the independent block driver.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const A = @import("stwo_riscv_frontend").rv64_air;
const S = A.crypto.secp256k1;
const KR = @import("../keccak/shared/roster.zig");
const SR = @import("../secp/roster.zig");
const F = @import("fixture.zig");
const E = @import("execution.zig");
const R = @import("roster.zig");
const W = @import("wire.zig");
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
        var c = try F.Case.init(a);
        defer c.deinit();
        const keys = c.keys();
        const truths = c.truths();
        try E.verify(a, &keys, &truths, c.expected(), &c.bundle);
        try std.fs.cwd().makeDir(args[2]);
        var dir = try std.fs.cwd().openDir(args[2], .{});
        defer dir.close();
        try W.write(a, dir, &keys, &truths, &c.bundle);
    } else if (std.mem.eql(u8, args[1], "verify")) {
        var dir = try std.fs.cwd().openDir(args[2], .{});
        defer dir.close();
        var loaded = try W.read(a, dir, .{ .max_cpus = 2, .max_truths = 3, .max_total_steps = 7 });
        defer loaded.deinit(a);
        if (loaded.cpu_declarations.len != 2 or loaded.truth_declarations.len != 3) return error.InvalidFixtureRoster;
        // Receiver independently chooses ALL declarations. Transport values
        // cannot choose a different software, geometry or expected truth roster.
        const expected_cpu = [_]W.CpuDeclaration{ .{ .geometry = .{ .cpu_log = 5 }, .bridges = .{ .keccak = 5 } }, .{ .geometry = .{ .cpu_log = 5 }, .bridges = .{ .add = 5, .double = 5 } } };
        for (expected_cpu, loaded.cpu_declarations) |x, y| if (!std.meta.eql(x, y)) return error.InvalidFixtureGeometry;
        const expected_truth = [_]W.TruthDeclaration{ .{ .family = .keccak, .first_id = 1, .calls = 1, .logs = .{ 5, 0 } }, .{ .family = .add, .first_id = 1, .calls = 1, .logs = .{ try S.layout.logSize(.product, &S.program.add, 1), try S.layout.logSize(.linear, &S.program.add, 1) } }, .{ .family = .double, .first_id = 1, .calls = 1, .logs = .{ try S.layout.logSize(.product, &S.program.double, 1), try S.layout.logSize(.linear, &S.program.double, 1) } } };
        for (expected_truth, loaded.truth_declarations) |x, y| if (!std.meta.eql(x, y)) return error.InvalidFixtureGeometry;
        var s0 = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &F.WORDS }, expected_cpu[0].geometry, expected_cpu[0].bridges);
        defer s0.deinit();
        var s1 = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &F.WORDS }, expected_cpu[1].geometry, expected_cpu[1].bridges);
        defer s1.deinit();
        var kt = try KR.TruthSetup.init(a, 5);
        defer kt.deinit();
        var at = try SR.TruthSetup.init(a, .add, expected_truth[1].logs);
        defer at.deinit();
        var dt = try SR.TruthSetup.init(a, .double, expected_truth[2].logs);
        defer dt.deinit();
        const truths = [_]R.Truth{ .{ .keccak = .{ .setup = &kt, .first_id = 1, .calls = 1 } }, .{ .secp = .{ .setup = &at, .first_id = 1, .calls = 1 } }, .{ .secp = .{ .setup = &dt, .first_id = 1, .calls = 1 } } };
        try E.verify(a, &.{ &s0, &s1 }, &truths, F.expectedFor(s0.materials.program.identity), &loaded.bundle);
    } else return error.ExpectedProduceOrVerifyDirectoryWorkers;
}
