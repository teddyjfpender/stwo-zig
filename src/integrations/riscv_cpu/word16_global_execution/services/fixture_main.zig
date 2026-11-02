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
    if (args.len >= 2 and (std.mem.eql(u8, args[1], "produce-v3") or std.mem.eql(u8, args[1], "verify-v3"))) return mainV3(a, args);
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

/// ethereum_services_v3 fixtures: `produce-v3|verify-v3 sha256|all DIR [workers]`.
/// `sha256` is the SHA-only two-shard fixture (services/sha256_fixture.zig);
/// `all` uses SHA-256, arith256_mod and bulk memory together (v3_fixture.zig).
/// `all-fused` is `all` with the fused-tail CPU interaction (the layout the
/// ethereum_services_v3 route defaults to); `all` keeps the historical bytes.
/// verify-v3 rebuilds every key from receiver-chosen declarations.
fn mainV3(a: std.mem.Allocator, args: []const []const u8) !void {
    const usage = error.ExpectedProduceV3OrVerifyV3VariantDirectoryWorkers;
    if (args.len < 4 or args.len > 5) return usage;
    const workers = if (args.len == 5) try std.fmt.parseInt(usize, args[4], 10) else 1;
    if (workers == 0 or workers > 32) return error.InvalidWorkers;
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = workers, .stack_size = 1024 * 1024 });
    defer pool.deinit();
    var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    const produce = std.mem.eql(u8, args[1], "produce-v3");
    const fused = std.mem.eql(u8, args[2], "all-fused");
    const all = fused or std.mem.eql(u8, args[2], "all");
    if (!all and !std.mem.eql(u8, args[2], "sha256")) return usage;
    const SF = @import("sha256_fixture.zig");
    const VF = @import("v3_fixture.zig");
    const HR = @import("../sha256/roster.zig");
    const AR = @import("../arith256/roster.zig");
    if (produce) {
        try std.fs.cwd().makeDir(args[3]);
        var dir = try std.fs.cwd().openDir(args[3], .{});
        defer dir.close();
        if (all) {
            var c = try VF.Case.initWith(a, .none, .{ .cpu_fused_tail = fused });
            defer c.deinit();
            const keys = c.keys();
            const truths = c.truths();
            try E.verify(a, &keys, &truths, c.expected(), &c.bundle);
            try W.write(a, dir, &keys, &truths, &c.bundle);
            // The receiver needs the loaded word for the public final registers.
            var file = try dir.createFile("loaded-x9.txt", .{ .exclusive = true });
            defer file.close();
            var text: [32]u8 = undefined;
            try file.writeAll(try std.fmt.bufPrint(&text, "{x:0>16}\n", .{c.loaded}));
        } else {
            var c = try SF.Case.init(a, .none, false);
            defer c.deinit();
            const keys = c.keys();
            var buffer: [2]R.Truth = undefined;
            const truths = c.truths(&buffer);
            try E.verify(a, &keys, truths, c.expected(), &c.bundle);
            try W.write(a, dir, &keys, truths, &c.bundle);
        }
        return;
    }
    var dir = try std.fs.cwd().openDir(args[3], .{});
    defer dir.close();
    if (all) {
        var loaded = try W.read(a, dir, .{ .max_cpus = 2, .max_truths = 2, .max_total_steps = VF.STEPS });
        defer loaded.deinit(a);
        if (loaded.cpu_declarations.len != 2 or loaded.truth_declarations.len != 2) return error.InvalidFixtureRoster;
        for (VF.BRIDGES, loaded.cpu_declarations) |x, y| if (!std.meta.eql(x, y.bridges)) return error.InvalidFixtureGeometry;
        // The receiver chooses the CPU layout from the variant, never the wire.
        for (loaded.cpu_declarations) |d| if (d.geometry.cpu_fused_tail != fused) return error.InvalidFixtureGeometry;
        const expected_truth = [_]W.TruthDeclaration{ .{ .family = .sha256, .first_id = 1, .calls = 2, .logs = .{ VF.SHA_LOG, 0 } }, .{ .family = .arith256_mod, .first_id = 1, .calls = 2, .logs = .{ VF.ARITH_LOG, 0 } } };
        for (expected_truth, loaded.truth_declarations) |x, y| if (!std.meta.eql(x, y)) return error.InvalidFixtureGeometry;
        // The receiver re-executes the fixture natively for its public end state
        // (the x9 word); it never trusts transported register values.
        var captured = try VF.Captured.init(a);
        const x9 = captured.loaded;
        captured.deinit();
        var s0 = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &VF.WORDS }, loaded.cpu_declarations[0].geometry, VF.BRIDGES[0]);
        defer s0.deinit();
        var s1 = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &VF.WORDS }, loaded.cpu_declarations[1].geometry, VF.BRIDGES[1]);
        defer s1.deinit();
        var ht = try HR.TruthSetup.init(a, VF.SHA_LOG);
        defer ht.deinit();
        var at = try AR.TruthSetup.init(a, VF.ARITH_LOG);
        defer at.deinit();
        const truths = VF.truthsFor(&ht, &at);
        try E.verify(a, &.{ &s0, &s1 }, &truths, VF.expectedFor(s0.materials.program.identity, x9), &loaded.bundle);
    } else {
        var loaded = try W.read(a, dir, .{ .max_cpus = 2, .max_truths = 1, .max_total_steps = 5 });
        defer loaded.deinit(a);
        if (loaded.cpu_declarations.len != 2 or loaded.truth_declarations.len != 1) return error.InvalidFixtureRoster;
        for (loaded.cpu_declarations) |d| if (!std.meta.eql(d.bridges, @import("types.zig").Logs{ .sha256 = 5 })) return error.InvalidFixtureGeometry;
        if (!std.meta.eql(loaded.truth_declarations[0], W.TruthDeclaration{ .family = .sha256, .first_id = 1, .calls = 3, .logs = .{ 5, 0 } })) return error.InvalidFixtureGeometry;
        var s0 = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &SF.WORDS }, loaded.cpu_declarations[0].geometry, .{ .sha256 = 5 });
        defer s0.deinit();
        var s1 = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &SF.WORDS }, loaded.cpu_declarations[1].geometry, .{ .sha256 = 5 });
        defer s1.deinit();
        var ht = try HR.TruthSetup.init(a, 5);
        defer ht.deinit();
        const truths = [_]R.Truth{.{ .sha256 = .{ .setup = &ht, .first_id = 1, .calls = 3 } }};
        try E.verify(a, &.{ &s0, &s1 }, &truths, SF.expectedFor(s0.materials.program.identity), &loaded.bundle);
    }
}
