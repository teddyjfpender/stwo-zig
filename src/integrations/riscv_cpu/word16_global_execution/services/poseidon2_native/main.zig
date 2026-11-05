//! Standalone trusted-fixture producer/receiver. A receiver never calls proving.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Protocol = @import("worker_protocol.zig");
const Key = @import("fixed_key.zig").Key;
const Inventory = @import("inventory.zig").Inventory;
const Worker = @import("cpu_worker.zig");
const Wire = @import("wire.zig");
const R = @import("../roster.zig");
const P = @import("../protocol.zig");
const F = @import("../jumpdest_fixture.zig");
const M = @import("../gkr_local/manifest.zig");
const MW = @import("../gkr_local/manifest_wire.zig");
const C = @import("../gkr_local/coordinator.zig");
pub fn main() !void {
    const a = std.heap.page_allocator;
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    if (args.len != 3 or !std.mem.eql(u8, args[1], "verify")) return error.UsageVerifyFixtureDirectory;
    try receive(a, args[2]);
}
pub fn receive(a: std.mem.Allocator, path: []const u8) !void {
    var pool: engine.work_pool.WorkPool = .{};
    try pool.initInPlaceWithOptions(.{ .worker_count = 8 });
    defer pool.deinit();
    var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    var captured = try F.Captured.init(a);
    defer captured.deinit();
    var setups: [2]R.CpuSetup = undefined;
    var setup_count: usize = 0;
    defer for (setups[0..setup_count]) |*setup| setup.deinit();
    var keys: [2]Key = undefined;
    var key_count: usize = 0;
    defer for (keys[0..key_count]) |*key| key.deinit();
    const profile = Protocol.Profile.fixture_b4_q54_p0_fold4;
    for (&setups, &keys, 0..) |*setup, *key, i| {
        setup.* = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &F.WORDS }, try captured.native[i].geometry(), F.bridges[i]);
        setup_count += 1;
        key.* = try Key.init(a, setup, profile);
        key_count += 1;
    }
    const setup_ptrs = [_]*const R.CpuSetup{ &setups[0], &setups[1] };
    const natives = [_]*@import("../../../word16_execution/prepared.zig").Prepared{ &captured.native[0], &captured.native[1] };
    var requests: [2]P.Request = undefined;
    for (&requests, 0..) |*request, i| request.* = try C.requestView(&natives, &captured.advice, i);
    var inventory = try Inventory.init(a, &setup_ptrs, &requests, F.expectedFor(captured.program.identity), &keys, profile);
    defer inventory.deinit();
    var dir = try std.fs.cwd().openDir(path, .{});
    defer dir.close();
    const manifest_bytes = try dir.readFileAlloc(a, "manifest.raw-blake.binary", MW.MAX_BYTES);
    defer a.free(manifest_bytes);
    var decoded = try MW.decode(a, inventory.execution_identity, inventory.workers, manifest_bytes);
    defer decoded.deinit();
    var manifest = try M.verifyAndSealFor(.flat, a, inventory.execution_identity, inventory.workers, decoded.stages);
    defer manifest.deinit(a);
    var claims: [2]M.Claims = undefined;
    var total: usize = 0;
    for (&claims, 0..) |*claim, i| {
        var name_buf: [64]u8 = undefined;
        const name = try std.fmt.bufPrint(&name_buf, "cpu-{}.worker.binary", .{i});
        const bytes = try dir.readFileAlloc(a, name, Wire.MAX_PROOF + Wire.HEADER + 32 * Wire.MAX_CLAIMS);
        defer a.free(bytes);
        var encoded = try Wire.decode(a, profile, @intCast(i), bytes);
        defer encoded.deinit(a);
        claim.* = try Worker.verify(a, setup_ptrs[i], requests[i], inventory.workers[i], inventory.first_ids[i], &manifest, i, &keys[i], &encoded, null);
        total += encoded.bytes.len;
    }
    try manifest.checkGlobalClosure(&claims);
    std.debug.print("P2_NATIVE_FRESH_RECEIVER accepted=true physical=2 steps=5 native_proof_bytes={} suite=P2v2-PCSFS+rawBlake-localGKR-manifest profile=fixtureP0 certified=false\n", .{total});
}
