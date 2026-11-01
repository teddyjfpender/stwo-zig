const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const F = @import("../fixture.zig");
const R = @import("../roster.zig");
const P = @import("../protocol.zig");
const Worker = @import("cpu_worker.zig");
const Manifest = @import("manifest.zig");
fn exercise(comptime shard: usize, comptime fail_seal: bool) !void {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    const a = failing.allocator();
    var captured = try F.Captured.init(a);
    defer captured.deinit();
    var setup = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &F.WORDS }, try captured.native[shard].geometry(), if (shard == 0) .{ .keccak = 5 } else .{ .add = 5, .double = 5 });
    defer setup.deinit();
    const n = &captured.native[shard];
    const request = P.Request{ .calls = if (shard == 0) .{ 1, 0, 0 } else .{ 0, 1, 1 }, .base = .{ .cpu = n.cpu.?.public, .epoch = @intCast(shard + 1), .division_requests = @intCast(n.division.len), .multiplication_requests = @intCast(n.multiplication.len), .memory = .{ .initial = if (shard == 0) captured.advice.initial else &.{}, .terminal = if (shard == 1) captured.advice.terminal else &.{}, .epoch = @intCast(shard + 1), .ls_count = @intCast(captured.advice.events[shard].len) } } };
    const g = setup.materials.geometry;
    const Memory = @import("../../../word16_execution/memory/prepared.zig").Prepared;
    const memory = try Memory.initOwnedForGlobalRamLadderIndependent(a, captured.advice.events[shard], try a.dupe(A.memory.closed_ram.types.Cell, request.base.memory.initial), try a.dupe(A.memory.closed_ram.types.Cell, request.base.memory.terminal), @intCast(shard + 1), g.ls_log, g.ls_tail_log, g.initialLog(), g.terminalLog());
    var source = R.Sources{ .core = try @import("../../../word16_execution/sources.zig").Source.fromPreparedWithOwnedMemory(a, &setup.materials, n, memory) };
    var owns = true;
    defer if (owns) source.deinit();
    if (shard == 0) source.keccak = try A.crypto.keccak.word16_bridge.source.Source.init(a, captured.advice.keccak[0], 1, 5) else {
        source.add = try A.crypto.secp256k1.word16_bridge.source.Source.init(a, .add, captured.advice.secp[1][0], 1, 5);
        source.double = try A.crypto.secp256k1.word16_bridge.source.Source.init(a, .double, captured.advice.secp[1][1], 1, 5);
    }
    try source.mergeRanges();
    const O = core.fields.om31.OM31;
    const config = core.pcs.ForField(O).PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.ForField(O).FriConfig.init(0, 1, 12) };
    const instances = try @import("roster.zig").fromSetup(a, &setup);
    defer a.free(instances);
    const expected = Manifest.ExpectedWorker{ .kind = .cpu, .ordinal = 0, .statement = Worker.cpuStatement(&setup, request, .{ 1, 1, 1 }, config), .fixed = setup.key.root, .local_instances = instances, .mass = try Worker.cpuMass(request), .global_relations = .{ .ram = true, .kio = shard == 0, .wire = shard == 1 } };
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const spill_path = try tmp.dir.realpathAlloc(a, ".");
    defer a.free(spill_path);
    var store = try @import("../../retained_main_store.zig").Store.initParked(spill_path, 128 << 20);
    defer store.deinit();
    var worker = try Worker.CpuWorker.init(a, &setup, request, source, expected, config, .{ 1, 1, 1 }, 2 << 30);
    owns = false;
    defer worker.deinit(a);
    if (fail_seal) {
        failing.fail_index = failing.alloc_index;
        try std.testing.expectError(error.OutOfMemory, worker.seal(a));
        failing.fail_index = std.math.maxInt(usize);
        return;
    }
    const stage = try worker.seal(a);
    try std.testing.expectError(error.WideCpuPhase, worker.seal(a));
    try worker.retireLocalMetadata();
    try worker.retireLocalMetadata();
    try std.testing.expect(try worker.spillMain(&store) > 0);
    try std.testing.expectEqual(@as(usize, 0), store.stats().live_mapped_bytes);
    try std.testing.expect(try worker.restoreMain(&store) > 0);
    try std.testing.expectEqualSlices(u8, &stage.main, &worker.scheme.trees.items[1].root());
    var pending = try Manifest.verifyAndSeal(a, @splat(0x91), &.{expected}, &.{stage});
    defer pending.deinit(a);
    failing.fail_index = failing.alloc_index;
    try std.testing.expectError(error.OutOfMemory, worker.complete(a, &pending, 0, 1 << 26));
    failing.fail_index = std.math.maxInt(usize);
    // An early stage-two allocation failure retains the phase and every owner.
    var encoded = try worker.complete(a, &pending, 0, 1 << 26);
    defer encoded.deinit(a);
    try std.testing.expectError(error.WideCpuPhase, worker.complete(a, &pending, 0, 1 << 26));
    const accepted = try Worker.verifyCpu(a, &setup, request, expected, .{ 1, 1, 1 }, &pending, 0, config, &encoded);
    try std.testing.expect(!accepted.ram.isZero());
    var initial_claim: usize = undefined;
    for (worker.plan.slots) |slot| if (slot.origin == .core and slot.origin.core == (if (shard == 0) .initial else .terminal)) {
        initial_claim = slot.claim_offset;
    };
    const saved = encoded.claims[initial_claim];
    var coordinates = saved.toM31Array();
    coordinates[7] = coordinates[7].add(core.fields.m31.M31.one());
    encoded.claims[initial_claim] = O.fromM31Array(coordinates);
    try std.testing.expectError(error.WideCpuPublicRamMismatch, Worker.verifyCpu(a, &setup, request, expected, .{ 1, 1, 1 }, &pending, 0, config, &encoded));
    encoded.claims[initial_claim] = saved;
    var wrong = expected;
    wrong.statement[0] ^= 1;
    try std.testing.expectError(error.WideCpuStatementMismatch, Worker.verifyCpu(a, &setup, request, wrong, .{ 1, 1, 1 }, &pending, 0, config, &encoded));
    const saved_mass = pending.entries[0].mass;
    pending.entries[0].mass.ram += 1;
    try std.testing.expectError(error.WideCpuManifestMismatch, Worker.verifyCpu(a, &setup, request, expected, .{ 1, 1, 1 }, &pending, 0, config, &encoded));
    pending.entries[0].mass = saved_mass;
    const save_main = pending.entries[0].scope.main;
    pending.entries[0].scope.main[0] ^= 1;
    try std.testing.expectError(error.GlobalGkrPhysicalRootMismatch, Worker.verifyCpu(a, &setup, request, expected, .{ 1, 1, 1 }, &pending, 0, config, &encoded));
    pending.entries[0].scope.main = save_main;
    const short = Worker.CpuEncoded{ .bytes = encoded.bytes, .claims = encoded.claims[0..0] };
    try std.testing.expectError(error.InvalidWideCpuClaims, Worker.verifyCpu(a, &setup, request, expected, .{ 1, 1, 1 }, &pending, 0, config, &short));
    // This is a shard proof; the absent truth/other shard debts remain explicit.
    try std.testing.expectError(error.UnclosedGlobalGkrRam, pending.checkGlobalClosure(&.{accepted}));
}

test "actual CPU Keccak services shard local GKR and physical OM proof fresh verify" {
    try exercise(0, false);
}
test "actual CPU ADD DOUBLE shard local GKR and physical OM proof fresh verify" {
    try exercise(1, false);
}

test "CPU worker stage-one early OOM destroys its retained owners once" {
    try exercise(0, true);
}
