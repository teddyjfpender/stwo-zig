const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const F = @import("../fixture.zig");
const R = @import("../roster.zig");
const P = @import("../protocol.zig");
const Worker = @import("cpu_worker.zig");
const Manifest = @import("manifest.zig");
pub const Mode = enum { normal, unretired, early_seal, parked_abort, later_worker_oom };
pub const Storage = enum { resident, coefficients, fully_parked };
pub fn exercise(comptime shard: usize, comptime mode: Mode, comptime storage: Storage) ![32]u8 {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    const a = failing.allocator();
    var captured = try F.Captured.init(a);
    defer captured.deinit();
    var setup = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &F.WORDS }, try captured.native[shard].geometry(), if (shard == 0) .{ .keccak = 5 } else .{ .add = 5, .double = 5 });
    defer setup.deinit();
    const n = &captured.native[shard];
    const request = P.Request{ .calls = v2Calls(if (shard == 0) .{ 1, 0, 0 } else .{ 0, 1, 1 }), .base = .{ .cpu = n.cpu.?.public, .epoch = @intCast(shard + 1), .division_requests = @intCast(n.division.len), .multiplication_requests = @intCast(n.multiplication.len), .memory = .{ .initial = if (shard == 0) captured.advice.initial else &.{}, .terminal = if (shard == 1) captured.advice.terminal else &.{}, .epoch = @intCast(shard + 1), .ls_count = @intCast(captured.advice.events[shard].len) } } };
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
    const Store = @import("../../retained_main_store.zig").Store;
    var store = if (storage == .fully_parked) try Store.initFullyParked(spill_path, 128 << 20) else try Store.initParked(spill_path, 128 << 20);
    defer store.deinit();
    const retention = try @import("retention_plan.zig").forCpu(a, &setup, request, config, 2 << 30, 1 << 26);
    try std.testing.expectError(error.ClassicWitnessBudgetExceeded, @import("retention_plan.zig").forCpu(a, &setup, request, config, 2 << 30, 1));
    if (shard == 0 and mode == .normal) {
        var bad = config;
        bad.pow_bits = 33;
        const allocations_before = failing.alloc_index;
        try std.testing.expectError(error.UnsupportedWideServicesConfig, Worker.CpuWorker.init(a, &setup, request, source, expected, bad, .{ 1, 1, 1 }, 2 << 30));
        try std.testing.expectEqual(allocations_before, failing.alloc_index);
        bad = config;
        bad.fri_config.log_blowup_factor = 2;
        try std.testing.expectError(error.UnsupportedWideServicesConfig, Worker.CpuWorker.init(a, &setup, request, source, expected, bad, .{ 1, 1, 1 }, 2 << 30));
        try std.testing.expectEqual(allocations_before, failing.alloc_index);
    }
    var worker = try Worker.CpuWorker.init(a, &setup, request, source, expected, config, .{ 1, 1, 1 }, 2 << 30);
    owns = false;
    var owns_worker = true;
    defer if (owns_worker) worker.deinit(a);
    if (mode == .early_seal) {
        failing.fail_index = failing.alloc_index;
        try std.testing.expectError(error.OutOfMemory, worker.seal(a));
        failing.fail_index = std.math.maxInt(usize);
        return @splat(0);
    }
    var timing = Worker.SealTiming{};
    if (mode == .normal) worker.seal_timing = &timing;
    const stage = try worker.seal(a);
    if (mode == .normal) try std.testing.expect(timing.main_commit_ns > 0 and timing.gkr_ns > 0);
    try std.testing.expectError(error.WideCpuPhase, worker.seal(a));
    if (mode != .unretired) {
        try worker.retireLocalMetadata();
        try worker.retireLocalMetadata();
        const memory_after = &worker.source.core.memory;
        var advice_bytes = std.mem.sliceAsBytes(memory_after.statement.initial).len + std.mem.sliceAsBytes(memory_after.statement.terminal).len;
        advice_bytes += std.mem.sliceAsBytes(memory_after.ls.metadata).len;
        if (memory_after.ls_tail) |tail| advice_bytes += std.mem.sliceAsBytes(tail.metadata).len;
        advice_bytes += std.mem.sliceAsBytes(memory_after.initial.metadata).len + std.mem.sliceAsBytes(memory_after.terminal.metadata).len;
        inline for (.{ "keccak", "add", "double" }) |name| if (@field(worker.source, name)) |bridge| {
            advice_bytes += std.mem.sliceAsBytes(bridge.calls).len;
            try std.testing.expectEqual(@as(usize, 0), bridge.fixed.len + bridge.counts16.len + bridge.counts8.len);
        };
        try std.testing.expectEqual(retention.global_metadata_bytes, advice_bytes);
        try std.testing.expectEqual(@as(usize, 0), memory_after.ls.fixed.len + memory_after.ls.counts16.len + memory_after.ls.counts8.len + memory_after.ls.selection_counts.len + memory_after.selection.fixed.len + memory_after.counts16.len + memory_after.counts8.len);
    }
    var coefficient_bytes: usize = 0;
    for (worker.scheme.trees.items[1].coefficients.?) |c| coefficient_bytes += std.mem.sliceAsBytes(c.coefficients()).len;
    try std.testing.expectEqual(retention.coefficient_bytes, coefficient_bytes);
    var merkle_bytes: usize = 0;
    for (worker.scheme.trees.items[1].commitment.layers) |layer| merkle_bytes += std.mem.sliceAsBytes(layer).len;
    try std.testing.expect(merkle_bytes <= retention.main_merkle_node_bytes);
    try std.testing.expectEqual(retention.main_merkle_bytes, retention.main_merkle_node_bytes + retention.main_merkle_descriptor_bytes);
    var binding_bytes: usize = 0;
    for (worker.child.?.binding.columns) |column| binding_bytes += std.mem.sliceAsBytes(column).len;
    try std.testing.expectEqual(retention.binding_bytes, binding_bytes);
    try std.testing.expectEqual(retention.resident_retained_bytes, retention.parked_retained_bytes + retention.coefficient_bytes);

    if (storage != .resident) {
        try std.testing.expect(try worker.spillMain(&store) > 0);
        try std.testing.expectEqual(@as(usize, 0), store.stats().live_mapped_bytes);
    }
    if (mode == .parked_abort or mode == .later_worker_oom) {
        if (mode == .later_worker_oom) {
            const next = &captured.native[1];
            var next_setup = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &F.WORDS }, try next.geometry(), .{ .add = 5, .double = 5 });
            defer next_setup.deinit();
            const next_request = P.Request{ .calls = v2Calls(.{ 0, 1, 1 }), .base = .{ .cpu = next.cpu.?.public, .epoch = 2, .division_requests = @intCast(next.division.len), .multiplication_requests = @intCast(next.multiplication.len), .memory = .{ .initial = &.{}, .terminal = captured.advice.terminal, .epoch = 2, .ls_count = @intCast(captured.advice.events[1].len) } } };
            var next_source = try @import("../pipeline.zig").buildCpuSource(a, &next_setup, next_request, next, &captured.advice, 1, @import("v2_scope.zig").widenFirstIds(.{ 1, 1, 1 }), false, null);
            var owns_next_source = true;
            defer if (owns_next_source) next_source.deinit();
            const next_instances = try @import("roster.zig").fromSetup(a, &next_setup);
            defer a.free(next_instances);
            const next_expected = Manifest.ExpectedWorker{ .kind = .cpu, .ordinal = 1, .statement = Worker.cpuStatement(&next_setup, next_request, .{ 1, 1, 1 }, config), .fixed = next_setup.key.root, .local_instances = next_instances, .mass = try Worker.cpuMass(next_request), .global_relations = .{ .ram = true, .kio = false, .wire = true } };
            var later = try Worker.CpuWorker.init(a, &next_setup, next_request, next_source, next_expected, config, .{ 1, 1, 1 }, 2 << 30);
            owns_next_source = false;
            defer later.deinit(a);
            failing.fail_index = failing.alloc_index;
            try std.testing.expectError(error.OutOfMemory, later.seal(a));
            failing.fail_index = std.math.maxInt(usize);
            // The previous parked worker remains owned throughout this failure.
            try std.testing.expect(store.stats().live_bytes > 0);
            try std.testing.expectEqual(@as(usize, 0), store.stats().live_mapped_bytes);
        }
        worker.deinit(a);
        owns_worker = false;
        try std.testing.expectEqual(@as(usize, 0), store.stats().live_bytes);
        try std.testing.expectEqual(@as(usize, 0), store.stats().live_mapped_bytes);
        try std.testing.expect(store.parking.head == null and store.owners == null);
        return @splat(0);
    }
    if (storage != .resident) try std.testing.expect(try worker.restoreMain(&store) > 0);
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
    if (shard == 0 and mode == .normal) {
        var bad = config;
        bad.pow_bits = 33;
        const allocations_before = failing.alloc_index;
        try std.testing.expectError(error.UnsupportedWideServicesConfig, Worker.verifyCpu(a, &setup, request, expected, .{ 1, 1, 1 }, &pending, 0, bad, &encoded));
        try std.testing.expectEqual(allocations_before, failing.alloc_index);
    }
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
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(encoded.bytes);
    for (encoded.claims) |claim| for (claim.toM31Array()) |coordinate| {
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, coordinate.v, .little);
        hash.update(&bytes);
    };
    var digest: [32]u8 = undefined;
    hash.final(&digest);
    return digest;
}

test "actual CPU Keccak services shard local GKR and physical OM proof fresh verify" {
    const retired = try exercise(0, .normal, .coefficients);
    const control = try exercise(0, .unretired, .coefficients);
    try std.testing.expectEqualSlices(u8, &control, &retired);
}
test "actual CPU ADD DOUBLE shard local GKR and physical OM proof fresh verify" {
    const retired = try exercise(1, .normal, .coefficients);
    const control = try exercise(1, .unretired, .coefficients);
    try std.testing.expectEqualSlices(u8, &control, &retired);
}

test "CPU worker stage-one early OOM destroys its retained owners once" {
    _ = try exercise(0, .early_seal, .coefficients);
}

test "CPU parked worker abort tears down FD registry and store without restore" {
    _ = try exercise(0, .parked_abort, .coefficients);
}
test "later CPU stage-one OOM unwinds prior parked worker without stale owners" {
    _ = try exercise(0, .later_worker_oom, .coefficients);
}
fn v2Calls(calls: [3]u32) [@import("../types.zig").FAMILIES]u32 {
    return calls ++ @as([@import("../types.zig").FAMILIES - 3]u32, @splat(0));
}
