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
    return exerciseProfile(shard, mode, storage, false);
}
pub fn exerciseProfile(comptime shard: usize, comptime mode: Mode, comptime storage: Storage, comptime beta2: bool) ![32]u8 {
    return exerciseWithBinding(shard, mode, storage, beta2, false);
}
pub fn exerciseWithBinding(comptime shard: usize, comptime mode: Mode, comptime storage: Storage, comptime beta2: bool, comptime deferred: bool) ![32]u8 {
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
    const Fixed = @import("fixed_authority.zig");
    const config = core.pcs.ForField(O).PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.ForField(O).FriConfig.init(0, if (beta2) 2 else 1, 12) };
    var cache: ?Fixed.Fixed.Cache = if (beta2) try Fixed.Fixed.Cache.init(a, 1 << 30) else null;
    defer if (cache) |*owner| owner.deinit();
    var fixed: ?Fixed.Binding = if (cache) |*owner| try Fixed.Binding.acquire(owner, &setup.key, config) else null;
    defer if (fixed) |*binding| binding.deinit();
    const fixed_ptr: ?*const Fixed.Binding = if (fixed) |*binding| binding else null;
    const instances = try @import("roster.zig").fromSetup(a, &setup);
    defer a.free(instances);
    const expected = Manifest.ExpectedWorker{ .kind = .cpu, .ordinal = 0, .statement = Worker.cpuStatementWithAuthority(&setup, request, .{ 1, 1, 1 }, config, fixed_ptr), .fixed = if (fixed_ptr) |binding| binding.root() else setup.key.root, .local_instances = instances, .mass = try Worker.cpuMass(request), .global_relations = .{ .ram = true, .kio = shard == 0, .wire = shard == 1 } };
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const spill_path = try tmp.dir.realpathAlloc(a, ".");
    defer a.free(spill_path);
    const Store = @import("../../retained_main_store.zig").Store;
    var store = if (storage == .fully_parked) try Store.initFullyParked(spill_path, 128 << 20) else try Store.initParked(spill_path, 128 << 20);
    defer store.deinit();
    const original_retention = try @import("retention_plan.zig").forCpu(a, &setup, request, config, 2 << 30, 1 << 26);
    const retention = if (deferred) try @import("retention_plan.zig").withDeferredBinding(original_retention, 2 << 30) else original_retention;
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
    {
        const Authority = @import("mass_authority.zig");
        const Globals = @import("global_cpu.zig");
        var counts = @import("mass_authority_test_support.zig").Counter{};
        var plan = try @import("cpu_components.zig").Plan.init(a, &setup);
        defer plan.deinit();
        const fixed_columns = try setup.fixedColumns(a);
        defer a.free(fixed_columns);
        const main_columns = try source.columns(a, &setup, 1);
        defer a.free(main_columns);
        for (plan.slots) |slot| {
            if (Globals.layout(slot.origin).width() == 0) continue;
            const descriptor = try @import("shape_metadata.zig").forOrigin(slot.origin);
            var fixed_row: [34]@import("stwo_core").fields.m31.M31 = undefined;
            var main_row: [134]@import("stwo_core").fields.m31.M31 = undefined;
            const rows = @as(usize, 1) << @intCast(slot.log);
            for (0..rows) |row| {
                for (fixed_row[0..descriptor.widths[0]], fixed_columns[slot.fixed_offset..][0..descriptor.widths[0]]) |*v, column| v.* = column.values[row];
                for (main_row[0..descriptor.widths[1]], main_columns[slot.main_offset..][0..descriptor.widths[1]]) |*v, column| v.* = column.values[row];
                try Globals.queriesFor(@import("stwo_core").fields.m31.M31, slot.origin, fixed_row[0..descriptor.widths[0]], main_row[0..descriptor.widths[1]], &counts);
            }
        }
        try std.testing.expectEqualDeep(try Authority.cpu(request), counts.totals);
    }
    var worker = try Worker.CpuWorker.initWithAuthority(a, &setup, request, source, expected, config, .{ 1, 1, 1 }, 2 << 30, fixed_ptr);
    owns = false;
    worker.defer_local_binding = deferred;
    var owns_worker = true;
    defer if (owns_worker) worker.deinit(a);
    var native_profile = @import("stwo_prover_api").stage_profile.Recorder.init(a, "rv64", "CPU-worker-stage-scope");
    defer native_profile.deinit();
    if (mode == .normal) worker.native_recorder = &native_profile;
    if (mode == .early_seal) {
        failing.fail_index = failing.alloc_index;
        try std.testing.expectError(error.OutOfMemory, worker.seal(a));
        failing.fail_index = std.math.maxInt(usize);
        return @splat(0);
    }
    var timing = Worker.SealTiming{};
    if (mode == .normal) worker.seal_timing = &timing;
    const stage = try worker.seal(a);
    if (mode == .normal) {
        try std.testing.expect(timing.main_commit_ns > 0 and timing.gkr_ns > 0);
        try std.testing.expect(timing.numerical_requested_peak_bytes > 0);
        try std.testing.expect(timing.including_binding_requested_peak_bytes >= timing.numerical_requested_peak_bytes);
        try std.testing.expect(timing.including_binding_requested_peak_bytes <= timing.admitted_gkr_peak_bytes);
        try std.testing.expect(timing.admitted_gkr_peak_bytes <= timing.gkr_allocator_limit_bytes);
    }
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
    try std.testing.expectEqual(if (deferred) retention.projected_binding_bytes else retention.binding_bytes, binding_bytes);
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
            const next_request = P.Request{ .calls = .{ 0, 1, 1 }, .base = .{ .cpu = next.cpu.?.public, .epoch = 2, .division_requests = @intCast(next.division.len), .multiplication_requests = @intCast(next.multiplication.len), .memory = .{ .initial = &.{}, .terminal = captured.advice.terminal, .epoch = 2, .ls_count = @intCast(captured.advice.events[1].len) } } };
            var next_source = try @import("../pipeline.zig").buildCpuSource(a, &next_setup, next_request, next, &captured.advice, 1, .{ 1, 1, 1 }, false, null);
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
    if (mode == .normal) {
        var profile = try native_profile.snapshot(a);
        defer profile.deinit(a);
        var found: usize = 0;
        for (profile.stages) |stage_node| if (std.mem.eql(u8, stage_node.id, "interaction_generation")) {
            found += 1;
            try std.testing.expect(stage_node.children == null);
        };
        try std.testing.expectEqual(@as(usize, 1), found);
        try std.testing.expectEqual(@as(usize, 0), native_profile.stack.items.len);
    }
    try std.testing.expectError(error.WideCpuPhase, worker.complete(a, &pending, 0, 1 << 26));
    if (shard == 0 and mode == .normal) {
        var bad = config;
        bad.pow_bits = 33;
        const allocations_before = failing.alloc_index;
        try std.testing.expectError(error.UnsupportedWideServicesConfig, Worker.verifyCpuWithAuthority(a, &setup, request, expected, .{ 1, 1, 1 }, &pending, 0, bad, &encoded, fixed_ptr));
        try std.testing.expectEqual(allocations_before, failing.alloc_index);
    }
    {
        const Components = @import("cpu_components.zig");
        const Metadata = @import("shape_metadata.zig");
        var physical = try Components.Set.init(a, &setup, request, .{ 1, 1, 1 }, &worker.plan, &pending.entries[0].local.?, pending.shared, encoded.claims);
        defer physical.deinit();
        var global_log: u32 = 0;
        for (worker.plan.slots) |slot| global_log = @max(global_log, slot.log);
        var channel = core.channel.raw_mod_m31.Om31Channel.init();
        const point = try core.circle.randomSecureFieldPointFor(O, &channel);
        for (physical.items, worker.plan.slots) |*item, slot| {
            const descriptor = try Metadata.forOrigin(slot.origin);
            switch (item.*) {
                inline else => |*component| {
                    try std.testing.expectEqual(descriptor.constraints, component.nConstraints());
                    var bounds = try component.traceLogDegreeBounds(a);
                    defer bounds.deinitDeep(a);
                    for (bounds.items, descriptor.widths) |tree, width| try std.testing.expectEqual(width, tree.len);
                    var masks = try component.maskPoints(a, point, global_log);
                    defer masks.deinitDeep(a);
                    for (masks.items) |tree| for (tree) |column| try std.testing.expect(column.len <= descriptor.max_samples);
                    for (0..component.nConstraints()) |i| try std.testing.expect(try component.constraintDegreeBound(i) <= descriptor.degree);
                },
            }
        }
    }
    const accepted = try Worker.verifyCpuWithAuthority(a, &setup, request, expected, .{ 1, 1, 1 }, &pending, 0, config, &encoded, fixed_ptr);
    try std.testing.expect(!accepted.ram.isZero());
    var initial_claim: usize = undefined;
    for (worker.plan.slots) |slot| if (slot.origin == .core and slot.origin.core == (if (shard == 0) .initial else .terminal)) {
        initial_claim = slot.claim_offset;
    };
    const saved = encoded.claims[initial_claim];
    var coordinates = saved.toM31Array();
    coordinates[7] = coordinates[7].add(core.fields.m31.M31.one());
    encoded.claims[initial_claim] = O.fromM31Array(coordinates);
    try std.testing.expectError(error.WideCpuPublicRamMismatch, Worker.verifyCpuWithAuthority(a, &setup, request, expected, .{ 1, 1, 1 }, &pending, 0, config, &encoded, fixed_ptr));
    encoded.claims[initial_claim] = saved;
    var wrong = expected;
    wrong.statement[0] ^= 1;
    try std.testing.expectError(error.WideCpuStatementMismatch, Worker.verifyCpuWithAuthority(a, &setup, request, wrong, .{ 1, 1, 1 }, &pending, 0, config, &encoded, fixed_ptr));
    const saved_mass = pending.entries[0].mass;
    pending.entries[0].mass.ram += 1;
    try std.testing.expectError(error.WideCpuManifestMismatch, Worker.verifyCpuWithAuthority(a, &setup, request, expected, .{ 1, 1, 1 }, &pending, 0, config, &encoded, fixed_ptr));
    pending.entries[0].mass = saved_mass;
    const save_main = pending.entries[0].scope.main;
    pending.entries[0].scope.main[0] ^= 1;
    try std.testing.expectError(error.GlobalGkrPhysicalRootMismatch, Worker.verifyCpuWithAuthority(a, &setup, request, expected, .{ 1, 1, 1 }, &pending, 0, config, &encoded, fixed_ptr));
    pending.entries[0].scope.main = save_main;
    const short = Worker.CpuEncoded{ .bytes = encoded.bytes, .claims = encoded.claims[0..0] };
    try std.testing.expectError(error.InvalidWideCpuClaims, Worker.verifyCpuWithAuthority(a, &setup, request, expected, .{ 1, 1, 1 }, &pending, 0, config, &short, fixed_ptr));
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

test "beta2 CPU K and ADD DOUBLE physical proofs authenticate independent fixed authority" {
    _ = try exerciseProfile(0, .normal, .fully_parked, true);
    _ = try exerciseProfile(1, .normal, .fully_parked, true);
}

test "deferred CPU projection completes after retirement and full parking with beta1 beta2 proof parity and abort cleanup" {
    inline for ([_]bool{ false, true }) |beta2| {
        const original = try exerciseWithBinding(0, .normal, .fully_parked, beta2, false);
        const projected = try exerciseWithBinding(0, .normal, .fully_parked, beta2, true);
        try std.testing.expectEqualSlices(u8, &original, &projected);
    }
    _ = try exerciseWithBinding(0, .parked_abort, .fully_parked, false, true);
    _ = try exerciseWithBinding(0, .later_worker_oom, .fully_parked, false, true);
}
