//! One typed stage-one barrier and complete physical proof set. This route is
//! explicit and experimental; it never constructs an old CPU Frame/Pending.
const std = @import("std");
const Stage = @import("stwo_prover_api").stage_profile;
const engine = @import("stwo_prover_engine");
const R = @import("../../word16_global_execution/services/roster.zig");
const Advice = @import("../../word16_global_execution/services/collector.zig").Advice;
const Native = @import("../../word16_execution/prepared.zig").Prepared;
const Pipeline = @import("../../word16_global_execution/services/pipeline.zig");
const I = @import("inventory.zig");
const M = @import("manifest.zig");
const CPU = @import("worker.zig");
const Frontier = @import("source.zig").Source;
const D = @import("../sponge_local_gkr/worker.zig");
const Truth = @import("../pure_p2_truth_worker.zig");
const LocalTruth = @import("../truth_local_gkr/worker.zig");
const Miller = @import("../pure_p2_tower_worker.zig");
const LocalMiller = @import("../miller_local_gkr/worker.zig");
const Tower = @import("../pure_p2_op_inventory.zig").MillerDeclaration;
const OldM = @import("../pure_p2_manifest.zig");
const W = @import("../pure_p2_worker_protocol.zig").W;
const Store = @import("../pure_p2_retained_main.zig").Store;
const B = @import("wire.zig");
const MetadataParking = @import("../pure_p2_cpu_metadata_parking.zig");
pub const Limits = struct {
    recorders: []const ?*Stage.Recorder = &.{},
    consume_memory_events: bool = false,
    park_cpu_metadata: bool = false,
    retire_source_auxiliaries: bool = false,
    cpu: @import("../pure_p2_cpu_worker.zig").Limits,
    truth: Truth.Limits,
    truth_gkr_bytes: usize,
    detached_live_bytes: usize,
    detached_gkr_bytes: usize,
    global_bytes: usize,
    miller: Miller.Limits,
    miller_gkr_bytes: usize,
    fn recorder(self: Limits, ordinal: usize) ?*Stage.Recorder {
        return if (self.recorders.len == 0) null else self.recorders[ordinal];
    }
};
pub const Inputs = struct {
    /// Optional tokens parked by the capture owner, borrowed through completion.
    captured_metadata: ?[]?MetadataParking.Token = null,
    captured_events: ?[]?@import("event_custody.zig").Token = null,
    cpus: []const I.Cpu,
    detached: []const I.Detached,
    catalog: []const I.Catalog,
    towers: []const Tower,
    native: []const *Native,
    advice: *const Advice,
    calls: []const @import("stwo_riscv_frontend").rv64_air.crypto.keccak_sponge.types.Call,
    words: []const @import("stwo_riscv_frontend").rv64_air.memory.closed_ram.types.State,
};
const Worker = union(enum) {
    cpu: CPU.Worker,
    detached: struct { value: D.Worker, budget: *engine.host_budget_allocator.SharedHostBudget },
    truth: Truth.Worker,
    local: LocalTruth.Worker,
    miller: Miller.Worker,
    miller_local: LocalMiller.Worker,
    fn deinit(self: *Worker) void {
        switch (self.*) {
            .detached => |*v| {
                v.value.deinit();
                v.budget.destroy();
            },
            inline else => |*v| v.deinit(),
        }
    }
    fn allocator(self: *Worker) std.mem.Allocator {
        return switch (self.*) {
            .detached => |*v| v.value.allocator,
            inline else => |*v| v.allocator,
        };
    }
    fn scheme(self: *Worker) *W.Scheme {
        return switch (self.*) {
            .detached => |*v| &v.value.scheme,
            inline else => |*v| &v.scheme,
        };
    }
    fn seal(self: *Worker) !M.StageOne {
        return switch (self.*) {
            .cpu => |*v| blk: {
                const s = try v.seal();
                break :blk .{ .main = s.main, .local = .{ .proof = &v.child.?.result.proof, .receipt = s.receipt } };
            },
            .detached => |*v| .{ .main = try v.value.seal() },
            inline else => |*v| .{ .main = (try v.seal()).main },
        };
    }
    fn complete(self: *Worker, a: std.mem.Allocator, digest: [36]u8, main: [36]u8) !B.Fragment {
        switch (self.*) {
            .cpu => |*v| {
                const out = try v.complete(digest);
                return .{ .main = main, .native = out.bytes, .local = out.local, .receipt = out.receipt, .claims = out.claims };
            },
            .detached => |*v| {
                var out = try v.value.complete(digest);
                defer out.deinit(v.value.allocator);
                const bytes = try a.dupe(u8, out.bytes);
                errdefer a.free(bytes);
                const local = try a.dupe(u8, out.local);
                errdefer a.free(local);
                const claims = try a.alloc(W.O, 24);
                for (out.claims, 0..) |row, i| @memcpy(claims[3 * i ..][0..3], &row);
                return .{ .main = main, .native = bytes, .local = local, .receipt = out.receipt, .claims = claims };
            },
            .miller => |*v| {
                var out = try v.completeSealed(.{ .manifest = digest, .main = main });
                errdefer out.deinit(a);
                return .{ .main = main, .native = out.bytes, .local = try a.alloc(u8, 0), .receipt = null, .claims = try a.dupe(W.O, &out.claims) };
            },
            .miller_local => |*v| {
                var out = try v.completeSealed(.{ .manifest = digest, .main = main });
                errdefer out.deinit(a);
                return .{ .main = main, .native = out.bytes, .local = out.local, .receipt = out.receipt, .claims = try a.dupe(W.O, &out.claims) };
            },
            .truth => |*v| {
                const out = try v.completeSealed(.{ .manifest = digest, .main = main });
                return .{ .main = main, .native = out.bytes, .local = try a.alloc(u8, 0), .receipt = null, .claims = out.claims };
            },
            .local => |*v| {
                const out = try v.completeSealed(.{ .manifest = digest, .main = main });
                errdefer {
                    var own = out;
                    own.deinit(a);
                }
                return .{ .main = main, .native = out.bytes, .local = out.local, .receipt = out.receipt, .claims = try a.dupe(W.O, &out.claims) };
            },
        }
    }
};
fn sealAndPark(worker: *Worker, expected_worker: M.Expected, store: *Store, recorder: ?*Stage.Recorder) !M.StageOne {
    switch (worker.*) {
        .detached => |*v| v.value.native_recorder = recorder,
        inline else => |*v| v.native_recorder = recorder,
    }
    var seal = try Stage.StageScope.begin(recorder, "stage_one_seal", "Native MAIN and local GKR sealing");
    defer seal.end();
    const out = try worker.seal();
    seal.end();
    var park = try Stage.StageScope.begin(recorder, "retained_main_park", "Write already committed coefficients and Merkle layers");
    defer park.end();
    _ = try store.parkBound(worker.allocator(), &worker.scheme().trees.items[1], .{ .setup = expected_worker.authority.fixed_identity, .statement = expected_worker.authority.statement });
    return out;
}
fn expected(source: I.Catalog, ordinal: u32) !OldM.Expected {
    return if (source.local_key) |key| key.expected(source.truth, ordinal) else source.key.expected(source.truth, ordinal);
}
pub fn produce(a: std.mem.Allocator, inventory: *const I.Inventory, inputs: Inputs, store: *Store, limits: Limits) !B.Bundle {
    if (limits.consume_memory_events and !@import("stwo_riscv_frontend").rv64_air.memory.ownership.same(a, inputs.advice.allocator)) return error.IncompatibleServiceAdviceAllocator;
    if (!engine.host_budget_allocator.SharedHostBudget.isAllocator(a)) return error.OpNativeRequiresSharedHostBudget;
    if (limits.recorders.len != 0 and limits.recorders.len != inventory.workers.len) return error.InvalidOpNativeTimings;
    if (inputs.cpus.len != inventory.cpu_count or inputs.detached.len != inventory.detached_count or inputs.catalog.len != inventory.truth_count or inputs.native.len != inputs.cpus.len or inputs.advice.sponge.len != inputs.cpus.len or inputs.cpus.len + inputs.detached.len + inputs.catalog.len + inputs.towers.len != inventory.workers.len) return error.DetachedInventoryRoster;
    // Current capture is a single immutable flattened suffix. Multi-worker
    // partitioning must provide separate source slices, never duplicate it.
    if (inputs.detached.len > 1) return error.DetachedSourcePartitionRequired;
    if (inputs.captured_events) |tokens| {
        if (!limits.consume_memory_events or tokens.len != inputs.cpus.len) return error.OpCaptureCustodyCoverage;
    }
    const workers = try a.alloc(Worker, inventory.workers.len);
    defer a.free(workers);
    var made: usize = 0;
    var retired: usize = 0;
    defer for (workers[retired..made]) |*worker| worker.deinit();
    const stages = try a.alloc(M.StageOne, workers.len);
    defer a.free(stages);
    if (inputs.captured_metadata) |tokens| {
        if (!limits.park_cpu_metadata or tokens.len != inputs.cpus.len) return error.OpCaptureCustodyCoverage;
        for (tokens) |token| if (token == null) return error.OpCaptureCustodyCoverage;
    }
    const owns_metadata = inputs.captured_metadata == null;
    const metadata = inputs.captured_metadata orelse try a.alloc(?MetadataParking.Token, inputs.cpus.len);
    defer if (owns_metadata) a.free(metadata);
    if (owns_metadata) @memset(metadata, null);
    defer if (owns_metadata) {
        for (metadata) |*token| if (token.*) |*owner| owner.deinit();
    };
    if (limits.park_cpu_metadata and owns_metadata) {
        // Same bounded immutable custody as the classic OP producer. This is
        // advice storage, never a replacement for physical MAIN/GKR authority.
        var total: usize = 0;
        for (inputs.native) |n| total = try std.math.add(usize, total, try MetadataParking.roundedBytes(if (n.cpu) |*cpu| cpu else return error.PreparedExecutionConsumed));
        if (total > store.disk_limit - store.reserved) return error.OpParkingDiskLimit;
        for (inputs.native, metadata) |n, *token| token.* = try MetadataParking.park(store, if (n.cpu) |*cpu| cpu else return error.PreparedExecutionConsumed);
    }
    for (inputs.cpus, inputs.native, 0..) |cpu, n, ordinal| {
        var source_scope = try Stage.StageScope.begin(limits.recorder(ordinal), "source_construction", "Construct worker witness and narrow metadata once");
        defer source_scope.end();
        if (metadata[ordinal]) |*token| try token.restore(if (n.cpu) |*value| value else return error.PreparedExecutionConsumed);
        if (inputs.captured_events) |tokens| {
            if (tokens[ordinal]) |*token| {
                try token.restore(inputs.advice.allocator, try @import("capture_custody.zig").Owner.eventDescriptor(n, ordinal), &inputs.advice.events[ordinal]);
            } else if (n.raw_counts.memory != 0 or inputs.advice.events[ordinal].len != 0) return error.OpCaptureCustodyCoverage;
        }
        var source = try Pipeline.buildCpuSourceForOp(a, cpu.setup, cpu.request, cpu.span, n, inputs.advice, ordinal, inventory.first_ids[ordinal], limits.consume_memory_events, null);
        var source_owned = true;
        defer if (source_owned) source.deinit();
        if (inputs.captured_events) |tokens| if (tokens[ordinal]) |*token| try token.consumed(inputs.advice.events[ordinal]);
        var frontier = try Frontier.initCalls(a, inputs.advice.sponge[ordinal].calls, cpu.request.sponge.calls, cpu.key.frontier_log, @intCast(cpu.request.base.epoch), @intCast(ordinal));
        var frontier_owned = true;
        defer if (frontier_owned) frontier.deinit();
        workers[ordinal] = .{ .cpu = try CPU.Worker.init(a, cpu.setup, cpu.request, cpu.span, inventory.first_ids[ordinal], @intCast(ordinal), cpu.key, source, frontier, limits.cpu) };
        source_owned = false;
        frontier_owned = false;
        made += 1;
        source_scope.end();
        stages[ordinal] = try sealAndPark(&workers[ordinal], inventory.workers[ordinal], store, limits.recorder(ordinal));
        if (limits.retire_source_auxiliaries) _ = try @import("../pure_p2_source_auxiliary_retirement.zig").retire(&workers[ordinal].cpu.source);
        if (metadata[ordinal]) |*token| try token.retireRestored(&workers[ordinal].cpu.source.core.cpu);
    }
    for (inputs.detached, 0..) |source, j| {
        const ordinal = inputs.cpus.len + j;
        var source_scope = try Stage.StageScope.begin(limits.recorder(ordinal), "source_construction", "Construct worker witness and narrow metadata once");
        defer source_scope.end();
        const budget = try engine.host_budget_allocator.SharedHostBudget.createRetainingParent(a, limits.detached_live_bytes);
        var owns_budget = true;
        defer if (owns_budget) budget.destroy();
        workers[ordinal] = .{ .detached = .{ .value = try D.Worker.init(budget.allocator(), source.geometry, source.key, @intCast(ordinal), inputs.calls, inputs.words, limits.global_bytes), .budget = budget } };
        owns_budget = false;
        made += 1;
        source_scope.end();
        stages[ordinal] = try sealAndPark(&workers[ordinal], inventory.workers[ordinal], store, limits.recorder(ordinal));
    }
    for (inputs.catalog, 0..) |source, j| {
        const ordinal = inputs.cpus.len + inputs.detached.len + j;
        var source_scope = try Stage.StageScope.begin(limits.recorder(ordinal), "source_construction", "Construct worker witness and narrow metadata once");
        defer source_scope.end();
        const exp = try expected(source, @intCast(ordinal));
        workers[ordinal] = if (source.local_key) |key| .{ .local = try LocalTruth.Worker.initWithGkrOptions(a, key, source.truth, Truth.SourceBuilder.fromAdvice(inputs.advice), exp, .{ .live_bytes = limits.truth.live_bytes, .main_bytes = limits.truth.main_bytes, .interaction_bytes = limits.truth.interaction_bytes, .gkr_bytes = limits.truth_gkr_bytes }, .{ .coefficient_encoding = .fixed4 }) } else .{ .truth = try Truth.Worker.init(a, source.key, source.truth, Truth.SourceBuilder.fromAdvice(inputs.advice), exp, limits.truth) };
        made += 1;
        source_scope.end();
        stages[ordinal] = try sealAndPark(&workers[ordinal], inventory.workers[ordinal], store, limits.recorder(ordinal));
    }
    const TowerInput = @import("stwo_riscv_frontend").rv64_air.crypto.bn254_tower.narrow.trace.Input;
    for (inputs.towers, 0..) |item, j| {
        const ordinal = inputs.cpus.len + inputs.detached.len + inputs.catalog.len + j;
        var source_scope = try Stage.StageScope.begin(limits.recorder(ordinal), "source_construction", "Construct worker witness and narrow metadata once");
        defer source_scope.end();
        const exp = if (item.local_key) |key| try key.expected(item.span, @intCast(ordinal)) else try item.key.expected(item.span, @intCast(ordinal));
        const input = try a.alloc(TowerInput, item.span.calls);
        defer a.free(input);
        var next: u64 = 1;
        var filled: usize = 0;
        for (inputs.advice.tower) |calls| for (calls) |call| {
            if (next >= item.span.first_id and next < @as(u64, item.span.first_id) + item.span.calls) {
                if (filled >= input.len) return error.InvalidOpTowerCoverage;
                for (&input[filled], 0..) |*value, k| value.* = @as(u256, call.before[4 * k]) | (@as(u256, call.before[4 * k + 1]) << 64) | (@as(u256, call.before[4 * k + 2]) << 128) | (@as(u256, call.before[4 * k + 3]) << 192);
                filled += 1;
            }
            next += 1;
        };
        if (filled != input.len) return error.InvalidOpTowerCoverage;
        workers[ordinal] = if (item.local_key) |key| .{ .miller_local = try LocalMiller.Worker.init(a, key, item.span, exp, input, .{ .live_bytes = limits.miller.live_bytes, .main_bytes = limits.miller.main_bytes, .interaction_bytes = limits.miller.interaction_bytes, .advice_bytes = limits.miller.advice_bytes, .gkr_bytes = limits.miller_gkr_bytes }) } else .{ .miller = try Miller.Worker.init(a, item.key, item.span, exp, input, limits.miller) };
        made += 1;
        source_scope.end();
        stages[ordinal] = try sealAndPark(&workers[ordinal], inventory.workers[ordinal], store, limits.recorder(ordinal));
    }
    var pending = try M.verifyAndSeal(a, inventory.execution, inventory.workers, stages);
    defer pending.deinit(a);
    const fragments = try a.alloc(B.Fragment, workers.len);
    errdefer a.free(fragments);
    var completed: usize = 0;
    errdefer for (fragments[0..completed]) |*fragment| fragment.deinit(a);
    for (workers, 0..) |*worker, ordinal| {
        if (ordinal < metadata.len) if (metadata[ordinal]) |*token| try token.restore(&worker.cpu.source.core.cpu);
        var restore = try Stage.StageScope.begin(limits.recorder(ordinal), "retained_main_restore", "Map and integrity-check sealed source payload");
        defer restore.end();
        _ = try store.restoreBound(&worker.scheme().trees.items[1], .{ .setup = inventory.workers[ordinal].authority.fixed_identity, .statement = inventory.workers[ordinal].authority.statement });
        restore.end();
        try pending.checkPhysicalRoots(ordinal, inventory.workers[ordinal].authority.fixed, stages[ordinal].main);
        var complete = try Stage.StageScope.begin(limits.recorder(ordinal), "stage_two_prove", "Manifest-bound native interaction and physical proof");
        defer complete.end();
        fragments[ordinal] = try worker.complete(a, pending.digest, stages[ordinal].main);
        complete.end();
        completed += 1;
        worker.deinit();
        retired += 1;
    }
    return .{ .execution = inventory.execution, .fragments = fragments };
}
