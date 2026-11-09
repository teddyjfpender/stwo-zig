//! First complete native OP producer: one source construction per worker,
//! stage-one barrier, bounded parked MAIN, then exact manifest-bound completion.
//! Sequential reference schedule; scheduling does not change proof authority.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const Budget = engine.host_budget_allocator.SharedHostBudget;
const Inv = @import("pure_p2_op_inventory.zig");
const B = @import("pure_p2_op_bundle.zig");
const MW = @import("pure_p2_manifest_wire.zig");
const Manifest = @import("pure_p2_manifest.zig");
const CPU = @import("pure_p2_cpu_worker.zig");
const Truth = @import("pure_p2_truth_worker.zig");
const Miller = @import("pure_p2_tower_worker.zig");
const Key = @import("pure_p2_fixed_key.zig").Key;
const Store = @import("pure_p2_retained_main.zig").Store;
const R = @import("../word16_global_execution/services/roster.zig");
const P = @import("../word16_global_execution/services/protocol.zig");
const T = @import("../word16_global_execution/services/types.zig");
const Advice = @import("../word16_global_execution/services/collector.zig").Advice;
const Pipeline = @import("../word16_global_execution/services/pipeline.zig");
const Native = @import("../word16_execution/prepared.zig").Prepared;
const W = @import("pure_p2_worker_protocol.zig").W;
const Stage = @import("stwo_prover_api").stage_profile;
pub const Timing = struct { stage_one_ns: u64 = 0, manifest_ns: u64 = 0, stage_two_ns: u64 = 0 };
pub const Limits = struct {
    cpu: CPU.Limits,
    truth: Truth.Limits,
    miller: Miller.Limits,
    recorders: []const ?*Stage.Recorder = &.{},
    timing: ?*Timing = null,
    /// Destructive source handoff only; metadata/requests already admitted.
    consume_memory_events: bool = false,
    fn recorder(self: Limits, i: usize) ?*Stage.Recorder {
        return if (self.recorders.len == 0) null else self.recorders[i];
    }
};
const Worker = union(enum) {
    cpu: CPU.Worker,
    truth: Truth.Worker,
    miller: Miller.Worker,
    fn deinit(self: *Worker) void {
        switch (self.*) {
            inline else => |*v| v.deinit(),
        }
    }
    fn scheme(self: *Worker) *W.Scheme {
        return switch (self.*) {
            inline else => |*v| &v.scheme,
        };
    }
    fn allocator(self: *Worker) std.mem.Allocator {
        return switch (self.*) {
            inline else => |v| v.allocator,
        };
    }
    fn seal(self: *Worker, a: std.mem.Allocator) !Manifest.StageOne {
        return switch (self.*) {
            .cpu => |*v| v.seal(a),
            inline else => |*v| v.seal(),
        };
    }
    fn complete(self: *Worker, a: std.mem.Allocator, pending: *const Manifest.Pending, index: usize) !B.Proof {
        return switch (self.*) {
            .cpu => |*v| block: {
                const out = try v.complete(a, pending, index);
                break :block .{ .bytes = out.bytes, .claims = out.claims };
            },
            .truth => |*v| block: {
                const out = try v.complete(pending, index);
                break :block .{ .bytes = out.bytes, .claims = out.claims };
            },
            .miller => |*v| block: {
                var out = try v.complete(pending, index);
                errdefer out.deinit(a);
                break :block .{ .bytes = out.bytes, .claims = try a.dupe(W.O, &out.claims) };
            },
        };
    }
};
fn sealAndPark(a: std.mem.Allocator, worker: *Worker, expected: Manifest.Expected, store: *Store, recorder: ?*Stage.Recorder) !Manifest.StageOne {
    switch (worker.*) {
        inline else => |*v| v.native_recorder = recorder,
    }
    var seal = try Stage.StageScope.begin(recorder, "stage_one_seal", "Native MAIN and local GKR sealing");
    defer seal.end();
    const out = try worker.seal(a);
    seal.end();
    var park = try Stage.StageScope.begin(recorder, "retained_main_park", "Write already committed coefficients and Merkle layers");
    defer park.end();
    _ = try store.parkBound(worker.allocator(), &worker.scheme().trees.items[1], .{ .setup = expected.fixed_identity, .statement = expected.statement });
    return out;
}
pub fn produce(a: std.mem.Allocator, inventory: *const Inv.Inventory, setups: []const *const R.CpuSetup, requests: []const P.Request, spans: []const T.OpTowerSpan, keys: []const *const Key, truths: []const R.Truth, truth_keys: []const *const Truth.Key, miller: []const Inv.MillerDeclaration, native: []const *Native, advice: *const Advice, store: *Store, limits: Limits) !B.Bundle {
    if (!Budget.isAllocator(a)) return error.OpNativeRequiresSharedHostBudget;
    if (limits.consume_memory_events and !@import("stwo_riscv_frontend").rv64_air.memory.ownership.same(a, advice.allocator)) return error.IncompatibleServiceAdviceAllocator;
    if (setups.len != inventory.cpu_count or requests.len != setups.len or spans.len != setups.len or keys.len != setups.len or native.len != setups.len or advice.tower.len != setups.len or truths.len != inventory.truth_count or truth_keys.len != truths.len or setups.len + truths.len + miller.len != inventory.workers.len) return error.InvalidOpNativeInventory;
    if (limits.recorders.len != 0 and limits.recorders.len != inventory.workers.len) return error.InvalidOpNativeTimings;
    var timer = try std.time.Timer.start();
    const workers = try a.alloc(Worker, inventory.workers.len);
    defer a.free(workers);
    var done: usize = 0;
    var retired: usize = 0;
    defer for (workers[retired..done]) |*worker| worker.deinit();
    const stages = try a.alloc(Manifest.StageOne, workers.len);
    defer a.free(stages);
    for (setups, requests, spans, keys, native, 0..) |setup, request, span, key, n, i| {
        var source_scope = try Stage.StageScope.begin(limits.recorder(i), "source_construction", "Construct CPU witness and narrow metadata once");
        defer source_scope.end();
        var source = try Pipeline.buildCpuSourceForOp(a, setup, request, span, n, advice, i, inventory.first_ids[i], limits.consume_memory_events, limits.recorder(i));
        const worker = CPU.Worker.initForOp(a, setup, request, span, source, inventory.workers[i], inventory.first_ids[i], key, limits.cpu) catch |err| {
            source.deinit();
            return err;
        };
        workers[done] = .{ .cpu = worker };
        done += 1;
        source_scope.end();
        stages[i] = try sealAndPark(a, &workers[i], inventory.workers[i], store, limits.recorder(i));
    }
    for (truths, truth_keys, 0..) |truth, key, j| {
        const i = setups.len + j;
        var source_scope = try Stage.StageScope.begin(limits.recorder(i), "source_construction", "Construct inherited truth witness once");
        defer source_scope.end();
        workers[done] = .{ .truth = try Truth.Worker.init(a, key, truth, Truth.SourceBuilder.fromAdvice(advice), inventory.workers[i], limits.truth) };
        done += 1;
        source_scope.end();
        stages[i] = try sealAndPark(a, &workers[i], inventory.workers[i], store, limits.recorder(i));
    }
    const Input = @import("stwo_riscv_frontend").rv64_air.crypto.bn254_tower.narrow.trace.Input;
    for (miller, 0..) |item, j| {
        const i = setups.len + truths.len + j;
        var source_scope = try Stage.StageScope.begin(limits.recorder(i), "source_construction", "Marshal inputs and construct Miller DAG witness once");
        defer source_scope.end();
        const input = try a.alloc(Input, item.span.calls);
        defer a.free(input);
        var ordinal: u64 = 1;
        var filled: usize = 0;
        for (advice.tower) |calls| for (calls) |call| {
            if (ordinal >= item.span.first_id and ordinal < @as(u64, item.span.first_id) + item.span.calls) {
                if (filled >= input.len) return error.InvalidOpTowerCoverage;
                for (&input[filled], 0..) |*value, k| value.* = @as(u256, call.before[4 * k]) | (@as(u256, call.before[4 * k + 1]) << 64) | (@as(u256, call.before[4 * k + 2]) << 128) | (@as(u256, call.before[4 * k + 3]) << 192);
                filled += 1;
            }
            ordinal += 1;
        };
        if (filled != input.len) return error.InvalidOpTowerCoverage;
        workers[done] = .{ .miller = try Miller.Worker.init(a, item.key, item.span, inventory.workers[i], input, limits.miller) };
        done += 1;
        source_scope.end();
        stages[i] = try sealAndPark(a, &workers[i], inventory.workers[i], store, limits.recorder(i));
    }
    const stage_one_ns = timer.read();
    const stage_one = try MW.encode(a, inventory.execution, inventory.workers, stages);
    errdefer a.free(stage_one);
    var pending = try Manifest.verifyAndSeal(a, inventory.execution, inventory.workers, stages);
    defer pending.deinit(a);
    const stage_two_start = timer.read();
    const proofs = try a.alloc(B.Proof, workers.len);
    errdefer a.free(proofs);
    var completed: usize = 0;
    errdefer for (proofs[0..completed]) |*proof| proof.deinit(a);
    for (workers, 0..) |*worker, i| {
        var restore = try Stage.StageScope.begin(limits.recorder(i), "retained_main_restore", "Map and integrity-check sealed source payload");
        defer restore.end();
        _ = try store.restoreBound(&worker.scheme().trees.items[1], .{ .setup = inventory.workers[i].fixed_identity, .statement = inventory.workers[i].statement });
        restore.end();
        var stage_two = try Stage.StageScope.begin(limits.recorder(i), "stage_two_prove", "Manifest-bound native interaction and physical proof");
        defer stage_two.end();
        proofs[i] = try worker.complete(a, &pending, i);
        completed += 1;
        worker.deinit();
        retired += 1;
    }
    if (limits.timing) |timing| timing.* = .{ .stage_one_ns = stage_one_ns, .manifest_ns = stage_two_start - stage_one_ns, .stage_two_ns = timer.read() - stage_two_start };
    return .{ .stage_one = stage_one, .proofs = proofs };
}
