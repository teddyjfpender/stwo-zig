//! Canonical two-phase coordinator. Sources seal independently, the complete
//! inventory is joined, then workers complete under one immutable manifest.
const std = @import("std");
const A = @import("stwo_riscv_frontend").rv64_air;
const Profile = @import("stwo_prover_api").stage_profile;
const G = @import("../protocol.zig");
const P = @import("protocol.zig");
const R = @import("roster.zig");
const Statement = @import("statement.zig");
const W = @import("worker.zig");
const Schedule = @import("schedule.zig");
const Options = @import("profiling.zig").Options;
const Native = @import("../../word16_execution/prepared.zig").Prepared;
const Core = @import("../../word16_execution/sources.zig");
const Memory = @import("../../word16_execution/memory/prepared.zig").Prepared;
const Advice = @import("collector.zig").Advice;
const Cell = A.memory.closed_ram.types.Cell;
const Stage1 = struct {
    allocator: std.mem.Allocator,
    setups: []const *const R.CpuSetup,
    truths: []const R.Truth,
    native: []const *Native,
    advice: *const Advice,
    expected: P.Expected,
    options: Options,
    requests: []const P.Request,
    first_steps: []const u64,
    workers: []?W.Worker,
    specs: [][32]u8,
    roots: []G.Receipt,
    fn execute(self: *Stage1, ordinal: usize) !void {
        const a = self.allocator;
        var stage = try Profile.StageScope.begin(self.options.recorder(ordinal), "source_construction", "Owned native worker witness construction");
        defer stage.end();
        const descriptor: W.Descriptor = if (ordinal < self.setups.len)
            .{ .cpu = .{ .setup = self.setups[ordinal], .request = self.requests[ordinal], .ordinal = ordinal, .first_step = self.first_steps[ordinal], .first_ids = try P.firstIds(self.requests, ordinal) } }
        else
            .{ .truth = .{ .value = self.truths[ordinal - self.setups.len], .ordinal = ordinal - self.setups.len } };
        var source = switch (descriptor) {
            .cpu => |cpu| W.Source{ .cpu = try self.cpuSource(cpu, self.options.recorder(ordinal)) },
            .truth => |truth| W.Source{ .truth = try R.TruthSource.init(a, truth.value, self.advice) },
        };
        var owns_source = true;
        errdefer if (owns_source) switch (source) {
            inline else => |*s| s.deinit(),
        };
        stage.end();
        var worker = try W.Worker.init(a, descriptor, source);
        owns_source = false;
        errdefer worker.deinit(a);
        const root = try worker.seal(a, self.expected, self.options, ordinal);
        self.specs[ordinal] = worker.spec;
        self.roots[ordinal] = root;
        self.workers[ordinal] = worker;
    }
    fn cpuSource(self: *Stage1, cpu: W.Cpu, recorder: ?*Profile.Recorder) !R.Sources {
        const a = self.allocator;
        const request = cpu.request;
        const g = cpu.setup.materials.geometry;
        const initial = try a.dupe(Cell, request.base.memory.initial);
        const terminal = a.dupe(Cell, request.base.memory.terminal) catch |err| {
            a.free(initial);
            return err;
        };
        const memory = try Memory.initOwnedForGlobalRamLadderIndependent(a, self.advice.events[cpu.ordinal], initial, terminal, request.base.epoch, g.ls_log, g.ls_tail_log, g.initialLog(), g.terminalLog());
        if (self.options.consume_memory_events) {
            a.free(self.advice.events[cpu.ordinal]);
            self.advice.events[cpu.ordinal] = &.{};
        }
        var base = try Core.Source.fromPreparedWithOwnedMemoryProfiled(a, &cpu.setup.materials, self.native[cpu.ordinal], memory, recorder);
        errdefer base.deinit();
        var k: ?A.crypto.keccak.word16_bridge.source.Source = null;
        errdefer if (k) |*s| s.deinit();
        var add: ?A.crypto.secp256k1.word16_bridge.source.Source = null;
        errdefer if (add) |*s| s.deinit();
        var double: ?A.crypto.secp256k1.word16_bridge.source.Source = null;
        errdefer if (double) |*s| s.deinit();
        var sha256: ?A.crypto.secp256k1.word16_bridge.source.Source = null;
        errdefer if (sha256) |*s| s.deinit();
        if (cpu.setup.bridges.keccak) |log| k = try A.crypto.keccak.word16_bridge.source.Source.init(a, self.advice.keccak[cpu.ordinal], cpu.first_ids[0], log);
        if (cpu.setup.bridges.add) |log| add = try A.crypto.secp256k1.word16_bridge.source.Source.init(a, .add, self.advice.secp[cpu.ordinal][0], cpu.first_ids[1], log);
        if (cpu.setup.bridges.double) |log| double = try A.crypto.secp256k1.word16_bridge.source.Source.init(a, .double, self.advice.secp[cpu.ordinal][1], cpu.first_ids[2], log);
        if (cpu.setup.bridges.sha256) |log| sha256 = try A.crypto.secp256k1.word16_bridge.source.Source.init(a, .sha256, self.advice.sha256[cpu.ordinal], cpu.first_ids[3], log);
        var arith: ?A.crypto.secp256k1.word16_bridge.source.Source = null;
        errdefer if (arith) |*s| s.deinit();
        if (cpu.setup.bridges.arith256_mod) |log| arith = try A.crypto.secp256k1.word16_bridge.source.Source.init(a, .arith256_mod, self.advice.arith256_mod[cpu.ordinal], cpu.first_ids[4], log);
        var curves: [@import("types.zig").CURVES]?A.crypto.secp256k1.word16_bridge.source.Source = @splat(null);
        errdefer for (&curves) |*c| if (c.*) |*s| s.deinit();
        for (&curves, @import("types.zig").FIRST_CURVE..) |*out, fam| if (cpu.setup.bridges.at(@enumFromInt(fam))) |log| {
            out.* = try A.crypto.secp256k1.word16_bridge.source.Source.init(a, @import("types.zig").bridgeKind(@enumFromInt(fam)), self.advice.curves[cpu.ordinal][fam - @import("types.zig").FIRST_CURVE], cpu.first_ids[fam], log);
        };
        var bulk: [@import("types.zig").bulk_kinds.len]?A.crypto.bulk_memory.source.Source = @splat(null);
        errdefer for (&bulk) |*b| if (b.*) |*s| s.deinit();
        for (@import("types.zig").bulk_kinds, &bulk) |kind, *out| if (cpu.setup.bridges.bulk.at(kind)) |log| {
            const shard = self.advice.bulk[cpu.ordinal];
            out.* = try A.crypto.bulk_memory.source.Source.init(a, kind, shard.calls, shard.words, log);
        };
        // Keccak sponge: one shared plan (calls, words, permutation states) and
        // the call/perm sources built from it.
        var plan: ?*A.crypto.keccak_sponge.source.Plan = null;
        errdefer if (plan) |p| {
            p.deinit(a);
            a.destroy(p);
        };
        var sponge: [2]?A.crypto.keccak_sponge.source.Source = @splat(null);
        errdefer for (&sponge) |*b| if (b.*) |*s| s.deinit();
        if (cpu.setup.bridges.sponge.any()) {
            const shard = self.advice.sponge[cpu.ordinal];
            const p = try a.create(A.crypto.keccak_sponge.source.Plan);
            errdefer a.destroy(p);
            p.* = try A.crypto.keccak_sponge.source.Plan.init(a, shard.calls, shard.words);
            plan = p;
            for (@import("types.zig").sponge_kinds, &sponge) |kind, *out| if (cpu.setup.bridges.sponge.at(kind)) |log| {
                out.* = try A.crypto.keccak_sponge.source.Source.init(a, kind, p, request.sponge.first_id, log);
            };
        }
        var source = R.Sources{ .core = base, .keccak = k, .add = add, .double = double, .sha256 = sha256, .arith256_mod = arith, .curves = curves, .bulk = bulk, .sponge_plan = plan, .sponge = sponge };
        // Locals own all fields until this final fallible operation succeeds.
        try source.mergeRanges();
        return source;
    }
};
const Stage2 = struct {
    allocator: std.mem.Allocator,
    workers: []?W.Worker,
    manifest: *const G.Manifest,
    options: Options,
    results: []?W.Result,
    fn execute(self: *Stage2, ordinal: usize) !void {
        const worker = if (self.workers[ordinal]) |*w| w else return error.MissingSealedServiceWorker;
        self.results[ordinal] = try worker.complete(self.allocator, self.manifest, self.options, ordinal);
    }
};
pub fn produce(a: std.mem.Allocator, setups: []const *const R.CpuSetup, truths: []const R.Truth, native: []const *Native, advice: *const Advice, expected: P.Expected, options: Options) !Statement.Bundle {
    try options.validate(setups.len + truths.len);
    if (options.consume_memory_events and !A.memory.ownership.same(a, advice.allocator)) return error.IncompatibleServiceAdviceAllocator;
    if (setups.len != native.len or setups.len != advice.events.len or setups.len != advice.keccak.len or setups.len != advice.secp.len or setups.len != advice.sha256.len or setups.len != advice.arith256_mod.len or setups.len != advice.curves.len or setups.len != advice.bulk.len or setups.len != advice.sponge.len) return error.InvalidCombinedInventory;
    const requests = try a.alloc(P.Request, setups.len);
    defer a.free(requests);
    const first_steps = try a.alloc(u64, setups.len);
    defer a.free(first_steps);
    var step: u64 = 0;
    for (native, requests, first_steps, 0..) |n, *r, *first, i| {
        const cpu = n.cpu orelse return error.PreparedExecutionConsumed;
        first.* = step;
        step = try std.math.add(u64, step, cpu.public.steps);
        var calls: [@import("types.zig").FAMILIES]u32 = undefined;
        calls[0..5].* = .{ @intCast(advice.keccak[i].len), @intCast(advice.secp[i][0].len), @intCast(advice.secp[i][1].len), @intCast(advice.sha256[i].len), @intCast(advice.arith256_mod[i].len) };
        for (calls[5..], advice.curves[i]) |*c, list| c.* = @intCast(list.len);
        r.* = .{ .sponge = advice.sponge[i].counts(), .bulk = advice.bulk[i].counts(), .calls = calls, .base = .{ .cpu = cpu.public, .epoch = cpu.epoch, .division_requests = @intCast(n.division.len), .multiplication_requests = @intCast(n.multiplication.len), .memory = .{ .initial = if (i == 0) advice.initial else &.{}, .terminal = if (i + 1 == setups.len) advice.terminal else &.{}, .epoch = cpu.epoch, .ls_count = @intCast(advice.events[i].len) } } };
    }
    // Sponge permutation IDs follow every Keccak-f call of the bundle.
    var next_sponge: u64 = 1;
    for (advice.keccak) |calls| next_sponge += calls.len;
    for (requests) |*r| if (r.sponge.any()) {
        r.sponge.first_id = std.math.cast(u32, next_sponge) orelse return error.CombinedLookupMassExceeded;
        next_sponge += r.sponge.perms;
    };
    _ = try P.admit(a, setups, truths, requests, expected);
    const count = setups.len + truths.len;
    const workers = try a.alloc(?W.Worker, count);
    defer a.free(workers);
    @memset(workers, null);
    defer for (workers) |*slot| if (slot.*) |*worker| worker.deinit(a);
    const specs = try a.alloc([32]u8, count);
    defer a.free(specs);
    const roots = try a.alloc(G.Receipt, count);
    defer a.free(roots);
    var stage1 = Stage1{ .allocator = a, .setups = setups, .truths = truths, .native = native, .advice = advice, .expected = expected, .options = options, .requests = requests, .first_steps = first_steps, .workers = workers, .specs = specs, .roots = roots };
    const estimates = try memoryEstimates(a, setups, truths, options.schedule.memory_cap_bytes != 0);
    defer a.free(estimates);
    const traces = try a.alloc(Schedule.Trace, if (options.directory != null) 2 * count else 0);
    defer a.free(traces);
    @memset(traces, .{});
    const run_options = struct {
        fn of(e: []const u64, t: []Schedule.Trace, phase: usize, n: usize) Schedule.RunOptions {
            return .{ .estimates = e, .trace = if (t.len == 0) &.{} else t[phase * n .. (phase + 1) * n] };
        }
    }.of;
    try Schedule.runWithOptions(Stage1, a, &stage1, count, options.schedule, run_options(estimates, traces, 0, count), Stage1.execute);
    // The only manifest/challenge barrier. No stage2 task exists before join.
    for (workers) |worker| if (worker == null) return error.MissingSealedServiceWorker;
    var manifest = try G.Manifest.init(a, specs, roots);
    errdefer manifest.deinit();
    const results = try a.alloc(?W.Result, count);
    defer a.free(results);
    @memset(results, null);
    defer for (results) |*slot| if (slot.*) |*result| result.deinit(a);
    var stage2 = Stage2{ .allocator = a, .workers = workers, .manifest = &manifest, .options = options, .results = results };
    try Schedule.runWithOptions(Stage2, a, &stage2, count, options.schedule, run_options(estimates, traces, 1, count), Stage2.execute);
    if (options.directory) |dir| try writeTrace(a, dir, options.schedule, traces, count);
    for (results) |result| if (result == null) return error.MissingCompletedServiceWorker;
    const cpus = try a.alloc(Statement.CpuEncoded, setups.len);
    errdefer a.free(cpus);
    const encoded_truths = try a.alloc(Statement.TruthEncoded, truths.len);
    for (cpus, results[0..setups.len]) |*out, result| out.* = result.?.cpu;
    for (encoded_truths, results[setups.len..]) |*out, result| out.* = result.?.truth;
    @memset(results, null); // atomic ownership publication, no fallible work remains.
    return .{ .manifest = manifest, .cpus = cpus, .truths = encoded_truths };
}

/// Declared-geometry estimate of one proof's transient trace bytes: every
/// committed column's base cells (M31, 4 bytes) twice, for coefficients plus
/// one evaluation pass. A coarse admission heuristic only, never authority.
pub fn memoryEstimate(a: std.mem.Allocator, setup: anytype) !u64 {
    var cells: u64 = 0;
    for (0..3) |tree| {
        const logs = try setup.logs(a, tree);
        defer a.free(logs);
        for (logs) |log| {
            if (log > 30) return error.InvalidCostGeometry;
            cells = try std.math.add(u64, cells, @as(u64, 1) << @intCast(log));
        }
    }
    return std.math.mul(u64, cells, 8);
}
fn memoryEstimates(a: std.mem.Allocator, setups: []const *const R.CpuSetup, truths: []const R.Truth, enabled: bool) ![]u64 {
    if (!enabled) return a.alloc(u64, 0);
    const out = try a.alloc(u64, setups.len + truths.len);
    errdefer a.free(out);
    for (setups, out[0..setups.len]) |setup, *e| e.* = try memoryEstimate(a, setup);
    for (truths, out[setups.len..]) |*truth, *e| e.* = try memoryEstimate(a, truth);
    return out;
}
fn writeTrace(a: std.mem.Allocator, dir: std.fs.Dir, policy: Schedule.Policy, traces: []const Schedule.Trace, count: usize) !void {
    const bytes = try std.json.Stringify.valueAlloc(a, .{ .schema = 1, .scope = "operational lane trace only; ns are relative to each phase start; estimates are declared-geometry heuristics", .policy = policy, .stage1 = traces[0..count], .stage2 = traces[count .. 2 * count] }, .{ .whitespace = .indent_2 });
    defer a.free(bytes);
    try @import("../../rv64_ethereum_batch_receipt.zig").writeExclusive(dir, "schedule.json", bytes);
}
