//! Metadata closure for already ROOT-AUTHENTICATED OM31 services leaf frames.
//! This is not an accepting execution verifier. Calling check() on arbitrary
//! JSON/words proves nothing: the outer root must authenticate every frame's
//! digest, admitted topology/profile and exactly-once ordered leaf coverage.
//! No STARK or numerical GKR verification is repeated here.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const O = core.fields.om31.OM31;
const R = @import("../../word16_global_execution/services/roster.zig");
const P = @import("../../word16_global_execution/services/protocol.zig");
const W = @import("../../word16_global_execution/services/gkr_local/worker_protocol.zig");
const Execution = @import("../../word16_global_execution/services/gkr_local/execution.zig");
const M = @import("../../word16_global_execution/services/gkr_local/manifest.zig");
const MW = @import("../../word16_global_execution/services/gkr_local/manifest_wire.zig");
const Receipt = @import("../../word16_global_execution/services/gkr_local/receipt.zig");
const Components = @import("../../word16_global_execution/services/gkr_local/cpu_components.zig");
const Boundary = @import("../../word16_global_execution/services/gkr_local/expected_boundary.zig");
const FixedSet = @import("../../word16_global_execution/services/gkr_local/fixed_authority_set.zig").Set;
const Cpu = @import("cpu_leaf.zig");
const Truth = @import("truth_leaf.zig");
const Keccak = @import("keccak_leaf.zig");
pub const CpuFrame = struct {
    words: []const u32,
    physical_claims: []const O,
    /// The SAME terminal marginals whose canonical receipt digest is computed
    /// inside this CPU leaf. They are authenticated by matching that receipt,
    /// never accepted because the producer supplies them in a sidecar.
    terminal_marginals: []const []const O,
};
pub const Frames = struct { cpus: []const CpuFrame, truths: []const []const u32 };
pub const Limits = struct { max_workers: usize = 256, max_public_words: usize = 1 << 20, max_marginal_values: usize = 32768 };
pub const Metadata = struct { manifest: M.Commitment, workers: usize };
fn admitSize(setups: []const *const R.CpuSetup, truths: []const R.Truth, frames: Frames, limits: Limits) !void {
    const workers = try std.math.add(usize, setups.len, truths.len);
    if (workers == 0 or workers > limits.max_workers or frames.cpus.len != setups.len or frames.truths.len != truths.len) return error.ServicesRootRoster;
    var words: usize = 0;
    var marginals: usize = 0;
    for (frames.cpus) |cpu| {
        if (cpu.terminal_marginals.len > Receipt.MAX_INSTANCES) return error.ServicesRootSidecarLimit;
        words = try std.math.add(usize, words, cpu.words.len);
        for (cpu.terminal_marginals) |pair| marginals = try std.math.add(usize, marginals, pair.len);
    }
    for (frames.truths) |truth| words = try std.math.add(usize, words, truth.len);
    if (words > limits.max_public_words or marginals > limits.max_marginal_values) return error.ServicesRootSidecarLimit;
}
/// Canonical receipt hashing is sufficient HERE only because the outer root
/// authenticates a CPU leaf that checked the numerical transcript and hashed
/// these exact reconstructed terminal marginals inside its public frame.
pub fn commitment(a: std.mem.Allocator, inventory: *const Execution.Inventory, stages: []const M.StageOne, cpus: []const CpuFrame) !M.Commitment {
    try M.validateStageOneShape(inventory.workers, stages);
    if (cpus.len != inventory.instances.len) return error.ServicesRootRoster;
    const entries = try a.alloc(M.CommitmentView, inventory.workers.len);
    defer a.free(entries);
    for (inventory.workers, stages, entries, 0..) |worker, stage, *entry, i| {
        const scope = Receipt.Scope{ .ordinal = worker.ordinal, .statement = worker.statement, .fixed = worker.fixed, .main = stage.main };
        var local: ?M.LocalCommitmentView = null;
        if (stage.local) |child| {
            if (i >= cpus.len) return error.ServicesRootRoster;
            const marginals = cpus[i].terminal_marginals;
            const instances = worker.local_instances orelse return error.ServicesRootRoster;
            const digest = try Receipt.digest(scope, instances, child.proof, marginals);
            if (!std.mem.eql(u8, &digest, &child.receipt_digest)) return error.ServicesRootReceiptMismatch;
            local = .{ .digest = digest, .claims_to_verify_by_instance = marginals };
        }
        // m5 chi-chain fields (canon-native hook): receiver-derived, carried unchanged.
        entry.* = .{ .kind = worker.kind, .global_relations = worker.global_relations, .mass = worker.mass, .scope = scope, .local = local, .chain = worker.chain };
    }
    return M.commitViews(inventory.execution_identity, entries);
}
fn checkCpuFrames(a: std.mem.Allocator, setups: []const *const R.CpuSetup, requests: []const P.Request, inventory: *const Execution.Inventory, stages: []const M.StageOne, manifest: M.Commitment, frames: []const CpuFrame, out: []M.Claims, threads: usize) !void {
    if (threads <= 1 or setups.len <= 1) {
        for (setups, requests, frames, 0..) |setup, request, frame, i| out[i] = try checkCpuFrame(a, setup, request, inventory.first_ids[i], inventory.workers[i], stages[i], manifest, frame);
        return;
    }
    const Job = struct {
        a: std.mem.Allocator,
        setups: []const *const R.CpuSetup,
        requests: []const P.Request,
        inventory: *const Execution.Inventory,
        stages: []const M.StageOne,
        manifest: M.Commitment,
        frames: []const CpuFrame,
        out: []M.Claims,
        errors: []?anyerror,
        next: std.atomic.Value(usize) = .init(0),
        pool: ?*engine.work_pool.WorkPool,
        fn work(job: *@This()) void {
            var binding: ?engine.work_pool.ScopedPoolBinding = if (job.pool) |p| (engine.work_pool.ScopedPoolBinding.initIfNeeded(p) catch null) else null;
            defer if (binding) |*b| b.deinit();
            job.loop();
        }
        fn loop(job: *@This()) void {
            while (true) {
                const i = job.next.fetchAdd(1, .monotonic);
                if (i >= job.setups.len) return;
                job.out[i] = checkCpuFrame(job.a, job.setups[i], job.requests[i], job.inventory.first_ids[i], job.inventory.workers[i], job.stages[i], job.manifest, job.frames[i]) catch |err| {
                    job.errors[i] = err;
                    continue;
                };
            }
        }
    };
    const errors = try a.alloc(?anyerror, setups.len);
    defer a.free(errors);
    @memset(errors, null);
    var job = Job{ .a = a, .setups = setups, .requests = requests, .inventory = inventory, .stages = stages, .manifest = manifest, .frames = frames, .out = out, .errors = errors, .pool = engine.work_pool.currentScopedPool() };
    var spawned: [16]std.Thread = undefined;
    var count: usize = 0;
    while (count + 1 < @min(threads, setups.len) and count < spawned.len) : (count += 1) {
        spawned[count] = std.Thread.spawn(.{ .stack_size = 64 << 20 }, Job.work, .{&job}) catch break;
    }
    job.loop();
    for (spawned[0..count]) |t| t.join();
    // The serial loop's refusal: the first failing CPU frame in index order.
    for (errors) |err| if (err) |e| return e;
}
pub fn checkCpuFrame(a: std.mem.Allocator, setup: *const R.CpuSetup, request: P.Request, first: anytype, expected: M.ExpectedWorker, stage: M.StageOne, manifest: M.Commitment, frame: CpuFrame) !M.Claims {
    const local = stage.local orelse return error.ServicesRootReceiptMismatch;
    var plan = try Components.Plan.init(a, setup);
    defer plan.deinit();
    if (frame.physical_claims.len != plan.claim_count) return error.InvalidWideCpuClaims;
    for (frame.physical_claims) |claim| for (claim.toM31Array()) |coordinate| if (coordinate.v >= core.fields.m31.Modulus) return error.NoncanonicalWideCpuClaim;
    const expected_words = try Cpu.expectedWords(a, setup, request, first, expected, manifest.digest, stage.main, local.receipt_digest, frame.physical_claims);
    defer a.free(expected_words);
    if (!std.mem.eql(u32, expected_words, frame.words)) return error.ServicesRootCpuFrameMismatch;
    // The complete authorized cell lists remain root-side native authority;
    // hashing megabytes of boundary cells into a circuit is unnecessary.
    for (plan.slots) |slot| if (slot.origin == .core and (slot.origin.core == .initial or slot.origin.core == .terminal)) {
        const initial = slot.origin.core == .initial;
        const expected_claim = try Boundary.claim(if (initial) request.base.memory.initial else request.base.memory.terminal, initial, manifest.shared.ram);
        if (!frame.physical_claims[slot.claim_offset].eql(expected_claim)) return error.WideCpuPublicRamMismatch;
    };
    return Components.Set.aggregate(&plan, frame.physical_claims);
}
/// Does independent inventory/input/output/adjacency admission, exact canonical
/// manifest reconstruction, CPU frame and public RAM checks, truth frame checks
/// and separate RAM/KIO/Wire closure. Requires external authenticated frames.
pub fn check(a: std.mem.Allocator, setups: []const *const R.CpuSetup, truths: []const R.Truth, requests: []const P.Request, expected: P.Expected, config: W.PcsConfig, fixed: ?*const FixedSet, stage_one_bytes: []const u8, frames: Frames, limits: Limits) !Metadata {
    try admitSize(setups, truths, frames, limits);
    var inventory = try Execution.Inventory.initWithAuthority(a, setups, truths, requests, expected, config, fixed);
    defer inventory.deinit();
    var stages = try MW.decode(a, inventory.execution_identity, inventory.workers, stage_one_bytes);
    defer stages.deinit();
    return checkPrepared(a, setups, truths, requests, &inventory, stages.stages, frames, limits, 1);
}
/// `check` after its first two steps (hook, M6 fold-v3 root-only receiver):
/// the caller passes the Inventory and stage-one decode it ALREADY built with
/// exactly `check`'s arguments (Inventory.initWithAuthority(setups, truths,
/// requests, expected, config, fixed); MW.decode(execution_identity, workers,
/// stage_one_bytes)), so admission is not computed twice. `threads > 1`
/// checks the CPU frames concurrently (independent, read-only inputs); the
/// result and every refusal are those of the serial loop.
pub fn checkPrepared(a: std.mem.Allocator, setups: []const *const R.CpuSetup, truths: []const R.Truth, requests: []const P.Request, inventory: *const Execution.Inventory, stages_in: []const M.StageOne, frames: Frames, limits: Limits, threads: usize) !Metadata {
    try admitSize(setups, truths, frames, limits);
    if (requests.len != setups.len or inventory.workers.len != setups.len + truths.len or stages_in.len != inventory.workers.len) return error.ServicesRootRoster;
    const stages = struct {
        stages: []const M.StageOne,
    }{ .stages = stages_in };
    const manifest = try commitment(a, inventory, stages.stages, frames.cpus);
    const claims = try a.alloc(M.Claims, inventory.workers.len);
    defer a.free(claims);
    try checkCpuFrames(a, setups, requests, inventory, stages.stages, manifest, frames.cpus, claims[0..setups.len], threads);
    for (truths, frames.truths, 0..) |truth, words, i| {
        const ordinal = setups.len + i;
        claims[ordinal] = switch (truth) {
            .keccak => try Keccak.checkStatement(words, truth, inventory.workers[ordinal], manifest.digest, stages.stages[ordinal].main),
            .secp => return error.ServicesRootUnsupportedLegacySecp,
            else => .{ .ram = O.zero(), .kio = O.zero(), .wire = try Truth.checkStatement(words, truth, inventory.workers[ordinal], manifest.digest, stages.stages[ordinal].main) },
        };
    }
    try M.checkClaimsClosure(inventory.workers, claims);
    return .{ .manifest = manifest, .workers = inventory.workers.len };
}
