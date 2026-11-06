//! Per-class memory policy for the job runtime (spec §3.7; frontier-delta §4 item 3).
//!
//! The policy is GENERATED from a measured sweep (scripts/rv64_m8_plan_sweep.py:
//! every job class through a real DeviceWorker with STWO_RV64_M8_JOBS_PLAN_DIR)
//! and committed under vectors/reports/rv64-m8-20261106/memory-plan/. A worker
//! loads it at start (STWO_RV64_M8_JOBS_PLAN=<policy.json>); unset keeps today's
//! behavior exactly (declared footprints, env arena, unbounded persistent regions).
//!
//! What the policy fixes, per GPU and per class:
//!   * `gpu.arena_words`: the static two-sided arena. Sized so that every class
//!     pair that may be co-resident fits: job A working on one side next to job B's
//!     inputs staged on the other (peak_A + staged_B ≤ arena), Airbender-style.
//!   * `class.peak_words`: the class's measured arena peak (own staged inputs +
//!     channel state + slab + every Enqueue.alloc), margin included. It replaces
//!     the job's hand-declared `Footprint.device_words` for the fit check.
//!   * `class.staged_words`: measured staged inputs (what B occupies beside A).
//!   * `max_concurrent`: 2 when the class fits beside every class's staged inputs
//!     (overlap), 1 when the worker must serialize it (never fail it).
//!   * `gpu.persistent_budget_words`: one region pool for Stager.persistent with
//!     LRU eviction of regions no in-flight job references.
//!   * `gpu.allocator`: `.reuse` reclaims non-LIFO frees inside a job's window.
//!
//! Memory layout only: no transcript, kernel or proof field depends on it.
const std = @import("std");
const api = @import("api.zig");
const W = @import("worker.zig");

pub const schema = "rv64-m8-jobs-memory-policy/v1";
/// Policy file consumed at worker start.
pub const env_policy = "STWO_RV64_M8_JOBS_PLAN";
/// Measurement: every Worker.destroy writes its class plans into this directory.
pub const env_plan_dir = "STWO_RV64_M8_JOBS_PLAN_DIR";
/// Worker channel state (Channel.state_words = 32) occupies one granule.
pub const state_granule: usize = W.Arena.granule;

pub const Allocator = enum { lifo, reuse };

pub const Gpu = struct {
    /// Static arena per GPU (words, granule-aligned).
    arena_words: u64,
    /// Pool for class-persistent regions (0 = today's per-key allocations, never evicted).
    persistent_budget_words: u64 = 0,
    /// 2 = one job working + one staged everywhere; 1 = some pair serializes.
    max_concurrent_jobs: u32 = 2,
    /// Scheduler-visible pipeline depth (finishing + enqueued + staged).
    max_outstanding: u32 = 3,
    allocator: Allocator = .lifo,
    /// Device words the plan was sized against (GPU memory minus reserves), for the record.
    device_budget_words: u64 = 0,
    /// Pinned host words per pipeline slot (0 = keep the configured size). Covers
    /// every class's measured pinned use (Stager.pinned + uploads + slab mirror).
    pinned_slot_words: u64 = 0,
    /// Cap on request-scoped retained regions per GPU (jobs/retained.zig;
    /// 0 = accounted, uncapped). They live OUTSIDE the static arena (their
    /// own exec-context allocations), so arena_words + this is the planned
    /// device share of the job runtime across a request's barrier.
    retained_budget_words: u64 = 0,
};

pub const ClassPolicy = struct {
    label: []const u8 = "",
    /// 64 lowercase hex chars of Job.classKey().
    class_key: []const u8,
    peak_words: u64,
    staged_words: u64 = 0,
    slab_words: u64 = 0,
    pinned_words: u64 = 0,
    persistent_words: u64 = 0,
    max_concurrent: u32 = 2,
};

pub const Unplanned = enum {
    /// Unknown class: fall back to the job's declared footprint.
    declared,
    /// Unknown class: refuse (a complete policy for a production run).
    refuse,
};

pub const Document = struct {
    schema: []const u8,
    gpu: Gpu,
    classes: []const ClassPolicy = &.{},
    unplanned: Unplanned = .declared,
};

/// Arena words a job occupies when its footprint is all it states.
pub fn peakOf(fp: api.Footprint) usize {
    return fp.device_words + std.mem.alignForward(usize, fp.slab_words, W.Arena.granule) + state_granule;
}

/// Job A (peak `resident_peak`, own staged inputs included) works on one side
/// while job B's inputs (`next_staged`) sit at the other end.
pub fn pairFits(arena_words: usize, resident_peak: usize, next_staged: usize) bool {
    return resident_peak <= arena_words and next_staged <= arena_words - resident_peak;
}

pub const Resolved = struct {
    /// What the worker checks and allocates with: slab/pinned/staged from the job,
    /// device_words from the class plan when planned.
    footprint: api.Footprint,
    peak_words: usize,
    staged_words: usize,
    planned: bool,
};

/// Resolution without a policy (or for an unplanned class): the declared footprint.
pub fn declared(fp: api.Footprint) Resolved {
    return .{ .footprint = fp, .peak_words = peakOf(fp), .staged_words = std.mem.alignForward(usize, fp.staged_words, W.Arena.granule), .planned = false };
}

pub const Policy = struct {
    parsed: std.json.Parsed(Document),
    map: std.AutoHashMapUnmanaged([32]u8, usize) = .empty,
    a: std.mem.Allocator,
    gpu: Gpu,

    pub fn parse(a: std.mem.Allocator, bytes: []const u8) !*Policy {
        const parsed = try std.json.parseFromSlice(Document, a, bytes, .{ .ignore_unknown_fields = true, .allocate = .alloc_always });
        errdefer parsed.deinit();
        const self = try a.create(Policy);
        errdefer a.destroy(self);
        self.* = .{ .parsed = parsed, .a = a, .gpu = parsed.value.gpu };
        errdefer self.map.deinit(a);
        try self.validate();
        return self;
    }

    pub fn load(a: std.mem.Allocator, path: []const u8) !*Policy {
        const bytes = try std.fs.cwd().readFileAlloc(a, path, 16 << 20);
        defer a.free(bytes);
        return parse(a, bytes);
    }

    /// STWO_RV64_M8_JOBS_PLAN unset → null (today's behavior).
    pub fn fromEnv(a: std.mem.Allocator) !?*Policy {
        const path = std.posix.getenv(env_policy) orelse return null;
        if (path.len == 0) return null;
        return try load(a, path);
    }

    pub fn deinit(self: *Policy) void {
        self.map.deinit(self.a);
        self.parsed.deinit();
        self.a.destroy(self);
    }

    pub fn classes(self: *const Policy) []const ClassPolicy {
        return self.parsed.value.classes;
    }

    pub fn class(self: *const Policy, key: [32]u8) ?*const ClassPolicy {
        const i = self.map.get(key) orelse return null;
        return &self.parsed.value.classes[i];
    }

    pub fn unplanned(self: *const Policy) Unplanned {
        return self.parsed.value.unplanned;
    }

    /// The footprint the worker plans with. A planned class takes its measured
    /// peak; slab_words and pinned_words always come from the job (the worker
    /// allocates the slab from it), staged words take the larger of the two.
    pub fn resolve(self: *const Policy, key: [32]u8, fp: api.Footprint) Resolved {
        const c = self.class(key) orelse return declared(fp);
        const slab = std.mem.alignForward(usize, fp.slab_words, W.Arena.granule);
        const staged = @max(@as(usize, @intCast(c.staged_words)), std.mem.alignForward(usize, fp.staged_words, W.Arena.granule));
        // Never below the job's own slab + state + staged inputs, whatever was measured.
        const peak = @max(@as(usize, @intCast(c.peak_words)), slab + state_granule + staged);
        var out = fp;
        out.device_words = peak - slab - state_granule;
        return .{ .footprint = out, .peak_words = peak, .staged_words = staged, .planned = true };
    }

    fn validate(self: *Policy) !void {
        const doc = self.parsed.value;
        if (!std.mem.eql(u8, doc.schema, schema)) return error.MemoryPolicySchemaMismatch;
        const g = doc.gpu;
        const granule = W.Arena.granule;
        if (g.arena_words == 0 or g.arena_words % granule != 0) return error.MemoryPolicyInvalidArena;
        if (g.persistent_budget_words % granule != 0) return error.MemoryPolicyInvalidPersistentBudget;
        if (g.max_concurrent_jobs < 1 or g.max_concurrent_jobs > 2 or g.max_outstanding < 1 or g.max_outstanding > 3) return error.MemoryPolicyInvalidConcurrency;
        try self.map.ensureTotalCapacity(self.a, @intCast(doc.classes.len));
        for (doc.classes, 0..) |c, i| {
            if (c.class_key.len != 64) return error.MemoryPolicyInvalidClassKey;
            var key: [32]u8 = undefined;
            _ = std.fmt.hexToBytes(&key, c.class_key) catch return error.MemoryPolicyInvalidClassKey;
            if (self.map.contains(key)) return error.MemoryPolicyDuplicateClass;
            self.map.putAssumeCapacity(key, i);
            if (c.peak_words % granule != 0 or c.staged_words % granule != 0) return error.MemoryPolicyUnalignedClass;
            if (c.peak_words > g.arena_words) return error.MemoryPolicyClassExceedsArena;
            if (c.peak_words < c.staged_words + state_granule + std.mem.alignForward(u64, c.slab_words, granule)) return error.MemoryPolicyClassPeakBelowParts;
            if (c.max_concurrent < 1 or c.max_concurrent > 2) return error.MemoryPolicyInvalidConcurrency;
            if (g.persistent_budget_words != 0 and std.mem.alignForward(u64, c.persistent_words, granule) > g.persistent_budget_words) return error.MemoryPolicyClassExceedsPersistentBudget;
            if (g.pinned_slot_words != 0 and c.pinned_words > g.pinned_slot_words) return error.MemoryPolicyClassExceedsPinnedSlot;
        }
        // The generator's concurrency claims must hold in the arena arithmetic.
        for (doc.classes) |r| {
            var fits_all = true;
            for (doc.classes) |s| fits_all = fits_all and pairFits(@intCast(g.arena_words), @intCast(r.peak_words), @intCast(s.staged_words));
            if (r.max_concurrent == 2 and !fits_all) return error.MemoryPolicyConcurrencyClaimDoesNotFit;
        }
    }
};

/// Static layout check (Airbender static-arena pattern) for one co-resident
/// pair, driven through the worker's real `Arena`: job A staged on `side`,
/// job B staged on the other side, then A's whole work window allocated up to
/// its peak. Asserts both staged regions and A's window are in bounds and
/// pairwise disjoint. Returns error.PairDoesNotFit when the arena is too small.
pub fn checkPair(arena_words: usize, a_peak: usize, a_staged: usize, b_staged: usize, side: api.Placement) !void {
    const granule = W.Arena.granule;
    if (a_peak % granule != 0 or a_staged % granule != 0 or b_staged % granule != 0) return error.UnalignedPlan;
    if (a_staged + state_granule > a_peak) return error.PeakBelowStaged;
    var arena = W.Arena{ .base = 0, .words = arena_words };
    arena.beginStage(side);
    const a_in: ?usize = if (a_staged == 0) null else arena.stageAlloc(side, a_staged) catch return error.PairDoesNotFit;
    arena.beginStage(side.other());
    const b_in: ?usize = if (b_staged == 0) null else arena.stageAlloc(side.other(), b_staged) catch return error.PairDoesNotFit;
    arena.beginWork(side, b_staged != 0);
    const work = a_peak - a_staged;
    // A's window as two allocations (channel state + the rest), as the worker does.
    const state = arena.workAlloc(state_granule) catch return error.PairDoesNotFit;
    const rest: ?usize = if (work > state_granule) (arena.workAlloc(work - state_granule) catch return error.PairDoesNotFit) else null;
    if (arena.peak != a_peak) return error.ArenaPeakModelMismatch;
    const Range = struct { lo: usize, hi: usize };
    var ranges: [4]Range = undefined;
    var n: usize = 0;
    if (a_in) |x| ranges[n] = .{ .lo = x / 4, .hi = x / 4 + a_staged };
    if (a_in != null) n += 1;
    if (b_in) |x| ranges[n] = .{ .lo = x / 4, .hi = x / 4 + b_staged };
    if (b_in != null) n += 1;
    // The window is contiguous from the state allocation for either growth direction.
    const lo = if (side == .bottom) state / 4 else (if (rest) |r| r / 4 else state / 4);
    ranges[n] = .{ .lo = lo, .hi = lo + work };
    n += 1;
    for (ranges[0..n], 0..) |x, i| {
        if (x.hi > arena_words or x.lo > x.hi) return error.LayoutOutOfBounds;
        for (ranges[0..i]) |y| if (x.lo < y.hi and y.lo < x.hi) return error.LayoutOverlap;
    }
}

/// Every ordered class pair of a policy, both placements. Pairs the policy
/// marks as serialized (max_concurrent 1 for A) are checked to really not fit,
/// so a stale "serialize" claim is caught as well as a stale "fits" claim.
pub fn checkPolicyLayout(p: *const Policy) !usize {
    const arena: usize = @intCast(p.gpu.arena_words);
    var pairs: usize = 0;
    for (p.classes()) |x| {
        var fits_all = true;
        for (p.classes()) |y| {
            const fits = pairFits(arena, @intCast(x.peak_words), @intCast(y.staged_words));
            fits_all = fits_all and fits;
            for ([_]api.Placement{ .bottom, .top }) |side| {
                if (checkPair(arena, @intCast(x.peak_words), @intCast(x.staged_words), @intCast(y.staged_words), side)) |_| {
                    if (!fits) return error.LayoutModelDisagreesWithPairFits;
                } else |err| switch (err) {
                    error.PairDoesNotFit => if (fits) return error.LayoutModelDisagreesWithPairFits,
                    else => return err,
                }
                pairs += 1;
            }
            // A alone (nothing staged beside it) must always fit.
            try checkPair(arena, @intCast(x.peak_words), @intCast(x.staged_words), 0, .bottom);
        }
        if ((x.max_concurrent == 2) != fits_all) return error.PolicyConcurrencyStale;
    }
    return pairs;
}

test {
    _ = @import("plan_test.zig");
}
