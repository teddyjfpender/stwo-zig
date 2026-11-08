//! M8 request feeder (STWO_RV64_M8_JOBS=1): one request, every proof a job.
//!
//! The feeder composes the two hybrids under one request:
//!   - native hybrid (rv64/native_hybrid.zig): per CPU segment a Stage1Job at
//!     the local-GKR seam and a Stage2Job at the coordinator stage-two seam;
//!   - outer hybrid (rv64/outer_job_factory.zig): every recursion
//!     leaf/fold/root an OuterNodeJob;
//! and (once its seam lands) TruthJob for truth/service proofs. The legacy
//! resident orchestration stays the request driver: admission, capture,
//! the global-chi seal, the recursion DAG and publication are frozen there
//! (the scheduler-driven request DAG, `request.Provider`, is the next pass).
//!
//! What this file owns (jobs-clean, no legacy imports; the sync lint scans it):
//!   Selection  STWO_RV64_M8_JOBS=1 implies every hybrid; an explicit "0" on a
//!              part flag under JOBS=1 is a contradiction and fails closed.
//!   Ledger     the publication gate: every job a request runs is registered,
//!              accepted only from its finish-time checks (slab status words,
//!              binding authority, composition status, truth closure), and
//!              `seal` refuses publication while any job is pending or rejected.
//!   Feeder     per-process state: selection, the ledger, request counters and
//!              the per-request receipt (m8-feeder.json, diagnostics only).
const std = @import("std");
const S = @import("scheduler.zig");

pub const Env = *const fn ([]const u8) ?[]const u8;

fn posixEnv(name: []const u8) ?[]const u8 {
    return std.posix.getenv(name);
}

/// Tri-state flag: unset, "0" or "1"; anything else fails closed.
fn flag(env: Env, name: []const u8) !?bool {
    const v = env(name) orelse return null;
    if (std.mem.eql(u8, v, "1")) return true;
    if (std.mem.eql(u8, v, "0")) return false;
    return error.InvalidM8JobsSelection;
}

pub const Selection = struct {
    /// STWO_RV64_M8_JOBS=1: the whole request runs as jobs.
    feeder: bool = false,
    /// Native segments as Stage1/Stage2 jobs (STWO_RV64_M8_NATIVE_JOBS).
    native: bool = false,
    /// Recursion nodes as OuterNodeJobs (STWO_RV64_M8_OUTER_JOBS).
    outer: bool = false,

    /// JOBS=1 forces native and outer on (a part flag may repeat "1", never
    /// "0"); JOBS unset/"0" leaves each part flag as given.
    pub fn from(env: Env) !Selection {
        const jobs = try flag(env, "STWO_RV64_M8_JOBS") orelse false;
        const native = try flag(env, "STWO_RV64_M8_NATIVE_JOBS");
        const outer = try flag(env, "STWO_RV64_M8_OUTER_JOBS");
        if (jobs) {
            if (native == false or outer == false) return error.InvalidM8JobsSelection;
            return .{ .feeder = true, .native = true, .outer = true };
        }
        return .{ .native = native orelse false, .outer = outer orelse false };
    }
    pub fn fromProcess() !Selection {
        return from(posixEnv);
    }
};

/// Job kinds the ledger tracks (scheduler kinds plus the hybrid seams).
pub const Kind = enum { native_stage1, native_stage2, truth, outer_node, outer_fixed };

pub const State = enum { pending, accepted, rejected };

/// Per-request publication gate. Thread-safe: hybrid seams run on the
/// coordinator's worker threads and on recursion lane threads.
pub const Ledger = struct {
    pub const Key = struct { kind: Kind, index: u32 };
    pub const Entry = struct { state: State = .pending, reason: ?anyerror = null };
    a: std.mem.Allocator,
    mutex: std.Thread.Mutex = .{},
    entries: std.AutoArrayHashMapUnmanaged(Key, Entry) = .empty,
    sealed: bool = false,

    pub fn init(a: std.mem.Allocator) Ledger {
        return .{ .a = a };
    }
    pub fn deinit(self: *Ledger) void {
        self.entries.deinit(self.a);
    }
    /// Start of a request: forget the previous request's jobs.
    pub fn reset(self: *Ledger) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.entries.clearRetainingCapacity();
        self.sealed = false;
    }
    /// A job is about to run. Registering twice is an error (a stale entry
    /// from an aborted attempt must be accepted or rejected, never replaced).
    pub fn expect(self: *Ledger, kind: Kind, index: u32) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.sealed) return error.M8LedgerSealed;
        const got = try self.entries.getOrPut(self.a, .{ .kind = kind, .index = index });
        if (got.found_existing) return error.M8LedgerDuplicateJob;
        got.value_ptr.* = .{};
    }
    fn settle(self: *Ledger, kind: Kind, index: u32, state: State, reason: ?anyerror) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.sealed) return error.M8LedgerSealed;
        const e = self.entries.getPtr(.{ .kind = kind, .index = index }) orelse return error.M8LedgerUnknownJob;
        if (e.state != .pending) return error.M8LedgerAlreadySettled;
        e.* = .{ .state = state, .reason = reason };
    }
    /// Finish-time acceptance: every status word must be zero and every
    /// host check must have passed (`checks` is the first failing check's
    /// error, or null). Returns the rejection error after recording it, so
    /// the caller propagates it and the request fails before publication.
    pub fn acceptStatus(self: *Ledger, kind: Kind, index: u32, status_words: []const u32, checks: ?anyerror) !void {
        const reason: ?anyerror = checks orelse for (status_words) |w| {
            if (w != 0) break error.M8JobStatusRejected;
        } else null;
        if (reason) |err| {
            try self.settle(kind, index, .rejected, err);
            return err;
        }
        try self.settle(kind, index, .accepted, null);
    }
    /// A job that failed before its checks (device error, abort).
    pub fn fail(self: *Ledger, kind: Kind, index: u32, err: anyerror) void {
        self.settle(kind, index, .rejected, err) catch {};
    }
    pub const Summary = struct { jobs: usize = 0, accepted: usize = 0, rejected: usize = 0, pending: usize = 0, first_rejection: ?[]const u8 = null };
    pub fn summary(self: *Ledger) Summary {
        self.mutex.lock();
        defer self.mutex.unlock();
        var s = Summary{ .jobs = self.entries.count() };
        for (self.entries.values()) |e| switch (e.state) {
            .accepted => s.accepted += 1,
            .pending => s.pending += 1,
            .rejected => {
                s.rejected += 1;
                if (s.first_rejection == null) s.first_rejection = @errorName(e.reason orelse error.M8JobStatusRejected);
            },
        };
        return s;
    }
    /// The publication gate: all registered jobs accepted. After a
    /// successful seal the ledger is frozen until `reset`.
    pub fn seal(self: *Ledger) !Summary {
        const s = self.summary();
        if (s.rejected != 0) return error.M8JobRejectedBeforePublication;
        if (s.pending != 0) return error.M8JobUnacceptedBeforePublication;
        self.mutex.lock();
        defer self.mutex.unlock();
        self.sealed = true;
        return s;
    }
};

/// Process-wide feeder state (one per service).
pub const Feeder = struct {
    a: std.mem.Allocator,
    selection: Selection,
    ledger: Ledger,
    requests: u64 = 0,
    /// Wall clock of the current request (begin → publish).
    timer: ?std.time.Timer = null,

    pub fn create(a: std.mem.Allocator, selection: Selection) !*Feeder {
        if (!selection.feeder) return error.M8FeederNotSelected;
        const self = try a.create(Feeder);
        self.* = .{ .a = a, .selection = selection, .ledger = Ledger.init(a) };
        std.debug.print("GPU_M8_FEEDER boot native={} outer={}\n", .{ selection.native, selection.outer });
        return self;
    }
    pub fn destroy(self: *Feeder) void {
        self.ledger.deinit();
        self.a.destroy(self);
    }
    pub fn beginRequest(self: *Feeder) void {
        self.ledger.reset();
        self.requests += 1;
        self.timer = std.time.Timer.start() catch null;
    }
    /// Gate + receipt: seal the ledger (refusing publication on any pending
    /// or rejected job), then `publish` (the caller's publication step),
    /// then the receipt into `out_dir` (null: no receipt).
    pub fn publish(self: *Feeder, out_dir: ?[]const u8, ctx: anytype, comptime publishFn: anytype) !void {
        const s = self.ledger.seal() catch |err| {
            const r = self.ledger.summary();
            std.debug.print("GPU_M8_FEEDER refuse request={} error={s} jobs={} accepted={} rejected={} pending={} first_rejection={s}\n", .{ self.requests, @errorName(err), r.jobs, r.accepted, r.rejected, r.pending, r.first_rejection orelse "-" });
            return err;
        };
        try publishFn(ctx);
        const wall: u64 = if (self.timer) |*t| t.read() else 0;
        std.debug.print("GPU_M8_FEEDER publish request={} jobs={} accepted={} wall_ns={}\n", .{ self.requests, s.jobs, s.accepted, wall });
        if (out_dir) |dir| try self.writeReceipt(dir, s, wall);
    }
    fn writeReceipt(self: *Feeder, dir: []const u8, s: Ledger.Summary, wall: u64) !void {
        var text: std.Io.Writer.Allocating = .init(self.a);
        defer text.deinit();
        try std.json.Stringify.value(.{ .schema = "rv64-m8-feeder-request/v1", .request = self.requests, .selection = self.selection, .ledger = s, .wall_ns = wall }, .{ .whitespace = .indent_1 }, &text.writer);
        var d = try std.fs.cwd().openDir(dir, .{});
        defer d.close();
        try d.writeFile(.{ .sub_path = "m8-feeder.json", .data = text.written() });
    }
};

// Keep the scheduler kinds and the ledger kinds in step for the DAG pass.
comptime {
    _ = S.Kind;
}

// ---------------------------------------------------------------- tests

const testing = std.testing;

fn envOf(comptime pairs: anytype) Env {
    return struct {
        fn get(name: []const u8) ?[]const u8 {
            inline for (pairs) |p| if (std.mem.eql(u8, name, p[0])) return p[1];
            return null;
        }
    }.get;
}

test "selection: JOBS=1 implies every hybrid; contradictions fail closed" {
    try testing.expectEqual(Selection{}, try Selection.from(envOf(.{})));
    try testing.expectEqual(Selection{ .feeder = true, .native = true, .outer = true }, try Selection.from(envOf(.{.{ "STWO_RV64_M8_JOBS", "1" }})));
    try testing.expectEqual(Selection{ .feeder = true, .native = true, .outer = true }, try Selection.from(envOf(.{ .{ "STWO_RV64_M8_JOBS", "1" }, .{ "STWO_RV64_M8_NATIVE_JOBS", "1" } })));
    try testing.expectEqual(Selection{ .native = true }, try Selection.from(envOf(.{ .{ "STWO_RV64_M8_JOBS", "0" }, .{ "STWO_RV64_M8_NATIVE_JOBS", "1" } })));
    try testing.expectEqual(Selection{ .outer = true }, try Selection.from(envOf(.{.{ "STWO_RV64_M8_OUTER_JOBS", "1" }})));
    try testing.expectError(error.InvalidM8JobsSelection, Selection.from(envOf(.{ .{ "STWO_RV64_M8_JOBS", "1" }, .{ "STWO_RV64_M8_OUTER_JOBS", "0" } })));
    try testing.expectError(error.InvalidM8JobsSelection, Selection.from(envOf(.{.{ "STWO_RV64_M8_JOBS", "yes" }})));
    try testing.expectError(error.InvalidM8JobsSelection, Selection.from(envOf(.{.{ "STWO_RV64_M8_NATIVE_JOBS", "" }})));
}

test "ledger: all accepted seals; duplicates and unknown jobs refused" {
    var l = Ledger.init(testing.allocator);
    defer l.deinit();
    try l.expect(.native_stage1, 0);
    try l.expect(.native_stage2, 0);
    try l.expect(.outer_node, 7);
    try testing.expectError(error.M8LedgerDuplicateJob, l.expect(.native_stage1, 0));
    try testing.expectError(error.M8LedgerUnknownJob, l.acceptStatus(.truth, 3, &.{0}, null));
    try l.acceptStatus(.native_stage1, 0, &.{ 0, 0 }, null);
    try l.acceptStatus(.native_stage2, 0, &.{0}, null);
    try testing.expectError(error.M8LedgerAlreadySettled, l.acceptStatus(.native_stage1, 0, &.{0}, null));
    // One job still pending: publication refused.
    try testing.expectError(error.M8JobUnacceptedBeforePublication, l.seal());
    try l.acceptStatus(.outer_node, 7, &.{}, null);
    const s = try l.seal();
    try testing.expectEqual(@as(usize, 3), s.accepted);
    try testing.expectError(error.M8LedgerSealed, l.expect(.truth, 0));
    l.reset();
    try l.expect(.truth, 0);
}

const Publication = struct {
    published: bool = false,
    fn run(self: *Publication) !void {
        self.published = true;
    }
};

test "negative: a corrupted status word or failed check rejects the request; nothing is published" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const f = try Feeder.create(testing.allocator, .{ .feeder = true, .native = true, .outer = true });
    defer f.destroy();
    // Corrupted composition status word in a Stage2 slab.
    f.beginRequest();
    try f.ledger.expect(.native_stage2, 1);
    try testing.expectError(error.M8JobStatusRejected, f.ledger.acceptStatus(.native_stage2, 1, &.{ 0, 0x1, 0 }, null));
    var p = Publication{};
    try testing.expectError(error.M8JobRejectedBeforePublication, f.publish(null, &p, Publication.run));
    try testing.expect(!p.published);
    // Corrupted claim: a host check (binding authority / truth closure) failed.
    f.beginRequest();
    try f.ledger.expect(.truth, 0);
    try testing.expectError(error.NativeBindingRejected, f.ledger.acceptStatus(.truth, 0, &.{0}, error.NativeBindingRejected));
    try testing.expectError(error.M8JobRejectedBeforePublication, f.publish(null, &p, Publication.run));
    try testing.expect(!p.published);
    // A job that died before its checks.
    f.beginRequest();
    try f.ledger.expect(.outer_node, 2);
    f.ledger.fail(.outer_node, 2, error.CudaEnqueueFailed);
    try testing.expectError(error.M8JobRejectedBeforePublication, f.publish(null, &p, Publication.run));
    try testing.expect(!p.published);
    // A job that never reported.
    f.beginRequest();
    try f.ledger.expect(.native_stage1, 4);
    try testing.expectError(error.M8JobUnacceptedBeforePublication, f.publish(null, &p, Publication.run));
    try testing.expect(!p.published);
    // Clean request publishes and writes the receipt.
    f.beginRequest();
    try f.ledger.expect(.native_stage1, 4);
    try f.ledger.acceptStatus(.native_stage1, 4, &.{0}, null);
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try tmp.dir.realpathAlloc(arena.allocator(), ".");
    try f.publish(dir, &p, Publication.run);
    try testing.expect(p.published);
    const receipt = try tmp.dir.readFileAlloc(arena.allocator(), "m8-feeder.json", 1 << 16);
    try testing.expect(std.mem.indexOf(u8, receipt, "\"accepted\": 1") != null);
}

test "ledger is safe across threads" {
    var l = Ledger.init(testing.allocator);
    defer l.deinit();
    const T = struct {
        fn run(ledger: *Ledger, base: u32) void {
            for (0..64) |i| {
                const idx: u32 = base + @as(u32, @intCast(i));
                ledger.expect(.outer_node, idx) catch unreachable;
                ledger.acceptStatus(.outer_node, idx, &.{0}, null) catch unreachable;
            }
        }
    };
    var threads: [4]std.Thread = undefined;
    for (&threads, 0..) |*t, i| t.* = try std.Thread.spawn(.{}, T.run, .{ &l, @as(u32, @intCast(i)) * 1000 });
    for (threads) |t| t.join();
    try testing.expectEqual(@as(usize, 256), (try l.seal()).accepted);
}
