//! Physical runtime endpoint. Reserve/retry on a HOST caller, never wait inside
//! a GPU owner callback. The permit crosses submit, bounds allocations before
//! mutation, and reconciles actual global retained bytes after joined cleanup.
const std = @import("std");
const A = @import("global_admission.zig");
const N = @import("pcs_native_abi.zig");
pub const Snapshot = extern struct {
    version: u32 = 1,
    device: u32 = 0,
    capacity: u64 = 0,
    chunk: u64 = 0,
    small_slab: u64 = 0,
    live_large: u64 = 0,
    live_small: u64 = 0,
    largest_virtual_free: u64 = 0,
    free_device: u64 = 0,
    total_device: u64 = 0,
    pub fn footprint(self: Snapshot) A.Footprint {
        return .{ .large = self.live_large, .small = self.live_small };
    }
    pub fn validate(self: Snapshot, endpoint: Endpoint) !void {
        if (self.version != 1 or self.device != endpoint.physical or self.capacity != endpoint.planner.preset.arenaBytes() or self.chunk != A.chunk_bytes or self.small_slab != A.small_slab_bytes) return error.StaticArenaPresetMismatch;
        if (self.free_device > self.total_device) return error.InvalidArenaSnapshot;
        const device_used = self.total_device - self.free_device;
        const held = try activeBudgetGuard(self.device, self.total_device);
        const used = try subtractBudgetGuard(device_used, self.total_device, held);
        if (used > self.capacity and used - self.capacity > A.external_budget) return error.ExternalGpuBudgetExceeded;
    }
};
/// External canary allocation belongs to another, supervised process. It
/// limits physical availability; it never changes this process's arena budget.
fn subtractBudgetGuard(used: u64, total: u64, held: u64) !u64 {
    if (held == 0) return used;
    if (total <= A.physical_limit or held < total - A.physical_limit or held - (total - A.physical_limit) >= A.chunk_bytes or held > used) return error.InvalidBudgetGuardReservation;
    return used - held;
}
fn activeBudgetGuard(device: u32, total: u64) !u64 {
    var name_buffer: [96]u8 = undefined;
    const name = try std.fmt.bufPrintZ(&name_buffer, "STWO_RV64_BUDGET_GUARD_BYTES_{}", .{device});
    const bytes_env = std.posix.getenv(name);
    const pid_env = std.posix.getenv("STWO_RV64_BUDGET_GUARD_PID");
    if (bytes_env == null and pid_env == null) return 0;
    const text = bytes_env orelse return error.MissingBudgetGuardDevice;
    const held = std.fmt.parseInt(u64, text, 10) catch return error.InvalidBudgetGuardReservation;
    if (held == 0 or total <= A.physical_limit or held < total - A.physical_limit or held - (total - A.physical_limit) >= A.chunk_bytes) return error.InvalidBudgetGuardReservation;
    const pid = std.fmt.parseInt(u32, pid_env orelse return error.MissingBudgetGuardPid, 10) catch return error.InvalidBudgetGuardPid;
    if (pid <= 1) return error.InvalidBudgetGuardPid;
    if (comptime @import("builtin").os.tag != .linux) return error.BudgetGuardObservationUnavailable;
    var path_buffer: [96]u8 = undefined;
    const stat_path = try std.fmt.bufPrint(&path_buffer, "/proc/{}/stat", .{pid});
    const stat = std.fs.openFileAbsolute(stat_path, .{}) catch return error.BudgetGuardNotAlive;
    defer stat.close();
    var stat_buffer: [4096]u8 = undefined;
    const n = try stat.readAll(&stat_buffer);
    const close = std.mem.lastIndexOfScalar(u8, stat_buffer[0..n], ')') orelse return error.InvalidBudgetGuardPid;
    if (close + 2 >= n or stat_buffer[close + 2] == 'Z' or stat_buffer[close + 2] == 'X' or stat_buffer[close + 2] == 'x') return error.BudgetGuardNotAlive;
    const cmd_path = try std.fmt.bufPrint(&path_buffer, "/proc/{}/cmdline", .{pid});
    const cmd = std.fs.openFileAbsolute(cmd_path, .{}) catch return error.BudgetGuardNotAlive;
    defer cmd.close();
    var cmd_buffer: [4096]u8 = undefined;
    const cn = try cmd.readAll(&cmd_buffer);
    const end = std.mem.indexOfScalar(u8, cmd_buffer[0..cn], 0) orelse return error.InvalidBudgetGuardPid;
    const executable = cmd_buffer[0..end];
    if (!std.mem.eql(u8, std.fs.path.basename(executable), "gpu-budget-guard")) return error.InvalidBudgetGuardPid;
    // The harness independently pins the guard binary/readyJSON and watches
    // its liveness for the entire proof. These envs are measurement controls,
    // never fields supplied by a proof or a guest request.
    return held;
}

test "external physical canary subtraction preserves the complete prover budget" {
    const total: u64 = 33679736832;
    const held: u64 = 5681184768;
    try std.testing.expectEqual(@as(u64, 27998552064), try subtractBudgetGuard(total, total, held));
    try std.testing.expectEqual(@as(u64, 27000000000), try subtractBudgetGuard(27000000000 + held, total, held));
    try std.testing.expectError(error.InvalidBudgetGuardReservation, subtractBudgetGuard(held - 1, total, held));
    try std.testing.expectError(error.InvalidBudgetGuardReservation, subtractBudgetGuard(total, total, held - 2097152));
    try std.testing.expectEqual(@as(u64, 123), try subtractBudgetGuard(123, total, 0));
}
comptime {
    if (@sizeOf(Snapshot) != 72) @compileError("arena snapshot ABI");
}
pub const Api = struct {
    snapshot: *const fn (*anyopaque, *Snapshot) callconv(.c) c_int,
    identity: *const fn (*anyopaque, *u64) callconv(.c) c_int,
    configure: *const fn (*anyopaque, u64) callconv(.c) c_int,
    begin: *const fn (*anyopaque, u64, u64, u64, u64, u64, [*:0]const u8) callconv(.c) c_int,
    end: *const fn (*anyopaque, u64, *Snapshot) callconv(.c) c_int,
    pub fn load(lib: *std.DynLib) !Api {
        var api: Api = undefined;
        inline for (std.meta.fields(Api)) |field| {
            const name = comptime if (std.mem.eql(u8, field.name, "identity")) "stwo_exec_context_identity" else "stwo_exec_context_" ++ (if (std.mem.eql(u8, field.name, "snapshot")) "arena_snapshot" else "admission_" ++ field.name) ++ "_v1";
            @field(api, field.name) = lib.lookup(field.type, name) orelse return error.MissingGlobalAdmissionRuntime;
        }
        return api;
    }
};
pub const Endpoint = struct {
    planner: *A.Planner,
    physical: u32,
    api: Api,
    session: *anyopaque,
    submit: N.Submit,
    owner_context: ?*anyopaque = null,
    owner_identity: u64 = 0,
    const Query = struct {
        endpoint: *const Endpoint,
        configure: bool = false,
        result: Snapshot = .{},
        failed: bool = false,
        owner_context: ?*anyopaque = null,
        owner_identity: u64 = 0,
        fn run(raw: *anyopaque, _: u64, user: ?*anyopaque) callconv(.c) c_int {
            const self: *@This() = @ptrCast(@alignCast(user orelse return 1));
            self.owner_context = raw;
            if (self.endpoint.api.identity(raw, &self.owner_identity) != 0 or self.owner_identity == 0) {
                self.failed = true;
                return 1;
            }
            if (self.configure and self.endpoint.api.configure(raw, self.endpoint.planner.preset.arenaBytes()) != 0) {
                self.failed = true;
                return 1;
            }
            if (self.endpoint.api.snapshot(raw, &self.result) != 0) {
                self.failed = true;
                return 1;
            }
            return 0;
        }
    };
    pub fn init(planner: *A.Planner, physical: u32, lib: *std.DynLib, session: *anyopaque, submit: N.Submit) !Endpoint {
        return .{ .planner = planner, .physical = physical, .api = try Api.load(lib), .session = session, .submit = submit };
    }
    pub fn configure(self: *Endpoint) !void {
        if (!self.planner.healthy(self.physical)) return error.PhysicalAdmissionPoisoned;
        const gate = try self.planner.stageGate(self.physical);
        gate.lock();
        defer {
            gate.unlock();
            self.planner.notifyResourceRelease();
        }
        var query = Query{ .endpoint = self, .configure = true };
        if (self.submit(self.session, Query.run, &query) != 0 or query.failed) return error.GlobalAdmissionConfigureFailed;
        try query.result.validate(self.*);
        try self.planner.observeIdle(self.physical, query.result.footprint());
        try self.planner.markConfigured(self.physical);
        self.owner_context = query.owner_context;
        self.owner_identity = query.owner_identity;
    }
    pub fn enabled(self: *const Endpoint) bool {
        return self.planner.schedulingEnabled();
    }
    pub const Attempt = union(enum) { admitted: Permit, blocked: A.Decision };
    pub fn tryReserve(self: *const Endpoint, demand: A.Demand) !Attempt {
        if (!demand.known or (self.planner.host_policy == .require_bounds and !demand.host_known)) return .{ .blocked = .{ .reason = .unknown_cost, .capacity = self.planner.capacity() } };
        if (!self.planner.healthy(self.physical)) return error.PhysicalAdmissionPoisoned;
        if (demand.retained_new.large != 0 or demand.retained_new.small != 0) return error.RuntimeUsesObservedRetention;
        const gate = try self.planner.stageGate(self.physical);
        if (!gate.tryLock()) return .{ .blocked = .{ .reason = .wide_stage_busy, .capacity = self.planner.capacity() } };
        errdefer gate.unlock();
        var query = Query{ .endpoint = self };
        if (self.submit(self.session, Query.run, &query) != 0 or query.failed) return error.GlobalAdmissionSnapshotFailed;
        try query.result.validate(self.*);
        try self.planner.observeIdle(self.physical, query.result.footprint());
        self.planner.observeHostRss(try currentRss());
        const timer = try std.time.Timer.start();
        const decision = try self.planner.tryBegin(self.physical, demand);
        if (decision.token) |token| return .{ .admitted = .{ .endpoint = self.*, .token = token, .demand = demand, .before = query.result, .timer = timer } };
        gate.unlock();
        return .{ .blocked = decision };
    }
    /// Host coordinator only, BEFORE taking any stage, owner or cache mutex.
    /// Every retained owner must reserve its downstream progress envelope;
    /// callers cannot wait on capacity that only their own blocked stage frees.
    pub fn reserve(self: *const Endpoint, demand: A.Demand) !Permit {
        return self.reserveWithPolicy(demand, null);
    }
    /// Peers may be host-transcripting between eligible GPU stages. Allow
    /// their progress; refuse only after 30 seconds with no ledger change.
    pub fn reserveDrain(self: *const Endpoint, demand: A.Demand) !Permit {
        return self.reserveDrainWithin(demand, 30 * std.time.ns_per_s);
    }
    fn reserveDrainWithin(self: *const Endpoint, demand: A.Demand, timeout_ns: u64) !Permit {
        return self.reserveWithPolicy(demand, timeout_ns);
    }
    fn reserveWithPolicy(self: *const Endpoint, demand: A.Demand, drain_timeout_ns: ?u64) !Permit {
        while (true) {
            const epoch = self.planner.epoch();
            switch (try self.tryReserve(demand)) {
                .admitted => |permit| return permit,
                .blocked => |decision| switch (decision.reason) {
                    .wide_stage_busy => self.planner.waitForChange(epoch),
                    .capacity_pressure => {
                        if (drain_timeout_ns) |timeout| {
                            if (!try self.planner.waitForChangeWithin(epoch, timeout)) return error.NativePostGlobalDrainUnavailable;
                        } else self.planner.waitForChange(epoch);
                    },
                    .unknown_cost => return error.GlobalGpuAllocationCostUnavailable,
                    .host_capacity_pressure => return error.GlobalHostAdmissionCapacity,
                    .request_exceeds_static_arena => return error.GlobalGpuClassExceedsStaticArena,
                    .runtime_poisoned => return error.PhysicalAdmissionPoisoned,
                    .admitted => unreachable,
                },
            }
        }
    }
};
pub const Permit = struct {
    endpoint: Endpoint,
    token: A.Token,
    demand: A.Demand,
    before: Snapshot,
    after: ?Snapshot = null,
    entered: bool = false,
    closed: bool = false,
    timer: std.time.Timer,
    enter_ns: u64 = 0,
    leave_ns: u64 = 0,
    /// Owner-thread entry, immediately before any allocation/kernel mutation.
    pub fn enterOwner(self: *Permit, raw: *anyopaque) !void {
        // A permit belongs to the exact session owner discovered at configure,
        // not merely another context with an equal live-byte baseline.
        if (self.entered or self.closed) return error.AdmissionOwnerAlreadyEntered;
        if (self.endpoint.owner_context == null or raw != self.endpoint.owner_context.?) return error.ForeignAdmissionOwner;
        var identity: u64 = 0;
        if (self.endpoint.api.identity(raw, &identity) != 0 or identity != self.endpoint.owner_identity or identity == 0) return error.ForeignAdmissionOwner;
        var preflight: Snapshot = .{};
        if (self.endpoint.api.snapshot(raw, &preflight) != 0) return error.GlobalAdmissionSnapshotFailed;
        try preflight.validate(self.endpoint);
        var label_buf: [192]u8 = undefined;
        const label = try std.fmt.bufPrintZ(&label_buf, "m7/{s}/{s}/r{}/o{}/t{}", .{ @tagName(self.demand.owner.domain), @tagName(self.demand.stage), self.demand.owner.request, self.demand.owner.ordinal, self.token.id });
        if (self.endpoint.api.begin(raw, self.token.id, self.before.live_large, self.before.live_small, self.demand.temporary.large, self.demand.temporary.small, label) != 0) return error.GlobalAdmissionOwnerBeginFailed;
        self.entered = true;
        self.endpoint.planner.commitEntered(self.token) catch |err| {
            self.endpoint.planner.poisonPhysical(self.endpoint.physical);
            return err;
        };
        self.enter_ns = self.timer.read();
    }
    /// Every transient release and lane join must precede this call.
    pub fn leaveOwner(self: *Permit, raw: *anyopaque) !void {
        if (!self.entered or self.after != null) return error.AdmissionOwnerNotActive;
        var snapshot: Snapshot = .{};
        if (self.endpoint.api.end(raw, self.token.id, &snapshot) != 0) {
            self.endpoint.planner.poisonPhysical(self.endpoint.physical);
            return error.GlobalAdmissionOwnerEndFailed;
        }
        self.after = snapshot;
        self.leave_ns = self.timer.read();
    }
    /// Host caller closes after submit returns. No unlock on an unresolved owner
    /// failure: that physical planner stays blocked/terminal until teardown.
    pub fn finish(self: *Permit, successor: A.Footprint) !void {
        if (self.closed) return error.StaleAdmissionToken;
        errdefer self.endpoint.planner.poisonPhysical(self.endpoint.physical);
        const after = if (self.entered) self.after orelse return error.AdmissionOwnerNotFinished else self.before;
        try after.validate(self.endpoint);
        if (self.entered) {
            try self.endpoint.planner.completeObserved(self.token, after.footprint(), successor);
        } else try self.endpoint.planner.cancelUnentered(self.token);
        self.closed = true;
        (try self.endpoint.planner.stageGate(self.endpoint.physical)).unlock();
        // Wake only after the physical gate is actually acquirable. Otherwise
        // a waiter can observe the new epoch, miss the still-held gate, and
        // sleep forever with no subsequent release notification.
        self.endpoint.planner.notifyResourceRelease();
        std.debug.print("GLOBAL_ADMISSION_STAGE physical={} ticket={} domain={s} stage={s} ordinal={} owner_queue_ns={} owner_callback_ns={} total_host_ns={} retained_large={} retained_small={} successor_large={} successor_small={}\n", .{ self.endpoint.physical, self.token.id, @tagName(self.demand.owner.domain), @tagName(self.demand.stage), self.demand.owner.ordinal, self.enter_ns, self.leave_ns - self.enter_ns, self.timer.read(), after.live_large, after.live_small, if (self.entered) successor.large else 0, if (self.entered) successor.small else 0 });
    }
};

fn currentRss() !u64 {
    if (@import("builtin").os.tag != .linux) return error.HostRssMeasurementUnavailable;
    const file = try std.fs.openFileAbsolute("/proc/self/statm", .{});
    defer file.close();
    var buf: [256]u8 = undefined;
    const n = try file.read(&buf);
    var words = std.mem.tokenizeAny(u8, buf[0..n], " \n\t");
    _ = words.next() orelse return error.InvalidHostRss;
    const pages = try std.fmt.parseInt(u64, words.next() orelse return error.InvalidHostRss, 10);
    return try std.math.mul(u64, pages, std.heap.pageSize());
}

test "runtime permit observes global retention and refuses untracked growth" {
    const M = struct {
        var live: A.Footprint = .{};
        var physical: u32 = 0;
        var begin_calls: usize = 0;
        var owner_identity: u64 = 41;
        fn state() Snapshot {
            return .{ .version = 1, .device = physical, .capacity = 22 << 30, .chunk = A.chunk_bytes, .small_slab = A.small_slab_bytes, .live_large = live.large, .live_small = live.small, .largest_virtual_free = 64 << 30, .free_device = 8 << 30, .total_device = 32 << 30 };
        }
        fn snapshot(_: *anyopaque, out: *Snapshot) callconv(.c) c_int {
            out.* = state();
            return 0;
        }
        fn identity(_: *anyopaque, out: *u64) callconv(.c) c_int {
            out.* = owner_identity;
            return 0;
        }
        fn configure(_: *anyopaque, _: u64) callconv(.c) c_int {
            return 0;
        }
        fn begin(_: *anyopaque, _: u64, _: u64, _: u64, _: u64, _: u64, _: [*:0]const u8) callconv(.c) c_int {
            begin_calls += 1;
            return 0;
        }
        fn end(_: *anyopaque, _: u64, out: *Snapshot) callconv(.c) c_int {
            out.* = state();
            return 0;
        }
        fn submit(raw: *anyopaque, callback: N.Callback, user: ?*anyopaque) callconv(.c) c_int {
            return callback(raw, 0, user);
        }
    };
    M.live = .{};
    M.physical = 0;
    M.begin_calls = 0;
    M.owner_identity = 41;
    var planner = try A.Planner.init(std.testing.allocator, &.{0}, .g22);
    defer planner.deinit();
    const raw: *anyopaque = @ptrFromInt(16);
    var endpoint = Endpoint{ .planner = &planner, .physical = 0, .api = .{ .snapshot = M.snapshot, .identity = M.identity, .configure = M.configure, .begin = M.begin, .end = M.end }, .session = raw, .submit = M.submit };
    try endpoint.configure();
    try std.testing.expect(!endpoint.enabled());
    inline for (std.meta.fields(A.Coverage)) |field| try planner.registerCoverage(0, @enumFromInt(field.value));
    try std.testing.expect(endpoint.enabled());
    const demand = A.Demand{ .owner = .{ .request = 1, .domain = .native_packet, .ordinal = 0 }, .stage = .witness, .known = true, .host_known = true, .temporary = try A.Footprint.allocation(4 << 20) };
    var permit = (try endpoint.tryReserve(demand)).admitted;
    try std.testing.expectError(error.ForeignAdmissionOwner, permit.enterOwner(@ptrFromInt(32)));
    M.physical = 1;
    try std.testing.expectError(error.StaticArenaPresetMismatch, permit.enterOwner(raw));
    try std.testing.expectEqual(@as(usize, 0), M.begin_calls);
    M.physical = 0;
    M.owner_identity = 42;
    try std.testing.expectError(error.ForeignAdmissionOwner, permit.enterOwner(raw));
    try std.testing.expectEqual(@as(usize, 0), M.begin_calls);
    M.owner_identity = 41;
    try permit.enterOwner(raw);
    try std.testing.expectError(error.AdmissionOwnerAlreadyEntered, permit.enterOwner(raw));
    M.live = try A.Footprint.allocation(4 << 20);
    try permit.leaveOwner(raw);
    try permit.finish(.{});
    try std.testing.expectEqual(A.chunk_bytes, (try planner.snapshot(0)).retained.large);
    M.live.large += A.chunk_bytes;
    try std.testing.expectError(error.UntrackedDeviceAllocation, endpoint.tryReserve(demand));
    M.live = .{};
    var cancel = (try endpoint.tryReserve(demand)).admitted;
    try cancel.finish(.{});
    const keep = try A.Footprint.allocation(2 << 30);
    const future = try A.Footprint.allocation(19 << 30);
    const truth = (try planner.tryBegin(0, .{ .owner = demand.owner, .stage = .witness, .known = true, .host_known = true, .temporary = keep, .stage_retained_upper = keep, .successor = future })).token.?;
    try planner.completeObserved(truth, keep, future);
    M.live = keep;
    var blocked_drain = demand;
    blocked_drain.temporary = try A.Footprint.allocation(5 << 30);
    blocked_drain.stage_retained_upper = blocked_drain.temporary;
    try std.testing.expectError(error.NativePostGlobalDrainUnavailable, endpoint.reserveDrainWithin(blocked_drain, 0));
    // A refusal did not enter the owner or steal the physical stage gate.
    const gate = try planner.stageGate(0);
    try std.testing.expect(gate.tryLock());
    gate.unlock();
    try planner.release(truth);
    M.live = .{};
}
