//! A local CPU0 Source+MAIN admission ticket, before global inventory exists.
//! The early-main orchestrator defers EVERY other request GPU stage until this
//! helper joins. It must not reuse this gate for concurrent per-segment launch.
const std = @import("std");
const CPU = @import("stwo_riscv_cpu_integration");
const Early = CPU.rv64_ethereum_gkr_main.EarlyCPU;
const Stage = CPU.rv64_device_source_stage;
const PcsConfig = @import("stwo_core").pcs.ForField(CPU.rv64_device_pcs.O).PcsConfig;
const Service = @import("pcs_native.zig");
const Trace = @import("trace_commit.zig");
const Projection = @import("cpu_projection.zig");
const Cost = @import("native_source_cost.zig");
const Adapter = @import("native_source_cost_adapter.zig");
const Capacity = @import("native_stage1_capacity.zig");
const Runtime = @import("admission_runtime.zig");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
pub const Context = struct {
    service: *Service.Context,
    trace: *Trace.Context,
    projection: *Projection.Context,
    physical: u32,
    mutex: std.Thread.Mutex = .{},
    claim: ?*Claim = null,
    poisoned: bool = false,
    pub fn stage(self: *Context) Early.MemoryAdmission {
        return .{ .context = self, .reserve = reserve };
    }
    pub fn deinit(self: *Context) void {
        // The orchestrator releases only after the actual worker/PCS owner has
        // destroyed its retained MAIN coefficients, including abort paths.
        std.debug.assert(self.claim == null);
    }
    fn snapshot(self: *Context) !Runtime.Snapshot {
        const query_fn = self.service.library.lookup(*const fn (*anyopaque, *Runtime.Snapshot) callconv(.c) c_int, "stwo_exec_context_arena_snapshot_v1") orelse return error.MissingEarlyStageSnapshot;
        const Query = struct {
            query: *const fn (*anyopaque, *Runtime.Snapshot) callconv(.c) c_int,
            result: Runtime.Snapshot = .{},
            fn run(raw: *anyopaque, _: u64, data: ?*anyopaque) callconv(.c) c_int {
                const q: *@This() = @ptrCast(@alignCast(data orelse return 1));
                return q.query(raw, &q.result);
            }
        };
        var q = Query{ .query = query_fn };
        if (self.service.submit(self.service.session, Query.run, &q) != 0) return error.EarlyStageSnapshotFailed;
        return q.result;
    }
    fn reserve(raw: *anyopaque, a: std.mem.Allocator, request: Stage.Request, config: PcsConfig, budget: *Budget) !Early.Ticket {
        const self: *Context = @ptrCast(@alignCast(raw));
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.poisoned or self.claim != null) return error.EarlyStageAdmissionBusy;
        if (request.ordinal != 0 or request.scope.ordinal != 0 or !self.trace.freeze_allocation_plan or self.service.admission != null or self.trace.service != self.service or self.projection.service != self.service or self.projection.pending != null or self.projection.prestage_error != null) return error.EarlyStageAdmissionUnavailable;
        const compact = if (std.posix.getenv("STWO_RV64_CPU_COMPACT_INGRESS")) |v| !std.mem.eql(u8, v, "0") else false;
        if (compact and self.projection.unpack == null) return error.MissingCpuUnpackKernel;
        const tc = self.trace.allocationOptions(config.fri_config.log_blowup_factor);
        const plan = try Adapter.init(a, request, .{ .compact_ingress = compact, .retain_ledgers = self.projection.retain_ledgers, .cold_rom = true, .commit = .{ .beta = tc.beta, .separate_coefficients = tc.separate_coefficients, .stream_budget = tc.stream_budget, .exact_prefix_banks = tc.exact_prefix_banks } });
        const before = try self.snapshot();
        const envelope = try Capacity.assess(before, self.physical, self.service.byte_cap, &plan);
        var stack_charge = try budget.reserveExternal(try std.math.mul(usize, plan.extra_pack_threads, @import("cpu_witness.zig").pack_stack_bytes));
        errdefer stack_charge.deinit();
        const claim = try a.create(Claim);
        errdefer a.destroy(claim);
        claim.* = .{ .allocator = a, .owner = self, .plan = plan, .before = before, .envelope = envelope, .pack_stacks = stack_charge.take() };
        errdefer claim.pack_stacks.deinit();
        try self.service.early_allocations.begin(&claim.plan, @import("pcs_scope.zig").identity(request.scope));
        self.claim = claim;
        std.debug.print("GPU_EARLY_MAIN_ADMISSION event=reserve physical={} plan={x} required_large={} required_small={} capacity_large={} capacity_small={} whole_process_peak_qualified=false host_cost_known=false\n", .{ self.physical, plan.identity, envelope.required.large, envelope.required.small, envelope.capacity.large, envelope.capacity.small });
        return .{ .context = claim, .finish_joined = Claim.finishJoined, .release_destroyed = Claim.releaseDestroyed };
    }
};
const Claim = struct {
    allocator: std.mem.Allocator,
    owner: *Context,
    plan: Cost.Plan,
    before: Runtime.Snapshot,
    envelope: Capacity.Envelope,
    pack_stacks: Budget.ExternalReservation,
    joined: bool = false,
    fn finishJoined(raw: *anyopaque) !void {
        const self: *Claim = @ptrCast(@alignCast(raw));
        self.owner.mutex.lock();
        defer self.owner.mutex.unlock();
        if (self.owner.claim != self or self.joined) return error.StaleEarlyStageTicket;
        errdefer self.owner.poisoned = true;
        const after = try self.owner.snapshot();
        try Capacity.checkJoined(self.before, after, self.envelope);
        try self.owner.service.early_allocations.finish(&self.plan);
        self.pack_stacks.deinit();
        self.joined = true;
        std.debug.print("GPU_EARLY_MAIN_ADMISSION event=joined physical={} plan={x} live_large={} live_small={}\n", .{ self.owner.physical, self.plan.identity, after.live_large, after.live_small });
    }
    fn releaseDestroyed(raw: *anyopaque) void {
        const self: *Claim = @ptrCast(@alignCast(raw));
        const owner = self.owner;
        owner.mutex.lock();
        std.debug.assert(owner.claim == self);
        owner.claim = null;
        owner.service.early_allocations.cancelDestroyed(&self.plan);
        owner.mutex.unlock();
        self.pack_stacks.deinit();
        const a = self.allocator;
        a.destroy(self);
    }
};
