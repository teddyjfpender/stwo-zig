//! Early Source+MAIN ownership. Legacy CPU0 uses a local GPU capacity ticket;
//! globally admitted segments use their Source/TC permits and charge only host
//! helper stacks here. A joined segment releases its active slot, while its
//! retained ticket remains owned until the worker/PCS owner is destroyed.
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
    retained_global_claims: usize = 0,
    poisoned: bool = false,
    pub fn stage(self: *Context) Early.MemoryAdmission {
        return .{ .context = self, .reserve = reserve };
    }
    pub fn deinit(self: *Context) void {
        // The orchestrator releases only after the actual worker/PCS owner has
        // destroyed its retained MAIN coefficients, including abort paths.
        std.debug.assert(self.claim == null and self.retained_global_claims == 0);
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
        const global = self.service.admission != null;
        if ((!global and (request.ordinal != 0 or request.scope.ordinal != 0)) or request.ordinal != request.scope.ordinal or !self.trace.freeze_allocation_plan or self.trace.service != self.service or self.projection.service != self.service or self.projection.pending != null or self.projection.prestage_error != null) return error.EarlyStageAdmissionUnavailable;
        const compact = if (std.posix.getenv("STWO_RV64_CPU_COMPACT_INGRESS")) |v| !std.mem.eql(u8, v, "0") else false;
        if (compact and self.projection.unpack == null) return error.MissingCpuUnpackKernel;
        const tc = self.trace.allocationOptions(config.fri_config.log_blowup_factor);
        const plan = try Adapter.init(a, request, .{ .compact_ingress = compact, .retain_ledgers = self.projection.retain_ledgers, .cold_rom = true, .commit = .{ .beta = tc.beta, .separate_coefficients = tc.separate_coefficients, .stream_budget = tc.stream_budget, .exact_prefix_banks = tc.exact_prefix_banks } });
        // Source and TC reserve their own global permits before allocation.
        // A second local GPU ticket would double charge those stages and
        // misattribute retention belonging to other globally admitted scopes.
        const before: Runtime.Snapshot = if (global) .{} else try self.snapshot();
        const envelope: Capacity.Envelope = if (global) undefined else try Capacity.assess(before, self.physical, self.service.byte_cap, &plan);
        var stack_charge = try budget.reserveExternal(try std.math.mul(usize, plan.extra_pack_threads, @import("cpu_witness.zig").pack_stack_bytes));
        errdefer stack_charge.deinit();
        const claim = try a.create(Claim);
        errdefer a.destroy(claim);
        claim.* = .{ .allocator = a, .owner = self, .plan = plan, .before = before, .envelope = envelope, .pack_stacks = stack_charge.take(), .global = global };
        errdefer claim.pack_stacks.deinit();
        if (global) {
            self.retained_global_claims = try std.math.add(usize, self.retained_global_claims, 1);
        } else try self.service.early_allocations.begin(&claim.plan, @import("pcs_scope.zig").identity(request.scope));
        self.claim = claim;
        if (global) {
            std.debug.print("GPU_EARLY_MAIN_ADMISSION event=reserve physical={} ordinal={} plan={x} gpu_policy=global_source_tc host_cost_known=false\n", .{ self.physical, request.ordinal, plan.identity });
        } else std.debug.print("GPU_EARLY_MAIN_ADMISSION event=reserve physical={} plan={x} required_large={} required_small={} capacity_large={} capacity_small={} whole_process_peak_qualified=false host_cost_known=false\n", .{ self.physical, plan.identity, envelope.required.large, envelope.required.small, envelope.capacity.large, envelope.capacity.small });
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
    global: bool = false,
    fn finishJoined(raw: *anyopaque) !void {
        const self: *Claim = @ptrCast(@alignCast(raw));
        self.owner.mutex.lock();
        defer self.owner.mutex.unlock();
        if (self.owner.claim != self or self.joined) return error.StaleEarlyStageTicket;
        errdefer self.owner.poisoned = true;
        if (self.global) {
            // The retained MAIN is charged by the global physical snapshot,
            // not by keeping this exclusive early-producer slot occupied.
            self.pack_stacks.deinit();
            self.joined = true;
            self.owner.claim = null;
            return;
        }
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
        if (self.global) {
            std.debug.assert(owner.retained_global_claims > 0);
            owner.retained_global_claims -= 1;
            if (!self.joined) {
                std.debug.assert(owner.claim == self);
                owner.claim = null;
            }
        } else {
            std.debug.assert(owner.claim == self);
            owner.claim = null;
            owner.service.early_allocations.cancelDestroyed(&self.plan);
        }
        owner.mutex.unlock();
        self.pack_stacks.deinit();
        const a = self.allocator;
        a.destroy(self);
    }
};

test "global early tickets release producer slot at join and retain independent destruction custody" {
    const a = std.testing.allocator;
    const budget = try Budget.create(a, 128);
    defer budget.destroy();
    // These service pointers must never be dereferenced by a global host-only
    // ticket: Source and TC independently own their actual GPU permits.
    var owner = Context{ .service = undefined, .trace = undefined, .projection = undefined, .physical = 0 };
    const first = try a.create(Claim);
    first.* = .{ .allocator = a, .owner = &owner, .plan = undefined, .before = undefined, .envelope = undefined, .pack_stacks = try budget.reserveExternal(32), .global = true };
    owner.claim = first;
    owner.retained_global_claims = 1;
    try Claim.finishJoined(first);
    try std.testing.expect(owner.claim == null);
    try std.testing.expectEqual(@as(usize, 1), owner.retained_global_claims);
    try std.testing.expectEqual(@as(usize, 0), budget.snapshot().external_live_bytes);
    try std.testing.expectError(error.StaleEarlyStageTicket, Claim.finishJoined(first));

    const second = try a.create(Claim);
    second.* = .{ .allocator = a, .owner = &owner, .plan = undefined, .before = undefined, .envelope = undefined, .pack_stacks = try budget.reserveExternal(64), .global = true };
    owner.claim = second;
    owner.retained_global_claims += 1;
    // Destroying an older retained worker must not clear the next active slot.
    Claim.releaseDestroyed(first);
    try std.testing.expect(owner.claim == second);
    try std.testing.expectEqual(@as(usize, 1), owner.retained_global_claims);
    try std.testing.expectEqual(@as(usize, 64), budget.snapshot().external_live_bytes);
    // An aborted producer returns the slot and charge without GPU retirement
    // fiction; its actual Source/TC owners are separately unwound by the caller.
    Claim.releaseDestroyed(second);
    try std.testing.expectEqual(@as(usize, 0), budget.snapshot().external_live_bytes);
    owner.deinit();
}
