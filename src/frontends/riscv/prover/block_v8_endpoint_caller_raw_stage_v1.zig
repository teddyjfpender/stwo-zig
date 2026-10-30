//! Resident arithmetic witness preparation only. No commitments, checkpoints,
//! WORD witnesses or proof authority. The new mixed original must still prove
//! all arithmetic/projections, append constrained halt auxiliaries, and close
//! the local buses before this owner can confer execution authority.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const P = @import("blake3_ethereum_sha_profile.zig");
const W = @import("block_v5_precompile_witness_v1.zig");
const Plan = @import("block_v8_endpoint_caller_plan_v1.zig");
pub const production_active = false;
pub const Limits = struct { max_live_bytes: usize = 4 << 30, plan: Plan.Limits = .{} };
pub const Owned = struct {
    a: std.mem.Allocator,
    budget: *engine.host_budget_allocator.SharedHostBudget,
    arena: std.heap.ArenaAllocator,
    witness: W.Witness,
    plan: Plan.Owned,
    fixed: []engine.pcs.ColumnEvaluation,
    main: []engine.pcs.ColumnEvaluation,
    pub fn initSegment(backing: std.mem.Allocator, segment: *const @import("../runner/mod.zig").EthereumShaSegmentResult, limits: Limits) !*Owned {
        if (limits.max_live_bytes == 0) return error.InvalidEndpointCallerBudget;
        const budget = try engine.host_budget_allocator.SharedHostBudget.createRetainingParent(backing, limits.max_live_bytes);
        errdefer budget.destroy();
        const a = budget.allocator();
        var witness = try W.Witness.initSegment(a, segment);
        errdefer witness.deinit();
        var plan = try Plan.Owned.init(a, &witness.statement, witness.total_steps, .{ .clock_frame = segment.base.clock_frame, .global_first_cycle = segment.base.global_first_cycle, .cycle_count = witness.total_steps }, limits.plan);
        errdefer plan.deinit();
        var arena = std.heap.ArenaAllocator.init(a);
        errdefer arena.deinit();
        const raw = arena.allocator();
        const full_fixed = try P.preprocessed(raw, &witness.statement);
        const full_main = try P.mainWitness(raw, &witness);
        const fixed = try plan.layout.columns(raw, 0, full_fixed);
        const main = try plan.layout.columns(raw, 1, full_main.columns);
        if (fixed.len != plan.schedule.fixed.len or main.len != plan.arithmetic_main_columns) return error.UntrustedEndpointCallerColumns;
        for (fixed, plan.schedule.fixed) |column, log| if (column.log_size != log or column.values.len != @as(usize, 1) << @intCast(log)) return error.UntrustedEndpointCallerColumns;
        for (main, plan.schedule.main) |column, log| if (column.log_size != log or column.values.len != @as(usize, 1) << @intCast(log)) return error.UntrustedEndpointCallerColumns;
        const self = try a.create(Owned);
        self.* = .{ .a = a, .budget = budget, .arena = arena, .witness = witness, .plan = plan, .fixed = fixed, .main = main };
        return self;
    }
    pub fn deinit(self: *Owned) void {
        const a = self.a;
        const budget = self.budget;
        self.arena.deinit();
        self.plan.deinit();
        self.witness.deinit();
        a.destroy(self);
        budget.destroy();
    }
};
