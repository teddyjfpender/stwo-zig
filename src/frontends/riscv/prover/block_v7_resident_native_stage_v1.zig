//! Explicit CPU resident handoff: original columns and PCS trees survive from
//! collection through the shared-original proof. No disk checkpoint, rebuild,
//! or successful-proof receipt is manufactured. The durable route is unchanged.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Current = @import("block_v5_cpu_execution_source_v1.zig").Current;
const Root = @import("block_v5_cpu_native_root_proposal_v1.zig");
const Physical = Root.ForBackend(Cpu);
const Access = @import("block_v5_native_memory_stage_v1.zig");
const AP = Access.ForBackend(Cpu);
const Native = @import("block_v7_native_proof_v1.zig");
const Cache = @import("block_v7_native_checkpoint_v1.zig");
const Counters = @import("../air/lookups/tables/counter.zig");
const Budget = engine.host_budget_allocator.SharedHostBudget;
pub const Owned = struct {
    allocator: std.mem.Allocator,
    budget: *Budget,
    owner: *@import("blake3_execution_trace.zig").Owner,
    original: Physical.Retained,
    access: AP.Retained,
    first: Native.For(Cpu).First,
    layout_mode: @import("block_v7_native_source_v1.zig").LayoutMode,
    pub fn collect(a: std.mem.Allocator, current: *Current, config: core.pcs.PcsConfig, profile: @import("../isa/execution_profile.zig").ExecutionProfile, index: u32, global: *Counters.Set, sink: Cache.EventSink, limits: Cache.Limits) !*Owned {
        const budget = Budget.fromAllocator(a) orelse return error.ResidentNativeRequiresHardBudget;
        if (Budget.fromAllocator(current.owner.allocator) != budget or limits.source.register_custody_mode != 1)
            return error.InvalidResidentNativeLifetime;
        // Caller witnesses require their own resident owner. This first path
        // deliberately refuses them instead of falling back into mixed storage.
        if (current.owner.external_retirements != 0) return error.UnsupportedResidentNativeCaller;
        const io = current.owner.statement.public_data.io_entries;
        if (!current.native_owner_owned or io.input_words.len != 0 or io.output_words.len != 0)
            return error.BorrowedResidentNativePublicIo;
        var local = try Counters.Set.init(a);
        defer local.deinit(a);
        const counters = if (current.owner.opcode_columns.lookup_counters) |*value| value else return error.InvalidResidentNativePhase;
        local.mergeFrom(counters);
        var original = try Physical.collectRetainedWithRetention(a, current.owner, config, profile, index, current.segment.base.global_first_cycle, .{ .max_public_words = 0, .max_metadata_bytes = @sizeOf(Root.Proposal) }, .{ .fixed = true, .main = true });
        errdefer original.deinit(a);
        const frame = @import("../air/block/memory_event.zig").Frame{ .clock_frame = .leaf_local, .global_first_cycle = current.segment.base.global_first_cycle, .cycle_count = current.owner.statement.public_data.clock };
        var access = try AP.collectRetainedTimed(a, current.owner, frame, &original.proposal, &local, limits.source, null);
        errdefer access.deinit(a);
        var first = if (access.proposal.slots.len == 0)
            try @import("block_v5_native_projection_fused_stage_v2.zig").ForBackend(Cpu).borrowProjectionFirstRound(a, &original.first.scheme, @splat(0))
        else
            try AP.borrowRetained(a, &original.first.scheme, &access.scheme, access.snapshots, &access.proposal);
        errdefer first.deinit(a);
        const out = try a.create(Owned);
        errdefer a.destroy(out);
        // Validate the exact old epoch entry, including the original physical
        // roots and census. Retention is an implementation choice, not a key.
        out.* = .{ .allocator = a, .budget = budget, .owner = current.owner, .original = original, .access = access, .first = first, .layout_mode = limits.native_layout_mode };
        _ = try out.pin().entry(a);
        for (access.source.inputs) |input| for (0..input.trace.domainSize()) |row| {
            const event = try input.trace.row(row);
            if (event.active) try sink.put(sink.context, try @import("block_memory_relation_v2.zig").decodeTransitionTuple(event.tuple));
        };
        _ = try current.takeNativeOwner();
        out.budget = budget.retain();
        global.mergeFrom(&local);
        return out;
    }
    pub fn pin(self: *const Owned) Native.Pin {
        return .{ .index = self.original.proposal.index, .shape = &self.original.proposal.shape, .frame = self.access.proposal.frame, .template = self.original.first.template, .roots = self.original.first.roots, .access_root = if (self.access.proposal.slots.len == 0) @splat(0) else self.access.proposal.witness_root, .expected_events = self.access.proposal.ordinary_events, .layout_mode = self.layout_mode };
    }
    pub fn deinit(self: *Owned) void {
        const a = self.allocator;
        const budget = self.budget;
        self.first.deinit(a);
        self.access.deinit(a);
        self.original.deinit(a);
        self.owner.deinit();
        a.destroy(self);
        budget.destroy();
    }
};
