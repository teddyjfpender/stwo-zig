//! Conservative hard planning for the actual raw local scope. No allocation is
//! permitted before this admission succeeds; scheduling estimates are separate.
const std = @import("std");
const Instance = @import("frame.zig").Instance;
const Numerical = @import("stwo_prover_engine").lookups.resource.ForField(@import("stwo_core").fields.om31.OM31);
pub const Plan = struct {
    input_bytes: usize = 0,
    owned_layer_bytes: usize = 0,
    metadata_bytes: usize = 0,
    binding_bytes: usize = 0,
    peak_bytes: usize = 0,
    pub fn forInstances(instances: []const Instance, limit: usize) !Plan {
        return forInstancesWithOwnedCheckpoints(instances, limit, false);
    }
    /// The lower reserve is valid ONLY for the fused stride2 owned producer and
    /// metadata-only terminal binding. Original backing capacities remain in
    /// the raw+working reserve until freed; logical resize is not a discount.
    pub fn forInstancesWithOwnedCheckpoints(instances: []const Instance, limit: usize, checkpointed: bool) !Plan {
        if (limit == 0) return error.MissingLocalGkrBudget;
        var numerical = Numerical.Plan{};
        var p = Plan{};
        var facts: usize = 0;
        var projection_scratch: usize = 0;
        for (instances) |instance| {
            facts = try std.math.add(usize, facts, try instance.facts());
            if (checkpointed) projection_scratch = @max(projection_scratch, try @import("prepared_projection.zig").For(@import("stwo_core").fields.om31.OM31).maxBytesForTerms(instance.terms));
            try numerical.add(.{ .kind = .multiplicities, .variables = try instance.variables() });
            p.binding_bytes = try std.math.add(usize, p.binding_bytes, try std.math.mul(usize, try instance.rows(), 64));
        }
        try numerical.finish();
        p.input_bytes = numerical.input_bytes;
        // Retained field name for receipt compatibility; this is the complete
        // working-plane reserve, not an assertion that input is still cloned.
        p.owned_layer_bytes = if (checkpointed) try std.math.mul(usize, facts, 2 * @sizeOf(@import("stwo_core").fields.om31.OM31) + @sizeOf(@import("stwo_core").fields.m31.M31)) else numerical.working_plane_bytes;
        p.metadata_bytes = numerical.metadata_bytes;
        const binding_headers = try std.math.mul(usize, instances.len, @sizeOf([]@import("stwo_core").fields.m31.M31));
        const binding_phase = try std.math.add(usize, try std.math.add(usize, if (checkpointed) projection_scratch else p.input_bytes, p.binding_bytes), try std.math.add(usize, binding_headers, p.metadata_bytes));
        const numerical_peak = try std.math.add(usize, try std.math.add(usize, p.input_bytes, p.owned_layer_bytes), p.metadata_bytes);
        // Metadata includes retained proof/artifact and adapter owner headers.
        // The parent-owned binding planes remain externally charged under the
        // same hard allocator; later PCS adoption requires its own worker lease.
        p.peak_bytes = @max(numerical_peak, binding_phase);
        if (p.peak_bytes > limit) return error.LocalGkrBudgetExceeded;
        return p;
    }
};

/// External backing reservation under the SAME cap, owned by the parent worker
/// allocator so existing owned PCS commits can adopt it without an allocator
/// mismatch. This owner is single-threaded; no concurrent budget mutations.
pub fn reserveExternal(budget: *@import("stwo_prover_engine").host_budget_allocator.HostBudgetAllocator, bytes: usize) !void {
    if (budget.live_bytes > budget.limit or budget.external_live_bytes > budget.limit - budget.live_bytes or bytes > budget.limit - budget.live_bytes - budget.external_live_bytes) {
        budget.budget_exceeded = true;
        return error.OutOfMemory;
    }
    budget.external_live_bytes += bytes;
    budget.peak_external_bytes = @max(budget.peak_external_bytes, budget.external_live_bytes);
    budget.peak_live_bytes = @max(budget.peak_live_bytes, budget.live_bytes + budget.external_live_bytes);
}
pub fn releaseExternal(budget: *@import("stwo_prover_engine").host_budget_allocator.HostBudgetAllocator, bytes: usize) void {
    std.debug.assert(bytes <= budget.external_live_bytes);
    budget.external_live_bytes -= bytes;
}
