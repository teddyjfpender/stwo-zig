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
    /// Source-checked tighter production-multiplicity reserve. Dense and owned
    /// checkpoint paths have separate phase bounds. Original backing capacities
    /// remain charged until freed; logical resize is not a physical discount.
    pub fn forInstancesWithOwnedCheckpoints(instances: []const Instance, limit: usize, checkpointed: bool) !Plan {
        return forInstancesWithTightAdmission(instances, limit, checkpointed, checkpointed);
    }
    pub fn forInstancesWithTightAdmission(instances: []const Instance, limit: usize, checkpointed: bool, tight: bool) !Plan {
        return forInstancesPolicy(instances, limit, checkpointed, tight, false);
    }
    /// Only for the source-checkpoint API: no dense N/D input owner exists,
    /// opaque cloning/materialization is excluded from the production path.
    pub fn forInstancesWithStreamedBottom(instances: []const Instance, limit: usize) !Plan {
        return forInstancesPolicy(instances, limit, true, true, true);
    }
    pub fn forInstancesWithSourceStorage(instances: []const Instance, limit: usize, checkpointed: bool) !Plan {
        return forInstancesPolicy(instances, limit, checkpointed, true, true);
    }
    fn forInstancesPolicy(instances: []const Instance, limit: usize, checkpointed: bool, tight: bool, streamed: bool) !Plan {
        if (limit == 0) return error.MissingLocalGkrBudget;
        var numerical = Numerical.Plan{};
        var p = Plan{};
        var facts: usize = 0;
        var projection_scratch: usize = 0;
        for (instances) |instance| {
            facts = try std.math.add(usize, facts, try instance.facts());
            if (checkpointed or streamed) projection_scratch = @max(projection_scratch, try @import("prepared_projection.zig").For(@import("stwo_core").fields.om31.OM31).maxBytesForTerms(instance.terms));
            try numerical.add(.{ .kind = .multiplicities, .variables = try instance.variables() });
            p.binding_bytes = try std.math.add(usize, p.binding_bytes, try std.math.mul(usize, try instance.rows(), 64));
        }
        try numerical.finish();
        p.input_bytes = if (streamed) 0 else numerical.input_bytes;
        // Retained field name for receipt compatibility; this is the complete
        // working-plane reserve, not an assertion that input is still cloned.
        p.owned_layer_bytes = if (tight) try std.math.mul(usize, facts, if (streamed and !checkpointed) @as(usize, 80) else 2 * @sizeOf(@import("stwo_core").fields.om31.OM31) + @sizeOf(@import("stwo_core").fields.m31.M31)) else numerical.working_plane_bytes;
        p.metadata_bytes = numerical.metadata_bytes;
        const binding_headers = try std.math.mul(usize, instances.len, @sizeOf([]@import("stwo_core").fields.m31.M31));
        const binding_phase = try std.math.add(usize, try std.math.add(usize, if (checkpointed or streamed) projection_scratch else p.input_bytes, p.binding_bytes), try std.math.add(usize, binding_headers, p.metadata_bytes));
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
