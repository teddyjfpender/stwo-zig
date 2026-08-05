//! Plan-correspondence checks for an owned Poseidon2 compatibility binding.

const std = @import("std");
const digest = @import("digest.zig");
const materializer = @import("degree3_materializer.zig");
const types = @import("types.zig");

pub const Error = error{
    PlanBindingMismatch,
    ProgramDigestMismatch,
};

pub fn validate(
    comptime entry_count: usize,
    program_digest: digest.Digest,
    gate: types.ValueId,
    policy: materializer.Policy,
    entries: anytype,
    plan_value: *const materializer.Plan,
) Error!void {
    if (!std.mem.eql(u8, &program_digest, &plan_value.program_digest))
        return error.ProgramDigestMismatch;
    if (plan_value.gate == null or gate != plan_value.gate.? or
        !std.meta.eql(policy, plan_value.policy) or
        entries.len != entry_count or
        plan_value.materializations.len != entry_count)
    {
        return error.PlanBindingMismatch;
    }
    var used = [_]bool{false} ** entry_count;
    for (entries) |entry| {
        const index = types.idIndex(entry.plan_materialization);
        if (index >= plan_value.materializations.len or used[index])
            return error.PlanBindingMismatch;
        const planned = plan_value.materializations[index];
        if (entry.value != planned.source_value or
            !std.meta.eql(entry.source_span, planned.source_span))
        {
            return error.PlanBindingMismatch;
        }
        used[index] = true;
    }
    for (used) |consumed| if (!consumed) return error.PlanBindingMismatch;
}
