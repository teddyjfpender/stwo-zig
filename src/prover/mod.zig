const std = @import("std");
const prover_api = @import("stwo_prover_api");

pub const fft_pool = @import("fft_pool.zig");
pub const engine = @import("engine.zig");
pub const mmap_alloc = @import("mmap_alloc.zig");
pub const line = @import("line.zig");
pub const fri = @import("fri.zig");
pub const air = @import("air/mod.zig");
pub const channel = @import("channel/mod.zig");
pub const lookups = @import("lookups/mod.zig");
pub const pcs = @import("pcs/mod.zig");
pub const poly = @import("poly/mod.zig");
pub const secure_column = @import("secure_column.zig");
pub const session = @import("session.zig");
pub const stage_profile = @import("stwo_prover_api").stage_profile;
pub const work_profile = prover_api.work_profile;
pub const host_budget_allocator = @import("host_budget_allocator.zig");
pub const vcs = @import("vcs/mod.zig");
pub const vcs_lifted = @import("vcs_lifted/mod.zig");
pub const prove = @import("prove.zig");
pub const task_graph = @import("task_graph.zig");
pub const task_profile = @import("stwo_prover_api").task_profile;
pub const transaction = @import("transaction.zig");
pub const work_pool = @import("work_pool.zig");
pub const resident_storage = @import("resident_storage.zig");
pub const measurement = @import("measurement/mod.zig");
pub const execution = @import("execution/mod.zig");

test {
    _ = @import("fri_work_test.zig");
    _ = @import("work_pool_test.zig");
    _ = host_budget_allocator;
    _ = @import("task_graph_nested_test.zig");
    _ = @import("task_graph_profile_failure_test.zig");
    _ = @import("task_graph_profile_test.zig");
    _ = @import("task_graph_retained_lease_test.zig");
    _ = @import("task_graph_work_pool_test.zig");
}

test "api signature: engine reexports the stable transaction contract" {
    comptime {
        if (engine.ProveOptions != prover_api.ProveOptions) {
            @compileError("engine ProveOptions drifted from stwo_prover_api");
        }
        if (@TypeOf(engine.assertProverEngine) != @TypeOf(prover_api.assertProverEngine)) {
            @compileError("engine assertion signature drifted from stwo_prover_api");
        }
    }
    std.testing.refAllDecls(engine);
}
