//! Shared structural machinery for Native CUDA AIR integrations.

pub const commit_tree = @import("commit_tree.zig");
pub const driver = @import("driver.zig");
pub const fri_executor = @import("fri_executor.zig");
pub const native_composition = @import("native_composition.zig");
pub const native_ingress = @import("native_ingress.zig");
pub const native_trace_commit = @import("native_trace_commit.zig");
pub const oods_executor = @import("oods_executor.zig");
pub const pipeline = @import("pipeline.zig");
pub const pow_decommit_executor = @import("pow_decommit_executor.zig");
pub const prepared_plan = @import("prepared_plan.zig");
pub const proof_assembly = @import("proof_assembly.zig");
pub const proof_bundle = @import("proof_bundle.zig");
pub const proof_decode = @import("proof_decode.zig");
pub const quotient_executor = @import("quotient_executor.zig");
pub const resident_views = @import("resident_views.zig");
pub const resident_bindings = @import("resident_bindings.zig");
pub const scheduled_executor = @import("scheduled_executor.zig");
pub const transcript_executor = @import("transcript_executor.zig");
pub const transcript_schedule = @import("transcript_schedule.zig");
pub const uniform_layout = @import("uniform_layout.zig");
pub const uniform_topology = @import("uniform_topology.zig");

test {
    _ = commit_tree;
    _ = driver;
    _ = fri_executor;
    _ = native_composition;
    _ = native_ingress;
    _ = native_trace_commit;
    _ = oods_executor;
    _ = pipeline;
    _ = pow_decommit_executor;
    _ = prepared_plan;
    _ = proof_assembly;
    _ = proof_bundle;
    _ = proof_decode;
    _ = quotient_executor;
    _ = resident_views;
    _ = resident_bindings;
    _ = scheduled_executor;
    _ = transcript_executor;
    _ = transcript_schedule;
    _ = uniform_layout;
    _ = uniform_topology;
}
