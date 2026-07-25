//! Planning contracts for a future resident Cairo CUDA proof executor.
//!
//! This package deliberately owns no stage execution. It turns authenticated
//! Cairo proof geometry into explicit device slots and the shared lifetime
//! arena used by native CUDA products.

pub const resident_plan = @import("resident_plan.zig");
pub const resident_session = @import("resident_session.zig");
pub const statement_ingress = @import("statement_ingress.zig");
pub const execution_schedule = @import("execution_schedule.zig");
pub const ingress = @import("ingress/mod.zig");
pub const proof_session = @import("proof_session.zig");
pub const preprocessed_cache = @import("preprocessed_cache.zig");
pub const canonical_twiddles = @import("canonical_twiddles.zig");
pub const eval = @import("eval/mod.zig");
pub const pcs_hooks = @import("pcs_hooks.zig");
pub const pcs_fri_controller = @import("pcs_fri_controller.zig");
pub const pcs_oods_controller = @import("pcs_oods_controller.zig");
pub const pcs_oods_topology = @import("pcs_oods_topology.zig");
pub const pcs_decommit_controller = @import(
    "pcs_decommit_controller.zig",
);
pub const pcs_decommit_topology = @import("pcs_decommit_topology.zig");
pub const quotient = @import("quotient/mod.zig");
pub const terminal_bundle = @import("terminal_bundle.zig");
pub const terminal_decode = @import("terminal_decode.zig");
pub const terminal_controller = @import("terminal_controller.zig");
pub const trace_commit = @import("trace_commit.zig");
pub const trace_schedule = @import("trace_schedule.zig");
pub const base_writer_binding = @import("base_writer_binding.zig");
pub const trace_writer_controller = @import("trace_writer_controller.zig");
pub const proof_route = @import("proof_route.zig");
pub const transcript = @import("transcript/mod.zig");

test {
    _ = @import("proof_session.zig");
    _ = @import("pcs_decommit_controller_test.zig");
    _ = @import("pcs_decommit_topology_test.zig");
    _ = @import("pcs_hooks_test.zig");
    _ = @import("pcs_fri_controller_test.zig");
    _ = @import("pcs_oods_controller_test.zig");
    _ = @import("pcs_oods_topology_test.zig");
    _ = @import("resident_plan_test.zig");
    _ = @import("terminal_route_test.zig");
    _ = @import("trace_commit_test.zig");
    _ = @import("trace_schedule_test.zig");
    _ = @import("base_writer_binding_test.zig");
    _ = @import("trace_writer_controller_test.zig");
    @import("std").testing.refAllDeclsRecursive(@This());
}
