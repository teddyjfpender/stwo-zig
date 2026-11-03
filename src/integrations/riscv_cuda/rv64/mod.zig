//! Additive RV64 numerical CUDA lane, based on PR310. Full Ethereum CUDA proof
//! dispatch remains unavailable until witness/PCS/transcript parity qualifies.
pub const joined_codegen = @import("joined_codegen.zig");
pub const symbolic_external = @import("symbolic_external.zig");
pub const projection_codegen = @import("projection_codegen.zig");
pub const gkr = @import("gkr.zig");
pub const batch = @import("batch.zig");
pub const composition_codegen = @import("composition_codegen.zig");
pub const channel = @import("channel.zig");
pub const pcs = @import("pcs.zig");
pub const deep = @import("deep.zig");
pub const samples = @import("samples.zig");
pub const fri = @import("fri.zig");
pub const trace = @import("trace.zig");
pub const pcs_assembly = @import("pcs_assembly.zig");
pub const plan = @import("plan.zig");
pub const scheduler = @import("scheduler.zig");
pub const resident = @import("resident.zig");
pub const assembly = @import("assembly.zig");
pub const sumcheck = @import("sumcheck.zig");
pub const production_ready = false;
test {
    _ = samples;
    _ = fri;
    _ = @import("tests/fri_test.zig");
    _ = @import("tests/trace_test.zig");
    _ = @import("tests/pcs_assembly_test.zig");
    _ = @import("tests/joined_codegen_test.zig");
    _ = @import("tests/symbolic_external_test.zig");
    _ = @import("tests/batch_test.zig");
    _ = @import("tests/gkr_test.zig");
    _ = @import("tests/projection_codegen_test.zig");
    _ = @import("tests/composition_codegen_test.zig");
    _ = @import("tests/channel_test.zig");
    _ = @import("tests/pcs_test.zig");
    _ = @import("tests/deep_test.zig");
    _ = @import("tests/plan_test.zig");
    _ = @import("tests/scheduler_test.zig");
    _ = @import("tests/resident_test.zig");
    _ = @import("tests/sumcheck_test.zig");
}
