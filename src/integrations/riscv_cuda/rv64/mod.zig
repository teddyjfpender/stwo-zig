//! Additive RV64 numerical CUDA lane, based on PR310. Full Ethereum CUDA proof
//! dispatch remains unavailable until witness/PCS/transcript parity qualifies.
pub const execution = @import("execution_bindings.zig");
pub const truth_source = @import("truth_source.zig");
pub const bridge_witness = @import("bridge_witness.zig");
pub const device_source = @import("device_source.zig");
pub const core_witness = @import("core_witness.zig");
pub const truth_codegen = @import("truth_codegen.zig");
pub const cpu_projection = @import("cpu_projection.zig");
pub const cpu_witness = @import("cpu_witness.zig");
pub const trace_commit = @import("trace_commit.zig");
pub const resident_composition = @import("resident_composition.zig");
pub const projection_codegen = @import("projection_codegen.zig");
pub const gkr = @import("gkr.zig");
pub const gkr_stage = @import("gkr_stage.zig");
pub const batch = @import("batch.zig");
pub const composition_codegen = @import("composition_codegen.zig");
pub const channel = @import("channel.zig");
pub const pcs = @import("pcs.zig");
pub const deep = @import("deep.zig");
pub const samples = @import("samples.zig");
pub const fri = @import("fri.zig");
pub const trace = @import("trace.zig");
pub const plan = @import("plan.zig");
pub const scheduler = @import("scheduler.zig");
pub const resident = @import("resident.zig");
pub const assembly = @import("assembly.zig");
pub const sumcheck = @import("sumcheck.zig");
pub const production_ready = false;
test {
    _ = truth_source;
    _ = core_witness;
    _ = device_source;
    _ = bridge_witness;
    _ = trace_commit;
    _ = cpu_witness;
    _ = cpu_projection;
    _ = truth_codegen;
    _ = gkr_stage;
    _ = resident_composition;
    _ = @import("composition_columns.zig");
    _ = @import("trace_input_reuse.zig");
    _ = @import("composition_cost.zig");
    _ = @import("runtime_memory.zig");
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

pub const outer_source = @import("outer_source.zig");
test {
    _ = outer_source;
}
