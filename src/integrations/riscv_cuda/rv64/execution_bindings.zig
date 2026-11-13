//! Typed native device and job interfaces used by product orchestration.
//! Device programs and proof records keep their existing canonical owners.
pub const runtime = struct {
    pub const resident_router = @import("resident_router.zig");
    pub const cuda_events = @import("cuda_events.zig");
    pub const abi = @import("abi.zig");
    pub const combined_publication = @import("combined_publication.zig");
    pub const resident_ready_policy = @import("resident_ready_policy.zig");
    pub const serial_fixed_policy = @import("serial_fixed_policy.zig");
    pub const circuit_air_preflight = @import("circuit_air_preflight.zig");
    pub const outer_job_factory = @import("outer_job_factory.zig");
    pub const outer_assignment = @import("outer_assignment.zig");
};
pub const jobs = struct {
    pub const runtime = @import("jobs/mod.zig");
    pub const gpu_native = @import("jobs/gpu_native.zig");
    pub const native_pcs = @import("jobs/native_pcs.zig");
    pub const native_encode = @import("jobs/native_encode.zig");
    pub const native_encode_oods = @import("jobs/native_encode_oods.zig");
    pub const native_device_stage2 = @import("jobs/native_device_stage2.zig");
    pub const native_gkr = @import("jobs/native_gkr.zig");
    pub const native_global = @import("jobs/native_global.zig");
    pub const native_commit = @import("jobs/native_commit.zig");
    pub const native_stage1 = @import("jobs/native_stage1.zig");
    pub const native_binding = @import("jobs/native_binding.zig");
    pub const native_composition = @import("jobs/native_composition.zig");
    pub const native_stage2 = @import("jobs/native_stage2.zig");
    pub const native_claims = @import("jobs/native_claims.zig");
    pub const driver = @import("jobs/driver.zig");
    pub const truth_class = @import("jobs/truth_class.zig");
    pub const truth_job = @import("jobs/truth_job.zig");
    pub const truth_challenges = @import("jobs/truth_challenges.zig");
    pub const native_device_stage1 = @import("jobs/native_device_stage1.zig");
    pub const native_device = @import("jobs/native_device.zig");
    pub const job_timing = @import("jobs/job_timing.zig");
    pub const native_leaf_wire = @import("jobs/native_leaf_wire.zig");
    pub const truth_factory = @import("jobs/truth_factory.zig");
    pub const recursion_classes = @import("jobs/recursion_classes.zig");
    pub const driver_bind = @import("jobs/driver_bind.zig");
    pub const native_leaf_build = @import("jobs/native_leaf_build.zig");
    pub const native_leaf_warm = @import("jobs/native_leaf_warm.zig");
    pub const channel = @import("jobs/channel.zig");
    pub const ops = @import("jobs/ops.zig");
    pub const driver_dag = @import("jobs/driver_dag.zig");
    pub const outer_device = @import("jobs/outer_device.zig");
    pub const outer_seed_device = @import("jobs/outer_seed_device.zig");
    pub const outer_class_plan = @import("jobs/outer_class_plan.zig");
    pub const outer_staged = @import("jobs/outer_staged.zig");
    pub const outer_job = @import("jobs/outer_job.zig");
    pub const api = @import("jobs/api.zig");
    pub const outer_fixed_job = @import("jobs/outer_fixed_job.zig");
    pub const worker = @import("jobs/worker.zig");
    pub const native_pack_capture = @import("jobs/native_pack_capture.zig");
    pub const native_pack = @import("jobs/native_pack.zig");
    pub const native_semantic = @import("jobs/native_semantic.zig");
    pub const native_framing_cache = @import("jobs/native_framing_cache.zig");
    pub const driver_request = @import("jobs/driver_request.zig");
    pub const driver_serve = @import("jobs/driver_serve.zig");
};
pub const composition = struct {
    pub const roles = @import("m8_native_composition_roles.zig");
    pub const joined_codegen = @import("joined_codegen.zig");
    pub const sources = @import("joined_fixture_support.zig");
    pub const real_composition = @import("real_composition.zig");
    pub const joined_parameters = @import("joined_parameters.zig");
};
pub const pcs = struct {
    pub const pcs_native = @import("pcs_native.zig");
    pub const hybrid_pcs = @import("hybrid_pcs.zig");
};
pub const source = struct {
    pub const global_stage = @import("global_stage.zig");
    pub const bulk_sponge = @import("bulk_sponge.zig");
    pub const gkr_sources = @import("gkr_sources.zig");
    pub const cpu_replay = @import("cpu_replay.zig");
    pub const m8_capture_stream = @import("m8_capture_stream.zig");
};
