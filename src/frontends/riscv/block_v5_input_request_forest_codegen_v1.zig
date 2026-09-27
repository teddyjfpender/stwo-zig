//! Address-retained actual producer/receiver/forest bodies. Never invokes them.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Plan = @import("recursion/block_v5_input_request_forest_plan_v1.zig");
const Public = @import("recursion/block_v5_input_request_forest_public_v1.zig");
const Bus = @import("recursion/block_v5_input_request_forest_bus_v1.zig");
const Source = @import("recursion/block_v5_input_request_forest_source_v1.zig");
const Rows = @import("recursion/block_v5_input_request_forest_preparation_v1.zig");
const Receiver = @import("recursion/block_v5_input_request_forest_receiver_v1.zig");
const Stage = @import("prover/block_v5_input_request_forest_stage_v1.zig").ForBackend(Cpu);
const RunModule = @import("prover/block_v5_input_request_forest_run_v1.zig");
const Run = RunModule.ForBackend(Cpu);
const Selection = @import("prover/block_v5_cpu_input_request_forest_v1.zig");
pub export fn stwo_input_request_forest_body_gate() void {
    inline for (.{ &Plan.derive, &Plan.Geometry.deinit, &Plan.Owned.init, &Plan.Owned.validate, &Plan.Owned.deinit, &Public.Owned.init, &Public.Owned.validate, &Bus.Owner.init, &Bus.Owner.validate, &Bus.Owner.deinit, &Bus.Values.at, &Source.Source.init, &Source.Source.validate, &Source.Source.cell, &Source.Source.replayPublic, &Source.Source.deinit, &Rows.prepare, &Rows.Prepared.deinit, &Receiver.admit, &Receiver.verify, &Receiver.verifyRoot, &Receiver.Fresh.validate, &Receiver.Fresh.deinit, &Stage.publish, &Stage.Artifact.deinit, &Run.run, &RunModule.Result.verifyRoot, &RunModule.Result.deinit, &Selection.publish }) |body| std.mem.doNotOptimizeAway(body);
}
