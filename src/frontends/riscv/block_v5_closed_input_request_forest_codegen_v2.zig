//! Retains real independent-key, verifier, node AIR, publisher and teardown
//! bodies. The exported marker never calls a proof/PCS/receiver body.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Bus = @import("recursion/block_v5_closed_input_request_forest_bus_v2.zig");
const Source = @import("recursion/block_v5_closed_input_request_forest_source_v2.zig");
const Rows = @import("recursion/block_v5_closed_input_request_forest_preparation_v2.zig");
const Receiver = @import("recursion/block_v5_closed_input_request_forest_receiver_v2.zig");
const Setup = @import("prover/block_v5_closed_input_request_forest_setup_v2.zig").ForBackend(Cpu);
const Stage = @import("prover/block_v5_closed_input_request_forest_stage_v2.zig").ForBackend(Cpu);
pub export fn stwo_closed_input_request_forest_body_gate() void {
    inline for (.{ &Bus.Owner.init, &Bus.Owner.validate, &Bus.Owner.deinit, &Bus.Values.at, &Source.Source.init, &Source.Source.validate, &Source.Source.cell, &Source.Source.replayPublic, &Source.Source.deinit, &Rows.prepare, &Rows.Prepared.deinit, &Receiver.admit, &Receiver.verify, &Receiver.verifyRoot, &Receiver.Fresh.validate, &Receiver.Fresh.deinit, &Setup.derive, &Stage.publish, &Stage.Artifact.deinit }) |body| std.mem.doNotOptimizeAway(body);
}
