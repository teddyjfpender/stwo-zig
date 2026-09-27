//! Genuine original/default and selected producer/receiver/ancestor function
//! bodies retained by address. Never invokes guest, PCS, STARK or device work.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Old = @import("recursion/block_v5_wide_public_windows_v1.zig");
const OldRows = @import("recursion/block_v5_wide_public_windows_preparation_v1.zig");
const OldReceiver = @import("recursion/block_v5_wide_public_windows_receiver_v1.zig");
const OldStage = @import("prover/block_v5_wide_public_windows_stage_v1.zig").ForBackend(Cpu);
const Public = @import("recursion/block_v5_tail_linked_public_windows_v2.zig");
const Rows = @import("recursion/block_v5_tail_linked_public_windows_preparation_v2.zig");
const Receiver = @import("recursion/block_v5_tail_linked_public_windows_receiver_v2.zig");
const Source = @import("recursion/block_v5_tail_linked_public_windows_source_v2.zig");
const Stage = @import("prover/block_v5_tail_linked_public_windows_stage_v2.zig").ForBackend(Cpu);
const Graph = @import("recursion/air/block_v5_input_tail_ancestor_graph_v1.zig");
const Ancestor = @import("recursion/block_v5_input_tail_ancestor_bus_v1.zig");
const AncestorRows = @import("recursion/block_v5_input_tail_ancestor_preparation_v1.zig");
const AncestorReceiver = @import("recursion/block_v5_input_tail_ancestor_receiver_v1.zig");
const AncestorStage = @import("prover/block_v5_input_tail_ancestor_stage_v1.zig").ForBackend(Cpu);
pub export fn stwo_tail_linked_public_body_gate() void {
    inline for (.{
        &Old.init,                    &Old.Owner.validate,            &OldRows.prepare,          &OldRows.Prepared.deinit,    &OldReceiver.verify,           &OldReceiver.Fresh.deinit, &OldStage.publish,                &OldStage.Artifact.deinit,
        &Public.init,                 &Public.Owner.validate,         &Public.Owner.inputPrefix, &Public.Owner.inputFrontier, &Public.Owner.publicWord,      &Public.Owner.cell,        &Public.Owner.mix,                &Public.Owner.deinit,
        &Rows.prepare,                &Rows.Prepared.deinit,          &Receiver.verify,          &Receiver.Fresh.validate,    &Receiver.Fresh.deinit,        &Source.Source.init,       &Source.Source.validate,          &Source.Source.inputPrefix,
        &Source.Source.inputFrontier, &Source.Source.replayPublic,    &Source.Source.deinit,     &Stage.publish,              &Stage.Artifact.deinit,        &Graph.derivePairs,        &Graph.prepare,                   &Graph.Prepared.deinit,
        &Ancestor.init,               &Ancestor.Owner.validate,       &Ancestor.Owner.deinit,    &AncestorRows.prepare,       &AncestorRows.Prepared.deinit, &AncestorReceiver.verify,  &AncestorReceiver.Fresh.validate, &AncestorReceiver.Fresh.deinit,
        &AncestorStage.publish,       &AncestorStage.Artifact.deinit,
    }) |body| std.mem.doNotOptimizeAway(body);
}
