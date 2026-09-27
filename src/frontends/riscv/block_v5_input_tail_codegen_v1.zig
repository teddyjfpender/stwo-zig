//! Genuine production addresses, never runtime proof calls.
const std = @import("std");
const Public = @import("recursion/block_v5_input_tail_public_v1.zig");
const Rows = @import("recursion/air/block_v5_input_tail_rows_v1.zig");
const Consumer = @import("recursion/air/block_v5_input_tail_consumer_v1.zig");
const Digest = @import("recursion/air/block_v5_input_tail_public_digest_v1.zig");
const Source = @import("recursion/block_v5_input_tail_source_v1.zig");
const Receiver = @import("recursion/block_v5_input_tail_receiver_v1.zig");
const Attachment = @import("recursion/block_v5_input_tail_attachment_v1.zig");
const Stage = @import("prover/block_v5_input_tail_stage_v1.zig").ForBackend(@import("stwo_cpu_backend").CpuBackend);
pub export fn stwo_input_tail_provider_body_gate() void {
    inline for (.{ &Public.Owned.init, &Public.Owned.require, &Public.Owned.retain, &Public.Owned.deinit, &Public.outputCall, &Rows.logical, &Rows.prepare, &Rows.Prepared.deinit, &Stage.publish, &Stage.Artifact.deinit, &Receiver.verify, &Receiver.Fresh.validate, &Receiver.Fresh.deinit, &Source.Source.init, &Source.Source.validate, &Source.Source.replayPublic, &Source.Source.cell, &Attachment.prepare, &Attachment.Prepared.deinit, &Consumer.prepare, &Consumer.trusted, &Consumer.Prepared.deinit, &Digest.prepare, &Digest.trusted, &Digest.prepareColumns, &Digest.ColumnPrepared.deinit }) |body| std.mem.doNotOptimizeAway(body);
}
