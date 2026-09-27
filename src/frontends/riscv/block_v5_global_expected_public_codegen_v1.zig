//! Retain actual durable owner, publisher, fresh verifier and normalizer bodies.
//! No function below invokes a proof, guest, device or producer.
const std = @import("std");
const Stage = @import("prover/block_v5_global_public_owned_stage_v1.zig");
const Producer = Stage.ForBackend(@import("stwo_cpu_backend").CpuBackend);
const File = @import("prover/block_v5_global_expected_public_file_v1.zig");
const Receiver = @import("recursion/block_v5_global_public_owned_receiver_v1.zig");
const Normalizer = @import("recursion/block_v5_global_public_export_normalizer_v1.zig");
pub export fn stwo_global_expected_public_body_gate() void {
    inline for (.{
        &@import("recursion/block_v5_global_expected_public_job_v1.zig").fromPolicy,
        &@import("recursion/block_v5_global_expected_public_job_v1.zig").Expected.bind,
        &File.encode,
        &File.write,
        &File.decode,
        &File.read,
        &File.Owned.retain,
        &File.Owned.deinit,
        &File.Owned.bind,
        &Stage.Session.open,
        &Stage.Session.reopen,
        &Stage.Session.deinit,
        &Producer.publishPrepared,
        &Stage.Artifact.deinit,
        &Receiver.verify,
        &@import("recursion/block_v5_global_public_export_receiver_v1.zig").verifyPrepared,
        &Receiver.Fresh.validate,
        &Receiver.Fresh.deinit,
        &Normalizer.normalize,
        &Normalizer.Normalized.cell,
        &Normalizer.Normalized.frameAt,
        &Normalizer.Normalized.originalCell,
        &Normalizer.Normalized.originalFrame,
        &Normalizer.Normalized.exportTerms,
        &Normalizer.Normalized.validate,
        &Normalizer.Normalized.rehomeInput,
        &Normalizer.Normalized.replay,
        &Normalizer.Normalized.deinit,
        &Normalizer.sourceAuthority,
    }) |body| std.mem.doNotOptimizeAway(body);
}
