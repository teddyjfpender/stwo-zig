//! Actual production body retention only; no retained operation is invoked.
const std = @import("std");
const core = @import("stwo_core");
const P = @import("recursion/block_v5_wide_public_windows_v1.zig");
const Bus = @import("recursion/block_v5_wide_public_windows_bus_v1.zig");
const G = @import("recursion/air/block_v5_wide_public_windows_composition_v1.zig");
const Rows = @import("recursion/air/block_v5_global_public_export_rows_v1.zig");
const Protocol = @import("recursion/block_v5_reusable_wide_public_windows_protocol_v1.zig");
const Receiver = @import("recursion/block_v5_wide_public_windows_receiver_v1.zig");
const Source = @import("recursion/block_v5_wide_public_windows_source_v1.zig");
fn mix(admission: *const Protocol.Admission, channel: *core.channel.blake3.Channel) !void {
    try admission.mix(channel);
}
fn mixSource(source: *const Source.Source, channel: *core.channel.blake3.Channel) !void {
    try source.mix(channel);
}
fn nested(a: std.mem.Allocator, source: *const Source.Source, capture: *const @import("recursion/blake3_native_parent_verifier.zig").Verified, capacity: u32) !@import("recursion/air/block_v5_scoped_child_verifier_rows_v1.zig").Prepared {
    return @import("recursion/air/block_v5_scoped_child_verifier_rows_v1.zig").prepare(a, Source.Admission.init(source), capture, 0, Source.PUBLIC_CIRCUIT, 1, capacity);
}
pub export fn stwo_wide_public_windows_body_gate() void {
    inline for (.{ &@import("recursion/block_v5_wide_expected_input_owner_v1.zig").Owned.init, &@import("recursion/block_v5_wide_expected_input_owner_v1.zig").Owned.require, &@import("recursion/block_v5_wide_expected_input_owner_v1.zig").Owned.deinit, &P.init, &P.Owner.validate, &P.Owner.deinit, &P.Owner.publicWord, &P.Owner.originalCell, &P.Owner.cycles, &P.Owner.exportTerms, &P.Owner.cell, &G.prepare, &G.Prepared.validate, &Rows.ForModules(P, G, Bus).prepare, &Rows.prepare, &@import("recursion/block_v5_wide_public_windows_preparation_v1.zig").prepare, &Receiver.verify, &Receiver.Fresh.validate, &Receiver.Fresh.deinit, &@import("prover/block_v5_wide_public_windows_stage_v1.zig").ForBackend(@import("stwo_cpu_backend").CpuBackend).publish, &Source.Source.init, &Source.Source.validate, &Source.Source.cell, &Source.Source.originalFrame, &Source.Source.originalCell, &Source.Source.window, &Source.Source.exportTerms, &Source.Source.replayPublic, &Source.Source.deinit, &mix, &mixSource, &nested }) |body| std.mem.doNotOptimizeAway(body);
}
