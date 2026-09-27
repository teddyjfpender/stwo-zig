//! Retains genuine independently admitted setup and original producer bodies;
//! the marker itself never invokes a compiler, PCS, prover or fresh receiver.
const std = @import("std");
const Requester = @import("recursion/block_v5_requester_recursive_shape_admission_v1.zig");
const Public = @import("recursion/block_v5_requester_public_recursive_shape_admission_v1.zig");
const Roster = @import("recursion/block_v5_recursive_parent_fixed_roster_v1.zig");
const RequesterRoster = Roster.ForPackedAdmission(Requester.Admission);
const PublicRoster = Roster.ForPackedAdmission(Public.Admission);
const Pieces = @import("recursion/block_v5_recursive_parent_fixed_pieces_v1.zig");
const RequesterPieces = Pieces.ForAdmission(Requester.Admission);
const PublicPieces = Pieces.ForAdmission(Public.Admission);
const Recorder = @import("recursion/air/blake3_native_recorder.zig");
fn replayRequester(a: std.mem.Allocator, source: *const Requester.Source) !void {
    try source.validate();
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    var recorder = Recorder.Recorder{ .a = arena.allocator() };
    source.replayPublic(&recorder);
    try recorder.check();
}
fn replayPublic(a: std.mem.Allocator, source: *const Public.Source) !void {
    try source.validate();
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    var recorder = Recorder.Recorder{ .a = arena.allocator() };
    source.replayPublic(&recorder);
    try recorder.check();
}
pub export fn stwo_requester_recursive_fixed_body_gate() void {
    inline for (.{ &Requester.Source.init, &Requester.Source.validate, &Requester.Source.deinit, &Requester.Admission.init, &Requester.Admission.validate, &Public.Source.init, &Public.Source.validate, &Public.Source.deinit, &Public.Admission.init, &Public.Admission.validate, &replayRequester, &replayPublic, &RequesterRoster.Owned.derive, &RequesterRoster.Owned.validateAgainst, &RequesterRoster.Owned.deinit, &PublicRoster.Owned.derive, &PublicRoster.Owned.validateAgainst, &PublicRoster.Owned.deinit, &RequesterPieces.Owned.init, &PublicPieces.Owned.init }) |body| std.mem.doNotOptimizeAway(body);
    const Tuple = @import("recursion/air/block_v5_requester_public_fixed_rows_v1.zig").Owned;
    inline for (.{ &Tuple.init, &Tuple.validateAgainst, &Tuple.deinit, &@import("recursion/air/block_v5_requester_recursive_packed_fixed_v1.zig").Owned.deinit }) |body| std.mem.doNotOptimizeAway(body);
    const Kernel = @import("recursion/air/block_v5_global_public_export_rows_v1.zig");
    inline for (.{ &Kernel.prepare, &Kernel.prepareFixed }) |body| std.mem.doNotOptimizeAway(body);
    const PublicKernel = Kernel.ForModules(@import("recursion/block_v5_requester_public_compensation_v1.zig"), @import("recursion/air/block_v5_requester_public_composition_v1.zig"), @import("recursion/block_v5_requester_public_bus_v1.zig"));
    inline for (.{ &PublicKernel.prepare, &PublicKernel.prepareFixed }) |body| std.mem.doNotOptimizeAway(body);
    // Preserve actual original PUBLIC21 verifier/publisher alongside setup ports.
    const Producer = @import("recursion/block_v5_requester_public_producer_v1.zig").ForBackend(@import("stwo_cpu_backend").CpuBackend);
    inline for (.{ &@import("recursion/block_v5_requester_public_preparation_v1.zig").prepare, &@import("recursion/block_v5_requester_public_receiver_v1.zig").verify, &Producer.deriveKey, &Producer.init, &Producer.proveEncodedConsuming }) |body| std.mem.doNotOptimizeAway(body);
}
