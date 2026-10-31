//! Deliberately bypasses native row admission AFTER constructing an honest
//! source. Acceptance must fail at the actual polynomial proof boundary.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Backend = @import("stwo_cpu_backend").CpuBackend;
const A = @import("stwo_riscv_frontend").rv64_air;
const Mat = @import("../word16_execution/setup.zig");
const P = @import("../word16_execution/protocol.zig");
const Sources = @import("../word16_execution/sources.zig");
const C = @import("../word16_execution/components.zig").Components;
const Execution = @import("../word16_execution/execution.zig");
const Tape = @import("stwo_riscv_frontend").rv64.compact_tape.Tape;
/// One actual false prover attempt, preserving original typed metadata/facts.
pub fn reject(a: std.mem.Allocator, setup: *const Mat.Setup, admission: Execution.Admission, boundary: A.word16_execution.types.Boundary, tape: *const Tape, column: usize, logical: usize) !void {
    var source = try Sources.Source.init(a, &setup.materials, admission.image, boundary, 1, tape);
    defer source.deinit();
    const n = @as(usize, 1) << @intCast(setup.materials.geometry.cpu_log);
    const pos = A.word16_execution.layout.physical(logical, setup.materials.geometry.cpu_log);
    source.cpu.main[column * n + pos] = source.cpu.main[column * n + pos].add(core.fields.m31.M31.one());
    const request = source.request();
    try admission.validate(setup, request);
    var scheme = try P.T.Scheme.init(a, P.T.P.config());
    var owns = true;
    defer if (owns) scheme.deinit(a);
    scheme.setCompactPolynomialStorage(5);
    var channel = P.T.P.Channel{};
    try P.mix(&channel, setup, request, admission.image_identity);
    try setup.appendFixed(a, &scheme, &channel);
    const main = try source.columns(a, 1);
    defer a.free(main);
    try scheme.commitBorrowedStreaming(a, main, 8, &channel);
    try source.releaseMain();
    const draw = P.draw(&channel);
    const claims = try source.generate(draw);
    channel.mixFelts(&claims.values());
    const interaction = try source.columns(a, 2);
    defer a.free(interaction);
    try scheme.commitBorrowedStreaming(a, interaction, 8, &channel);
    source.releaseCommittedInteraction();
    var components = try C.init(&setup.materials, request, draw, claims);
    const handles = try components.provers(a);
    defer a.free(handles);
    owns = false;
    if (engine.prove.proveExWithRecorder(Backend, P.T.P.Hasher, P.T.P.MerkleChannel, a, handles, &channel, scheme, false, null)) |result| {
        var accepted = result;
        accepted.aux.deinit(a);
        accepted.proof.deinit(a);
        return error.FalseExecutionWitnessProved;
    } else |err| {
        if (err != error.ConstraintsNotSatisfied) return err;
    }
}
