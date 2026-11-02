const std = @import("std");
const builtin = @import("builtin");
const circle = @import("stwo_core").circle;
const core_air_components = @import("stwo_core").air.components;
const qm31 = @import("stwo_core").fields.qm31;
const pcs_core = @import("stwo_core").pcs;
const canonic = @import("stwo_core").poly.circle.canonic;
const proof_mod = @import("stwo_core").proof;
const verifier_types = @import("stwo_core").verifier_types;
const component_prover = @import("air/component_prover.zig");
const composition_work = @import("air/composition_work.zig");
const oods_work = @import("air/oods_work.zig");
const proof_work_completion = @import("air/proof_work_completion.zig");
const device_composition = @import("air/device_composition.zig");
const prover_air_accumulation = @import("air/accumulation.zig");
const prover_circle = @import("poly/circle/mod.zig");
const pcs_prover = @import("pcs/mod.zig");
const prover_api = @import("stwo_prover_api");
const stage_profile = prover_api.stage_profile;
const work_profile = prover_api.work_profile;

const QM31 = qm31.QM31;
const CirclePointQM31 = circle.CirclePointQM31;
const PREPROCESSED_TRACE_IDX = verifier_types.PREPROCESSED_TRACE_IDX;
const TreeVec = pcs_core.TreeVec;
const WorkRecorder = work_profile.Recorder(true);
const completeAirCompositionWork = proof_work_completion.completeAirCompositionWork;
const completeOodsSeedToPointWork = proof_work_completion.completeOodsSeedToPointWork;
const completeOodsWork = proof_work_completion.completeOodsWork;

pub const ForField = @import("prove_family.zig").ForField;
const Default = ForField(QM31);
pub const ProvingError = Default.ProvingError;
pub const prove = Default.prove;
pub const proveEx = Default.proveEx;
pub const proveExWithRecorder = Default.proveExWithRecorder;
pub const proveExWithStage = Default.proveExWithStage;
pub const proveExWithExecution = Default.proveExWithExecution;
pub const proveExWithExecutionDiagnosed = Default.proveExWithExecutionDiagnosed;
pub const proveExWithExecutionDiagnosedRetainingFailure = Default.proveExWithExecutionDiagnosedRetainingFailure;
pub const testing = Default.testing;
const splitCompositionPair = Default.splitCompositionPair;

test "composition deep chunks outlive borrowed coefficient backing" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, checkCompositionChunkLifetime, .{});
}
fn checkCompositionChunkLifetime(a: std.mem.Allocator) !void {
    const M = @import("stwo_core").fields.m31.M31;
    const source = try a.alloc(M, 64);
    var source_alive = true;
    defer if (source_alive) a.free(source);
    for (source, 0..) |*value, i| value.* = M.fromU64(i + 1);
    var pair: prover_circle.SecureCirclePoly.SplitPair = undefined;
    for (0..4) |coordinate| {
        pair.left.polys[coordinate] = try prover_circle.CircleCoefficients.initBorrowed(source[coordinate * 16 ..][0..8]);
        pair.right.polys[coordinate] = try prover_circle.CircleCoefficients.initBorrowed(source[coordinate * 16 + 8 ..][0..8]);
    }
    defer pair.deinit(a);
    var chunks = try splitCompositionPair(a, pair, 2);
    defer chunks.deinit(a);
    try std.testing.expect(chunks.owns_polynomials);
    a.free(source);
    source_alive = false;
    for (chunks.chunks, 0..) |chunk, index| {
        for (chunk.polys, 0..) |coordinate, lane| {
            for (coordinate.coefficients(), 0..) |value, offset| {
                try std.testing.expectEqual(M.fromU64(lane * 16 + index * 4 + offset + 1).toU32(), value.toU32());
            }
        }
    }
}
