//! Object-only body retention for the actual Metal runtime/PCS quotient seam.
//! No wrapper is invoked, no device opened, no proof generated.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const dispatch = @import("backends/metal/runtime/secure_polynomial_composition_v1.zig");
const Backend = @import("backends/metal/commit_backend.zig").MetalCommitBackend;
fn install(a: std.mem.Allocator, image: []const u8, sha: [32]u8, programs: []const *const engine.air.secure_polynomial_program_v1.Program, limits: dispatch.Limits) anyerror!void {
    return Backend.installSecurePolynomialAot(a, image, sha, programs, limits);
}
fn evaluate(a: std.mem.Allocator, components: []const engine.air.component_prover.ComponentProver, random: core.fields.qm31.QM31, trace: *const engine.air.component_prover.Trace, residents: []const ?*anyopaque, tower: ?engine.poly.twiddles.TwiddleTree([]const core.fields.m31.M31)) anyerror!?engine.secure_column.SecureColumnByCoords {
    return Backend.computeCompositionEvaluation(a, components, random, trace, residents, tower);
}
export fn stwo_word_metal_quotient_body_gate() void {
    std.mem.doNotOptimizeAway(&install);
    std.mem.doNotOptimizeAway(&evaluate);
}
