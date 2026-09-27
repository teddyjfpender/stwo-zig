//! Actual production bodies retained in an object; no wrapper is executed.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Backend = @import("backends/metal/commit_backend.zig").MetalCommitBackend;
const Runtime = @import("backends/metal/runtime.zig");
const Column = engine.secure_column.SecureColumnByCoords;
const Line = engine.line.LineEvaluation;
fn column(a: std.mem.Allocator, n: usize) anyerror!Column {
    return Backend.allocateSecureColumnWithAllocator(a, n);
}
fn line(a: std.mem.Allocator, domain: core.poly.line.LineDomain) anyerror!Line {
    return Backend.allocateLineEvaluationWithAllocator(a, domain);
}
fn convert(a: std.mem.Allocator, value: Line) anyerror!Column {
    return Backend.secureColumnFromLineWithAllocator(a, value);
}
fn circleFold(a: std.mem.Allocator, source: Column, destination: *Line, domain: core.poly.circle.domain.CircleDomain, alpha: core.fields.qm31.QM31) anyerror!void {
    return Backend.foldCircleResidentIntoLine(a, source, destination, domain, alpha, null);
}
fn lineFold(a: std.mem.Allocator, source: Line, alpha: core.fields.qm31.QM31, workspace: *core.fri.FoldLineWorkspace, folds: u32) anyerror!Line {
    return Backend.foldLineEvaluationN(a, source, alpha, workspace, folds);
}
fn cascade(a: std.mem.Allocator, metal: *Runtime.Runtime, source: *anyopaque, count: u32, circle_source: ?*anyopaque, alpha: ?[4]u32, coordinates: []const *anyopaque, terminal: *anyopaque, initial: u32, step: u32, channel: *[11]u32) anyerror!Runtime.FriLineCascadeResult {
    return Runtime.Runtime.foldFriCircleLineCascadeForSuite(true, metal, a, source, count, circle_source, alpha, null, initial, step, coordinates, terminal, @splat(0), @splat(0), 0, channel, true);
}
fn fused(a: std.mem.Allocator, metal: *Runtime.Runtime, provider: *engine.pcs.quotient_ops.LazyQuotientProvider, out: *Column, line_output: *anyopaque, coordinates: []const *anyopaque, terminal: *anyopaque, initial: u32, step: u32, channel: *[11]u32) anyerror!Runtime.QuotientFriCommitResult {
    return metal.computeQuotientsAndCommitFri(true, a, provider, out, line_output, coordinates, terminal, initial, step, channel, @splat(0), @splat(0), 0);
}
fn folded(a: std.mem.Allocator, metal: *Runtime.Runtime, source: *anyopaque, count: u32, inverse: []const u32, alphas: []const [4]u32, destination: *anyopaque, coordinates: *anyopaque) anyerror!Runtime.FriFoldCommitResult {
    return @import("backends/metal/runtime/fri_fold_commit_budgeted_v1.zig").foldFriLineAndCommitForHash(a, metal, source, count, inverse, alphas, destination, coordinates, @splat(0), @splat(0), 0, 1);
}
fn drain(a: std.mem.Allocator) anyerror!void {
    return Backend.drainBudgetedFriCaches(a);
}
const B3 = core.vcs_lifted.blake3_merkle;
const Prover = engine.fri.FriProver(Backend, B3.MerkleHasher, B3.MerkleChannel);
fn proverDestroy(a: std.mem.Allocator, value: *Prover) void {
    value.deinit(a);
}
fn cascadeDestroy(a: std.mem.Allocator, value: *Backend.FriLineCascadeResult(B3.MerkleHasher)) void {
    value.deinit(a);
}
fn shutdown() Backend.ShutdownError!void {
    return Backend.shutdown();
}
fn ordinaryColumn(n: usize) anyerror!Column {
    return Backend.allocateSecureColumn(n);
}
fn ordinaryLine(domain: core.poly.line.LineDomain) anyerror!Line {
    return Backend.allocateLineEvaluation(domain);
}
fn ordinaryConvert(value: Line) anyerror!Column {
    return Backend.secureColumnFromLine(value);
}
export fn stwo_metal_fri_budget_body_gate() void {
    std.mem.doNotOptimizeAway(&column);
    std.mem.doNotOptimizeAway(&line);
    std.mem.doNotOptimizeAway(&convert);
    std.mem.doNotOptimizeAway(&circleFold);
    std.mem.doNotOptimizeAway(&lineFold);
    std.mem.doNotOptimizeAway(&cascade);
    std.mem.doNotOptimizeAway(&fused);
    std.mem.doNotOptimizeAway(&folded);
    std.mem.doNotOptimizeAway(&drain);
    std.mem.doNotOptimizeAway(&proverDestroy);
    std.mem.doNotOptimizeAway(&cascadeDestroy);
    std.mem.doNotOptimizeAway(&shutdown);
    std.mem.doNotOptimizeAway(&ordinaryColumn);
    std.mem.doNotOptimizeAway(&ordinaryLine);
    std.mem.doNotOptimizeAway(&ordinaryConvert);
}
