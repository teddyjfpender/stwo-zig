//! Retain actual allocator-bearing sampled runtime/backend bodies in an object.
//! No function here is executed and no Metal device is opened.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const Runtime = @import("backends/metal/runtime.zig").Runtime;
const Backend = @import("backends/metal/commit_backend.zig").MetalCommitBackend;
const Plans = engine.pcs.sampled_coefficient_plans;

fn coefficientSingle(r: *Runtime, a: std.mem.Allocator, tree: Plans.CoefficientEvalTreePlan) anyerror!void {
    _ = try r.evaluateCoefficientPlans(a, tree.coefficients, tree.tree_values, tree.plans);
}
fn coefficientSingleUnprofiled(r: *Runtime, a: std.mem.Allocator, tree: Plans.CoefficientEvalTreePlan) anyerror!void {
    _ = try r.evaluateCoefficientPlansUnprofiled(a, tree.coefficients, tree.tree_values, tree.plans);
}
fn coefficientTrees(r: *Runtime, a: std.mem.Allocator, trees: []const Plans.CoefficientEvalTreePlan) anyerror!void {
    _ = try r.evaluateCoefficientTreePlans(a, trees);
}
fn coefficientTreesUnprofiled(r: *Runtime, a: std.mem.Allocator, trees: []const Plans.CoefficientEvalTreePlan) anyerror!void {
    _ = try r.evaluateCoefficientTreePlansUnprofiled(a, trees);
}
fn barycentric(r: *Runtime, a: std.mem.Allocator, trees: []const Plans.BarycentricEvalTreePlan) anyerror!void {
    // Actual runtime selects the strict resident or explicit host-stage ABI
    // from the independently supplied tree roster; both bodies are retained.
    _ = try r.evaluateBarycentricTreePlans(a, trees);
}
fn backendCoefficient(a: std.mem.Allocator, tree: Plans.CoefficientEvalTreePlan) anyerror!void {
    try Backend.evaluateCoefficientPlans(a, tree.coefficients, tree.tree_values, tree.plans);
}
fn backendCoefficientReceipt(a: std.mem.Allocator, tree: Plans.CoefficientEvalTreePlan) anyerror!void {
    _ = try Backend.evaluateCoefficientPlansWithReceipt(a, tree.coefficients, tree.tree_values, tree.plans);
}
fn backendCoefficientTrees(a: std.mem.Allocator, trees: []const Plans.CoefficientEvalTreePlan) anyerror!void {
    try Backend.evaluateCoefficientTreePlans(a, trees);
}
fn backendCoefficientTreesReceipt(a: std.mem.Allocator, trees: []const Plans.CoefficientEvalTreePlan) anyerror!void {
    _ = try Backend.evaluateCoefficientTreePlansWithReceipt(a, trees);
}
fn backendBarycentric(a: std.mem.Allocator, trees: []const Plans.BarycentricEvalTreePlan) anyerror!void {
    try Backend.evaluateBarycentricTreePlans(a, trees);
}
fn backendBarycentricReceipt(a: std.mem.Allocator, trees: []const Plans.BarycentricEvalTreePlan) anyerror!void {
    _ = try Backend.evaluateBarycentricTreePlansWithReceipt(a, trees);
}
export fn stwo_metal_sampled_budget_body_gate() void {
    std.mem.doNotOptimizeAway(&coefficientSingle);
    std.mem.doNotOptimizeAway(&coefficientSingleUnprofiled);
    std.mem.doNotOptimizeAway(&coefficientTrees);
    std.mem.doNotOptimizeAway(&coefficientTreesUnprofiled);
    std.mem.doNotOptimizeAway(&barycentric);
    std.mem.doNotOptimizeAway(&backendCoefficient);
    std.mem.doNotOptimizeAway(&backendCoefficientReceipt);
    std.mem.doNotOptimizeAway(&backendCoefficientTrees);
    std.mem.doNotOptimizeAway(&backendCoefficientTreesReceipt);
    std.mem.doNotOptimizeAway(&backendBarycentric);
    std.mem.doNotOptimizeAway(&backendBarycentricReceipt);
}
