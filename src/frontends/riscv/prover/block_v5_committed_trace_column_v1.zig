//! One bounded trace-domain view recovered from immutable retained PCS data.
//! Shared by warm projections; never recommits a column or builds a new LDE.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Column = engine.pcs.ColumnEvaluation;
const M = core.fields.m31.M31;
const canonic = core.poly.circle.canonic;
const Twiddles = engine.poly.twiddles;
const BorrowedTransform = Twiddles.TwiddleTree([]const M);

/// One bounded canonical coset tower shared by an entire selected span batch.
/// Smaller interpolation/evaluation domains borrow its suffixes. Domain log1
/// needs its own eight-byte tower: repeated doubling represents the order-one
/// step index as 0, whereas the canonical coset retains the raw index 2^31.
/// Keep the exact coset equality guards rather than replacing their metadata.
pub const Batch = struct {
    allocator: std.mem.Allocator,
    owned: Twiddles.TwiddleTree([]M),
    minimum: ?Twiddles.TwiddleTree([]M),
    pub fn init(a: std.mem.Allocator, maximum_log: u32) !Batch {
        if (maximum_log == 0 or maximum_log >= core.circle.M31_CIRCLE_LOG_ORDER)
            return error.InvalidV5CommittedTraceColumn;
        var owned = try precompute(a, maximum_log);
        errdefer Twiddles.deinitM31(a, &owned);
        const minimum = if (maximum_log == 1) null else try precompute(a, 1);
        return .{ .allocator = a, .owned = owned, .minimum = minimum };
    }
    pub fn deinit(self: *Batch) void {
        Twiddles.deinitM31(self.allocator, &self.owned);
        if (self.minimum) |*minimum| Twiddles.deinitM31(self.allocator, minimum);
        self.* = undefined;
    }
    pub fn recover(self: *const Batch, committed: Column, trace_log: u32) !Column {
        return recoverWithTwiddles(self.allocator, committed, trace_log, self.transform(committed.log_size), self.transform(trace_log));
    }
    fn transform(self: *const Batch, log: u32) BorrowedTransform {
        const selected = if (log == 1) self.minimum orelse self.owned else self.owned;
        return .init(selected.root_coset, selected.twiddles, selected.itwiddles);
    }
};

fn precompute(a: std.mem.Allocator, log: u32) !Twiddles.TwiddleTree([]M) {
    return Twiddles.precomputeM31(a, canonic.CanonicCoset.new(log).circleDomain().half_coset) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.SingularTwiddle => return error.SingularSystem,
    };
}

pub fn requiredTransformLog(committed: Column, trace_log: u32) !u32 {
    try committed.validateRetained();
    if (trace_log == 0 or trace_log > 24 or committed.log_size < trace_log or
        committed.log_size >= core.circle.M31_CIRCLE_LOG_ORDER)
        return error.InvalidV5CommittedTraceColumn;
    return if (committed.coefficient_values != null) trace_log else committed.log_size;
}

pub fn recover(a: std.mem.Allocator, committed: Column, trace_log: u32) !Column {
    var batch = try Batch.init(a, try requiredTransformLog(committed, trace_log));
    defer batch.deinit();
    return batch.recover(committed, trace_log);
}
fn recoverWithTwiddles(a: std.mem.Allocator, committed: Column, trace_log: u32, source_transform: BorrowedTransform, trace_transform: BorrowedTransform) !Column {
    _ = try requiredTransformLog(committed, trace_log);
    if (committed.coefficient_values) |retained|
        return evaluateBounded(a, retained, trace_log, trace_transform);
    var coefficients = try engine.poly.circle.poly.interpolateFromEvaluationWithTwiddles(a, .{ .domain = canonic.CanonicCoset.new(committed.log_size).circleDomain(), .values = committed.values }, source_transform);
    defer coefficients.deinit(a);
    return evaluateBounded(a, coefficients.coefficients(), trace_log, trace_transform);
}
fn evaluateBounded(a: std.mem.Allocator, full: []const M, trace_log: u32, transform: BorrowedTransform) !Column {
    const count = @as(usize, 1) << @intCast(trace_log);
    if (full.len > count) for (full[count..]) |value| {
        if (!value.isZero()) return error.InvalidV5CommittedTraceDegree;
    };
    const trace = try engine.poly.circle.poly.CircleCoefficients.initBorrowed(full[0..@min(count, full.len)]);
    const evaluation = try trace.evaluateWithTwiddles(a, canonic.CanonicCoset.new(trace_log).circleDomain(), transform);
    return .{ .log_size = trace_log, .values = evaluation.values };
}

test {
    _ = @import("tests/block_v5_committed_trace_column_test.zig");
}
