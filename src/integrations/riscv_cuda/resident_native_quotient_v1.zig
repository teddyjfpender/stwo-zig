//! Explicit native-source tiny DEEP transform policy. The shared DEEP
//! numerator, denominator, grouping, lifting and transcript remain unchanged.
//! Existing Cairo/default transform admission retains its strict minimum log.
const std = @import("std");
const cuda = @import("stwo_cuda_backend");
const common = cuda.runtime.stages.common;
const layout = cuda.runtime.stages.resident_layout;
const Q = cuda.runtime.stages.quotient;
const Controller = @import("stwo_cairo_cuda_integration").executor.quotient.controller;
const Tiny = @import("resident_parent_transform_v1.zig");
const Stage = cuda.runtime.telemetry.Stage;
const stwo_quotient_tiny_inverse_on = cuda.abi.stages.transform.stwo_quotient_tiny_inverse_on;
pub fn initialIndex(coefficient_log: u32) !u32 {
    if (coefficient_log < 1 or coefficient_log > 2) return error.InvalidKernelDescriptor;
    return @as(u32, 1) << @intCast(29 - coefficient_log);
}
pub fn initialize(prepared: *const Controller.Prepared, session: anytype, inverse_twiddles: common.Words) !void {
    const log = prepared.combine.domain_log_size;
    if (log >= 3) return prepared.initializeTransform(session, inverse_twiddles);
    try common.requireStage(session, .ingress);
    const index = try initialIndex(log);
    if (prepared.circle.half_coset_initial_index != index or prepared.views.subdomain_inverse_twiddles.len != (@as(usize, 1) << @intCast(log - 1)) or prepared.views.coefficient_logs.len != 4) return error.InvalidKernelDescriptor;
    // The tiny inverse derives x/y on the device from the admitted domain
    // index. It does not consume canonical-domain twiddles, which would be
    // wrong here. The common final extension uses the original forward tree.
    try session.context.uploadSlice(u32, prepared.views.coefficient_logs, &.{ log, log, log, log });
}
pub fn execute(prepared: *const Controller.Prepared, session: anytype) !void {
    return prepared.executeWith(Ops, session);
}
pub const Ops = struct {
    pub const prepareTerms = Q.Native.prepareTerms;
    pub const finalizeGroups = Q.Native.finalizeGroups;
    pub const accumulate = Q.addressed.Native.accumulateBucketedFinalized;
    pub const combine = Q.Native.combineCompact;
    pub const extend = Tiny.extend;
    pub fn inverse(session: anytype, stage: Stage, input: common.WordMatrix, output: common.WordMatrix, log: u32, twiddles: common.Words) !void {
        if (log >= 3) return cuda.runtime.stages.transform.Native.inverseCompact(session, stage, input, output, log, twiddles);
        try common.requireStage(session, stage);
        const index = try initialIndex(log);
        const rows = @as(usize, 1) << @intCast(log);
        const source = try layout.wordMatrix(session, input, rows);
        const dest = try layout.wordMatrix(session, output, rows);
        if (source.column_count != dest.column_count) return error.InvalidKernelDescriptor;
        if (layout.overlap(source.range, dest.range) and (source.range.start != dest.range.start or source.stride_words != dest.stride_words)) return error.OverlappingDeviceRange;
        try common.record(session, stage, stwo_quotient_tiny_inverse_on(source.pointer, source.stride_words, dest.pointer, dest.stride_words, try common.count(source.column_count), log, index, session.context.stream));
    }
};
