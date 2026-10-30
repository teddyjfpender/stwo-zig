//! Original parent admits two/four-row padding cohorts. Explicit tiny device
//! kernels supplement the existing resident transform, whose domain starts8.
const cuda = @import("stwo_cuda_backend");
const common = cuda.runtime.stages.common;
const layout = cuda.runtime.stages.resident_layout;
const Stage = cuda.runtime.telemetry.Stage;
extern fn stwo_parent_tiny_inverse_on([*]const u32, usize, [*]u32, usize, u32, u32, [*]const u32, u32, ?*anyopaque) c_int;
extern fn stwo_parent_tiny_extend_on([*]const u32, usize, [*]const u32, [*]u32, usize, u32, u32, [*]const u32, u32, ?*anyopaque) c_int;
pub fn inverseCompact(session: anytype, stage: Stage, input: common.WordMatrix, output: common.WordMatrix, log: u32, twiddles: common.Words) !void {
    if (log >= 3) return cuda.runtime.stages.transform.Native.inverseCompact(session, stage, input, output, log, twiddles);
    try common.requireStage(session, stage);
    if (log == 0) return error.InvalidKernelDescriptor;
    const n = @as(usize, 1) << @intCast(log);
    const i = try layout.wordMatrix(session, input, n);
    const o = try layout.wordMatrix(session, output, n);
    const t = try layout.resident(session, u32, twiddles, twiddles.len);
    if (i.column_count != o.column_count or twiddles.len < n / 2) return error.InvalidKernelDescriptor;
    if (layout.overlap(i.range, o.range) and (i.range.start != o.range.start or i.stride_words != o.stride_words)) return error.OverlappingDeviceRange;
    if (layout.overlap(o.range, t.range)) return error.OverlappingDeviceRange;
    try common.record(session, stage, stwo_parent_tiny_inverse_on(i.pointer, i.stride_words, o.pointer, o.stride_words, try common.count(i.column_count), log, t.pointer, try common.count(twiddles.len), session.context.stream));
}
pub fn extend(session: anytype, stage: Stage, input: common.WordMatrix, logs: common.Words, output: common.WordMatrix, log: u32, twiddles: common.Words, skip_circle: bool) !void {
    if (log >= 3) return cuda.runtime.stages.transform.Native.extend(session, stage, input, logs, output, log, twiddles, skip_circle);
    try common.requireStage(session, stage);
    if (log == 0 or skip_circle) return error.InvalidKernelDescriptor;
    const n = @as(usize, 1) << @intCast(log);
    const i = try layout.wordMatrix(session, input, n / 2);
    const o = try layout.wordMatrix(session, output, n);
    const t = try layout.resident(session, u32, twiddles, twiddles.len);
    const l = try layout.resident(session, u32, logs, logs.len);
    if (i.column_count != o.column_count or logs.len != i.column_count or twiddles.len < n / 2) return error.InvalidKernelDescriptor;
    if (layout.overlap(o.range, i.range) or layout.overlap(o.range, t.range) or layout.overlap(o.range, l.range)) return error.OverlappingDeviceRange;
    try common.record(session, stage, stwo_parent_tiny_extend_on(i.pointer, i.stride_words, l.pointer, o.pointer, o.stride_words, try common.count(i.column_count), log, t.pointer, try common.count(twiddles.len), session.context.stream));
}
