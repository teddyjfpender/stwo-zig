//! Device-only canonical FFT twiddle construction. No per-proof CPU field work.
const cuda = @import("stwo_cuda_backend");
const common = cuda.runtime.stages.common;
extern fn stwo_canonical_twiddle_tree_on(u32, [*]u32, [*]u32, ?*anyopaque) c_int;
pub fn generate(session: anytype, log: u32, forward: common.Words, inverse: common.Words) !void {
    try common.requireStage(session, .ingress);
    if (log == 0 or log > 30) return error.InvalidResidentParentTwiddles;
    const n = @as(usize, 1) << @intCast(log - 1);
    if (forward.len != n or inverse.len != n or forward.address == inverse.address) return error.InvalidResidentParentTwiddles;
    const f = try session.context.deviceSlicePointer(u32, forward, n);
    const i = try session.context.deviceSlicePointer(u32, inverse, n);
    try common.record(session, .ingress, stwo_canonical_twiddle_tree_on(log, f, i, session.context.stream));
}
