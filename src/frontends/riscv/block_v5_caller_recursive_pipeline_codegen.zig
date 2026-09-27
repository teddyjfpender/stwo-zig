//! Retain real original staged/live caller + both recursive publication bodies.
//! Only the marker is invoked; none of the retained functions is executed.
const std = @import("std");
const Pipeline = @import("prover/block_v5_caller_recursive_pipeline_v1.zig").ForBackend(@import("stwo_cpu_backend").CpuBackend);
pub export fn stwo_caller_recursive_pipeline_body_gate() void {
    inline for (.{ &Pipeline.proveStaged, &Pipeline.proveSegment, &Pipeline.proveStagedWithAdmissions, &Pipeline.proveSegmentWithAdmissions, &Pipeline.Session.init, &Pipeline.Session.initBorrowed, &Pipeline.Session.deinit, &Pipeline.Session.sink, &Pipeline.Session.hooks }) |body| std.mem.doNotOptimizeAway(body);
}
