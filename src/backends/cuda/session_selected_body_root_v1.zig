//! OBJECT / SEMANTIC ONLY: real CUDA/AOT bodies, never execute these exports.
const Session = @import("runtime/session.zig").NativeSession;
const Runtime = @import("runtime/process_runtime.zig").NativeRuntime;

pub export fn stwo_cuda_selected_session_open_body_gate(selected: *const Session.Selection) void {
    var construction = Session.openSelected(&.{89}, selected.*);
    construction.deinit() catch return;
}
pub export fn stwo_cuda_selected_session_cleanup_body_gate(construction: *Session.Construction) void {
    construction.deinit() catch return;
}
pub export fn stwo_cuda_selected_runtime_open_body_gate(selected: *const Session.Selection) void {
    var construction = Runtime.openSelected(&.{89}, selected.*);
    construction.deinit() catch return;
}
pub export fn stwo_cuda_selected_runtime_cleanup_body_gate(construction: *Runtime.Construction) void {
    construction.deinit() catch return;
}
pub export fn stwo_cuda_selected_runtime_terminal_body_gate(owner: *Runtime, abort: bool) void {
    if (abort) owner.abort() catch return else owner.close() catch return;
}
pub export fn stwo_cuda_selected_session_compatibility_body_gate() void {
    var owner = Session.open(&.{89}) catch return;
    owner.close() catch return;
}
